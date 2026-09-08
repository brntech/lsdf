# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .detectors import (
    DEPENDENCY_LIGHT_DETECTOR_FAMILIES,
    OPTIONAL_DETECTOR_FAMILIES,
    OPT_IN_DETECTOR_FAMILIES,
)
from .policy import SUBTYPE_MANIFEST_PATH, VALID_ACTIONS, _load_subtype_manifest, load_policy

LEGACY_SIGNATURE_VERSION = "lsdf-policy-signature-v1"
SIGNATURE_VERSION = "lsdf-policy-signature-v2-ed25519"
PERFORMANCE_DOC_PATH = Path("docs/performance.md")

FAMILY_DISPLAY_NAMES = {
    "xpia": "prompt-injection",
}


def validate_policy_file(path: Path) -> dict[str, Any]:
    policy = load_policy(path)
    return {"valid": True, "path": str(path), "policy": policy.summary()}


def diff_policy_files(old_path: Path, new_path: Path) -> dict[str, Any]:
    old = load_policy(old_path)
    new = load_policy(new_path)
    old_rules = {rule.id: rule for rule in old.rules}
    new_rules = {rule.id: rule for rule in new.rules}
    added = sorted(set(new_rules) - set(old_rules))
    removed = sorted(set(old_rules) - set(new_rules))
    changed = sorted(
        rule_id
        for rule_id in set(old_rules) & set(new_rules)
        if old_rules[rule_id] != new_rules[rule_id]
    )
    return {
        "old_path": str(old_path),
        "new_path": str(new_path),
        "old_policy": old.name,
        "new_policy": new.name,
        "added_rules": added,
        "removed_rules": removed,
        "changed_rules": changed,
        "entity_delta": sorted(new.entities - old.entities),
        "surface_delta": sorted(new.surfaces - old.surfaces),
    }


def format_policy_diff_markdown(report: dict[str, Any]) -> str:
    return (
        "# LSDF Policy Diff\n\n"
        f"- Old: {report['old_policy']} ({report['old_path']})\n"
        f"- New: {report['new_policy']} ({report['new_path']})\n"
        f"- Added rules: {_join(report['added_rules'])}\n"
        f"- Removed rules: {_join(report['removed_rules'])}\n"
        f"- Changed rules: {_join(report['changed_rules'])}\n"
        f"- Added entities: {_join(report['entity_delta'])}\n"
        f"- Added surfaces: {_join(report['surface_delta'])}\n"
    )


def explain_policy_file(path: Path) -> dict[str, Any]:
    return explain_loaded_policy(load_policy(path), source=str(path))


def explain_loaded_policy(policy: Any, *, source: str) -> dict[str, Any]:
    actions: dict[str, int] = {}
    severities: dict[str, int] = {}
    surfaces: dict[str, int] = {}
    entities: dict[str, int] = {}
    categories: dict[str, int] = {}
    on_fail: dict[str, int] = {}
    scopes: dict[str, int] = {}
    for rule in policy.rules:
        actions[rule.action] = actions.get(rule.action, 0) + 1
        severities[rule.severity] = severities.get(rule.severity, 0) + 1
        scopes[rule.scope] = scopes.get(rule.scope, 0) + 1
        if rule.on_fail:
            on_fail[rule.on_fail] = on_fail.get(rule.on_fail, 0) + 1
        for surface in _rule_values(rule.match, "surface", "surface_any_of"):
            surfaces[surface] = surfaces.get(surface, 0) + 1
        for entity in _rule_values(rule.match, "entity", "entity_any_of"):
            entities[entity] = entities.get(entity, 0) + 1
        for category in _rule_values(
            rule.match,
            "entity_in_category",
            "entity_in_category_any_of",
        ):
            categories[category] = categories.get(category, 0) + 1
    performance = _performance_for_profile(policy.name)
    return {
        "path": source,
        "policy": policy.summary(),
        "mode": policy.mode,
        "rule_count": len(policy.rules),
        "detection": {
            "families": list(policy.detectors.enabled_families),
            "settings": policy.detectors.family_settings,
            "entities": sorted(policy.entities),
            "categories": sorted(policy.entity_categories),
        },
        "action": {
            "mode": policy.mode,
            "actions": dict(sorted(actions.items())),
            "on_fail": dict(sorted(on_fail.items())),
            "scopes": dict(sorted(scopes.items())),
        },
        "actions": dict(sorted(actions.items())),
        "on_fail": dict(sorted(on_fail.items())),
        "scopes": dict(sorted(scopes.items())),
        "severities": dict(sorted(severities.items())),
        "surfaces": dict(sorted(surfaces.items())),
        "entities": dict(sorted(entities.items())),
        "entity_categories": dict(sorted(categories.items())),
        "detector_families": list(policy.detectors.enabled_families),
        "performance": performance,
        "audit": {
            "store_raw_values": policy.audit.store_raw_values,
            "store_redacted_evidence": policy.audit.store_redacted_evidence,
            "include_policy_decision": policy.audit.include_policy_decision,
        },
        "unsupported_actions": sorted(set(actions) - VALID_ACTIONS),
        "unavailable_actions": ["require_approval"],
        "posture": _policy_posture(policy.mode, actions),
    }


def format_policy_explain_text(report: dict[str, Any]) -> str:
    performance = _format_policy_performance_text(report.get("performance"))
    return (
        "LSDF Policy Explain\n"
        f"- Path: {report['path']}\n"
        f"- Name: {report['policy']['name']}\n"
        f"- Posture: {report['posture']}\n"
        f"- Rules: {report['rule_count']}\n"
        f"- Detection families: {_join(report['detection']['families'])}\n"
        f"- Detection entities: {_join(report['detection']['entities'])}\n"
        f"- Action mode: {report['action']['mode']}\n"
        f"- Actions: {_format_counts(report['action']['actions'])}\n"
        f"- on_fail: {_format_counts(report['action']['on_fail'])}\n"
        f"- Scopes: {_format_counts(report['action']['scopes'])}\n"
        f"- Surfaces: {_format_counts(report['surfaces'])}\n"
        f"- Entities: {_format_counts(report['entities'])}\n"
        f"- Entity categories: {_format_counts(report['entity_categories'])}\n"
        f"{performance}"
        f"- Unavailable actions: {_join(report['unavailable_actions'])}\n"
    )


def format_policy_explain_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# LSDF Policy Explain",
        "",
        f"- Path: `{report['path']}`",
        f"- Name: {report['policy']['name']}",
        f"- Posture: {report['posture']}",
        f"- Rules: {report['rule_count']}",
        f"- Unavailable actions: {_join(report['unavailable_actions'])}",
        "",
        "## Detection Axis",
        "",
        f"- Families: {_join(report['detection']['families'])}",
        f"- Entity scope: {_join(report['detection']['entities'])}",
        f"- Categories available: {_join(report['detection']['categories'])}",
        "",
        "## Action Axis",
        "",
        f"- Mode: {report['action']['mode']}",
        f"- on_fail: {_format_counts(report['action']['on_fail'])}",
        f"- Scopes: {_format_counts(report['action']['scopes'])}",
        "",
    ]
    _add_table(lines, "Actions", report["actions"])
    _add_table(lines, "Entity Categories", report["entity_categories"])
    _add_table(lines, "Surfaces", report["surfaces"])
    _add_table(lines, "Entities", report["entities"])
    _add_performance_section(lines, report.get("performance"))
    return "\n".join(lines).rstrip() + "\n"


def list_adapter_families() -> dict[str, Any]:
    return {
        "baseline": [_adapter_row(family, "baseline") for family in DEPENDENCY_LIGHT_DETECTOR_FAMILIES],
        "adapters": [_adapter_row(family, "adapter") for family in OPT_IN_DETECTOR_FAMILIES],
        "optional": [_adapter_row(family, "optional") for family in OPTIONAL_DETECTOR_FAMILIES],
    }


def format_adapter_list_text(report: dict[str, Any]) -> str:
    lines = ["LSDF Adapter Families"]
    for section in ("baseline", "adapters", "optional"):
        lines.append(f"{section}:")
        for row in report[section]:
            lines.append(
                f"- {row['name']} ({row['family']}): {row['description']}"
            )
    return "\n".join(lines) + "\n"


def format_adapter_list_markdown(report: dict[str, Any]) -> str:
    lines = ["# LSDF Adapter Families", ""]
    for section in ("baseline", "adapters", "optional"):
        rows = report[section]
        lines.extend(
            [
                f"## {section.title()}",
                "",
                "| Name | Internal family | Description |",
                "| --- | --- | --- |",
            ]
        )
        for row in rows:
            lines.append(f"| `{row['name']}` | `{row['family']}` | {row['description']} |")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def list_entity_vocabulary() -> dict[str, Any]:
    manifest = _load_subtype_manifest()
    return {
        "manifest_path": str(SUBTYPE_MANIFEST_PATH),
        "version": manifest["version"],
        "categories": {
            category: sorted(members)
            for category, members in sorted(manifest["categories"].items())
        },
        "standalone_entities": sorted(manifest["standalone_entities"]),
        "reserved_subtypes": {
            entity: details
            for entity, details in sorted(manifest["reserved_subtypes"].items())
        },
        "detectors": {
            detector_id: sorted(str(entity) for entity in detector.get("emits", []))
            for detector_id, detector in sorted(manifest["detectors"].items())
        },
    }


def format_entity_list_text(report: dict[str, Any]) -> str:
    lines = ["LSDF Entity Vocabulary"]
    for category, members in report["categories"].items():
        lines.append(f"- {category}: {_join(members)}")
    lines.append(f"- Standalone: {_join(report['standalone_entities'])}")
    lines.append(f"- Reserved: {_join(report['reserved_subtypes'])}")
    return "\n".join(lines) + "\n"


def format_entity_list_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# LSDF Entity Vocabulary",
        "",
        f"- Manifest: `{report['manifest_path']}`",
        f"- Version: {report['version']}",
        "",
        "## Categories",
        "",
        "| Category | Members |",
        "| --- | --- |",
    ]
    for category, members in report["categories"].items():
        lines.append(f"| `{category}` | {_join(f'`{member}`' for member in members)} |")
    lines.extend(
        [
            "",
            "## Standalone Entities",
            "",
            _join(f"`{entity}`" for entity in report["standalone_entities"]),
            "",
            "## Reserved Subtypes",
            "",
            "| Entity | Status | Fallback emitter |",
            "| --- | --- | --- |",
        ]
    )
    for entity, details in report["reserved_subtypes"].items():
        lines.append(
            f"| `{entity}` | {details.get('status', '')} | `{details.get('fallback_emitter', 'none')}` |"
        )
    return "\n".join(lines).rstrip() + "\n"


def generate_policy_keypair(public_key_path: Path, private_key_path: Path) -> dict[str, Any]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    private_key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_key_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return {
        "generated": True,
        "algorithm": "ed25519",
        "public_key_path": str(public_key_path),
        "private_key_path": str(private_key_path),
    }


def sign_policy_file(path: Path, output: Path, private_key_path: Path | None = None) -> dict[str, Any]:
    load_policy(path)
    if private_key_path is None:
        return _sign_policy_legacy(path, output)
    private_key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("Policy private key must be an Ed25519 PEM key")
    payload = path.read_bytes()
    digest = _policy_digest(path)
    signature = {
        "version": SIGNATURE_VERSION,
        "algorithm": "ed25519",
        "policy_path": str(path),
        "policy_sha256": digest,
        "signature": base64.b64encode(private_key.sign(payload)).decode("ascii"),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(signature, indent=2) + "\n", encoding="utf-8")
    return {
        "signed": True,
        "legacy": False,
        "algorithm": "ed25519",
        "policy_path": str(path),
        "signature_path": str(output),
        "sha256": digest,
    }


def verify_policy_signature(
    path: Path,
    signature_path: Path | None = None,
    public_key_path: Path | None = None,
) -> dict[str, Any]:
    load_policy(path)
    signature_path = signature_path or path.with_suffix(path.suffix + ".sig")
    signature = json.loads(signature_path.read_text(encoding="utf-8"))
    version = signature.get("version")
    if version == LEGACY_SIGNATURE_VERSION:
        return _verify_legacy_policy_signature(path, signature_path, signature)
    expected = _policy_digest(path)
    base = {
        "policy_path": str(path),
        "signature_path": str(signature_path),
        "sha256": expected,
        "legacy": False,
        "algorithm": "ed25519",
    }
    if version != SIGNATURE_VERSION:
        return {**base, "valid": False, "reason": "unsupported signature version"}
    if signature.get("policy_sha256") != expected:
        return {**base, "valid": False, "reason": "policy digest mismatch"}
    if public_key_path is None:
        return {**base, "valid": False, "reason": "public key required for Ed25519 signature"}
    public_key = serialization.load_pem_public_key(public_key_path.read_bytes())
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("Policy public key must be an Ed25519 PEM key")
    try:
        public_key.verify(base64.b64decode(signature["signature"]), path.read_bytes())
    except (InvalidSignature, KeyError, ValueError):
        return {**base, "valid": False, "reason": "signature verification failed"}
    return {**base, "valid": True}


def _sign_policy_legacy(path: Path, output: Path) -> dict[str, Any]:
    digest = _policy_digest(path)
    signature = {
        "version": LEGACY_SIGNATURE_VERSION,
        "policy_path": str(path),
        "sha256": digest,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(signature, indent=2) + "\n", encoding="utf-8")
    return {
        "signed": True,
        "legacy": True,
        "algorithm": "sha256",
        "policy_path": str(path),
        "signature_path": str(output),
        "sha256": digest,
    }


def _verify_legacy_policy_signature(
    path: Path,
    signature_path: Path,
    signature: dict[str, Any],
) -> dict[str, Any]:
    expected = _policy_digest(path)
    valid = signature.get("sha256") == expected
    return {
        "valid": valid,
        "legacy": True,
        "algorithm": "sha256",
        "policy_path": str(path),
        "signature_path": str(signature_path),
        "sha256": expected,
        **({} if valid else {"reason": "legacy digest mismatch"}),
    }


def _policy_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _rule_values(match: dict[str, Any], single_key: str, list_key: str) -> list[str]:
    values: list[str] = []
    if single_key in match:
        values.append(str(match[single_key]))
    if list_key in match:
        values.extend(str(value) for value in match[list_key])
    return values


def _adapter_row(family: str, kind: str) -> dict[str, str]:
    name = FAMILY_DISPLAY_NAMES.get(family, family)
    return {
        "name": name,
        "family": family,
        "kind": kind,
        "description": _adapter_description(family),
    }


def _adapter_description(family: str) -> str:
    descriptions = {
        "regex": "Dependency-light structured secrets, anchored identifiers, contact, financial, and MRN patterns.",
        "entropy": "Dependency-light high-entropy credential-like token supplement.",
        "medical-regex": "Dependency-light clinical context patterns for PHI subtypes.",
        "contextual-anchored": "Dependency-light inline XML and narrow label/value secret and identity fields.",
        "contextual-broad": "Opt-in broad contextual PII, PHI, and output-shape heuristics.",
        "xpia": "Opt-in prompt-injection heuristics for RAG and tool-result surfaces.",
        "presidio": "Optional Microsoft Presidio analyzer adapter normalized to LSDF entities.",
        "gliner": "Optional local GLiNER open-vocabulary PII/PHI model adapter.",
        "openai_privacy_filter": "Optional bundled OpenAI privacy-filter reference ML detector adapter.",
    }
    return descriptions.get(family, "Custom detector family.")


def _performance_for_profile(
    profile: str,
    path: Path = PERFORMANCE_DOC_PATH,
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "available": False,
        "source": str(path),
        "profile": profile,
    }
    if not path.exists():
        return {**report, "reason": "performance report not found"}
    lines = path.read_text(encoding="utf-8").splitlines()
    header = f"## Profile `{profile}`"
    try:
        start = lines.index(header)
    except ValueError:
        return {**report, "reason": "profile not found in performance report"}

    end = next(
        (idx for idx in range(start + 1, len(lines)) if lines[idx].startswith("## Profile `")),
        len(lines),
    )
    section = lines[start:end]
    families = ""
    mode = ""
    payloads: dict[str, dict[str, Any]] = {}
    in_payload_table = False
    for line in section:
        if line.startswith("Detector families:"):
            left, _, right = line.partition(". Mode:")
            families = left.replace("Detector families:", "").strip()
            mode = right.strip(" `.") if right else ""
            continue
        if line.startswith("| Payload |"):
            in_payload_table = True
            continue
        if not in_payload_table:
            continue
        if not line.startswith("| `"):
            if payloads:
                in_payload_table = False
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 8:
            continue
        payload = cells[0].strip("`")
        try:
            payloads[payload] = {
                "throughput_per_sec": float(cells[1].replace(",", "")),
                "min_ms": float(cells[2].replace(",", "")),
                "p50_ms": float(cells[3].replace(",", "")),
                "p95_ms": float(cells[4].replace(",", "")),
                "p99_ms": float(cells[5].replace(",", "")),
                "max_ms": float(cells[6].replace(",", "")),
                "avg_ms": float(cells[7].replace(",", "")),
            }
        except ValueError:
            continue
    if not payloads:
        return {**report, "reason": "payload table not found in performance report"}
    return {
        **report,
        "available": True,
        "detector_families": families,
        "mode": mode,
        "payloads": payloads,
    }


def _format_policy_performance_text(performance: dict[str, Any] | None) -> str:
    if not performance or not performance.get("available"):
        return "- Performance: not available\n"
    payloads = performance.get("payloads", {})
    small = payloads.get("small_chat_turn", {})
    rag = payloads.get("rag_heavy_session", {})
    parts = []
    if small:
        parts.append(f"small_chat_turn p50={small['p50_ms']:.3f} ms")
    if rag:
        parts.append(f"rag_heavy_session p50={rag['p50_ms']:.3f} ms")
    detail = "; ".join(parts) if parts else "profile present"
    return f"- Performance: {detail} (source: {performance['source']})\n"


def _add_performance_section(lines: list[str], performance: dict[str, Any] | None) -> None:
    lines.extend(["## Performance", ""])
    if not performance or not performance.get("available"):
        reason = (performance or {}).get("reason", "not available")
        source = (performance or {}).get("source", str(PERFORMANCE_DOC_PATH))
        lines.extend([f"- Source: `{source}`", f"- Status: {reason}", ""])
        return
    lines.extend(
        [
            f"- Source: `{performance['source']}`",
            f"- Detector families in report: {performance.get('detector_families') or 'unknown'}",
            "",
            "| Payload | p50 ms | p95 ms | p99 ms |",
            "| --- | ---: | ---: | ---: |",
        ]
    )
    for payload, stats in performance["payloads"].items():
        lines.append(
            f"| `{payload}` | {stats['p50_ms']:.3f} | {stats['p95_ms']:.3f} | {stats['p99_ms']:.3f} |"
        )
    lines.append("")


def _policy_posture(mode: str, actions: dict[str, int]) -> str:
    if mode == "monitor":
        return "observe decisions without enforcing transforms or blocks"
    if actions.get("block", 0) and actions.get("redact", 0):
        return "enforce blocking on high-risk surfaces and redaction on releasable content"
    if actions.get("block", 0):
        return "enforce blocking for matched sensitive data"
    if actions.get("redact", 0) or actions.get("tokenize", 0):
        return "enforce transformation for matched sensitive data"
    return "low-enforcement or allow/log focused policy"


def _format_counts(counts: dict[str, int]) -> str:
    if not counts:
        return "none"
    return ", ".join(f"{key}={counts[key]}" for key in sorted(counts))


def _add_table(lines: list[str], title: str, counts: dict[str, int]) -> None:
    lines.extend([f"## {title}", "", "| Value | Rules |", "| --- | ---: |"])
    if counts:
        for key in sorted(counts):
            safe_key = str(key).replace("|", "\\|")
            lines.append(f"| {safe_key} | {counts[key]} |")
    else:
        lines.append("| none | 0 |")
    lines.append("")


def _join(values: Iterable[str]) -> str:
    items = list(values)
    return ", ".join(items) if items else "none"
