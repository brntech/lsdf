# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import warnings

import yaml

from .detectors import DEPENDENCY_LIGHT_DETECTOR_FAMILIES, known_detector_families
from .types import Finding, PolicyDecision

VALID_ACTIONS = {
    "redact",
    "mask",
    "tokenize",
    "block",
    "replace",
    "hash",
    "encrypt",
}
VALID_MODES = {"monitor", "redact", "block"}
VALID_ON_FAIL = {"block", "mask", "reask", "observe", "exception"}
VALID_SCOPES = {"span", "surface"}
VALID_HASH_ALGOS = {"sha256", "sha512", "blake2b"}
POLICY_DIR = Path(__file__).resolve().parents[2] / "policies"
DOMAIN_PACK_DIR = POLICY_DIR / "domain-packs"
SUBTYPE_MANIFEST_PATH = POLICY_DIR / "subtype-emission-manifest.yaml"
FOUNDATION_FIXTURE_ROOT = Path(__file__).resolve().parents[2] / "tests" / "foundation" / "fixtures"
STREAMING_SURFACES = {"output.stream_chunk"}
DEFAULT_POLICY_SURFACES = {
    "input.messages",
    "input.system",
    "input.developer",
    "input.rag_context",
    "input.tool_results",
    "output.content",
    "output.stream_chunk",
    "output.tool_calls.arguments",
    "output.reasoning",
    "logs.traces",
}
POLICY_PROFILES = {
    "default": "default.yaml",
    "balanced": "balanced.yaml",
    "broad-pii": "broad-pii.yaml",
    "strict": "strict.yaml",
    "broad-pii-ml": "broad-pii-ml.yaml",
    "monitor": "monitor.yaml",
    "dev": "dev.yaml",
    "healthcare": "healthcare.yaml",
}
DOMAIN_PACKS = {
    "healthcare": "healthcare.yaml",
    "financial": "financial.yaml",
    "enterprise-dlp": "enterprise-dlp.yaml",
}
HEALTHCARE_DOUBLE_APPLY_ERROR = """Error: cannot compose --profile healthcare with --domain-pack healthcare
  Both define rules under the `healthcare.*` namespace. Pick one:
    --profile healthcare       (clinical defaults)
    --profile broad-pii --domain-pack healthcare       (BYO base + pack overlay)"""
PROMPT_INJECTION_HEALTHCARE_NOTE = (
    "INFO: prompt-injection detects RAG/tool-result attacks, not PHI; PHI "
    "containment still requires healthcare/PII detection such as the healthcare "
    "profile or healthcare domain pack."
)


@dataclass(frozen=True)
class AuditConfig:
    store_raw_values: bool = False
    store_redacted_evidence: bool = True
    include_policy_decision: bool = True


@dataclass(frozen=True)
class DetectorConfig:
    enabled_families: tuple[str, ...] = DEPENDENCY_LIGHT_DETECTOR_FAMILIES
    family_settings: dict[str, dict[str, Any]] = field(default_factory=dict)


@dataclass(frozen=True)
class Rule:
    id: str
    match: dict[str, Any]
    action: str
    severity: str = "medium"
    priority: int = 0
    on_fail: str | None = None
    scope: str = "span"
    # Per-rule operator parameters (action-specific). Validated at load
    # time: `replace` requires `replacement`, `hash` accepts an optional
    # `hash_algo`, `encrypt` requires `encrypt_key_env`.
    replacement: str | None = None
    hash_algo: str | None = None
    encrypt_key_env: str | None = None

    def matches(self, finding: Finding, categories: dict[str, set[str]] | None = None) -> bool:
        min_confidence = self.match.get("min_confidence")
        if min_confidence is not None and finding.confidence < float(min_confidence):
            return False
        return _match_entity(self.match, finding.entity, categories or {}) and _match_surface(
            self.match, finding.surface
        )

    def specificity(self) -> int:
        keys = {
            "entity",
            "entity_any_of",
            "entity_in_category",
            "entity_in_category_any_of",
            "entity_except",
            "surface",
            "surface_any_of",
            "min_confidence",
        }
        return sum(1 for key in keys if key in self.match)


@dataclass(frozen=True)
class GatePromise:
    corpora: tuple[str, ...]
    recall_floor: float
    specificity_floor: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "corpora": list(self.corpora),
            "recall_floor": self.recall_floor,
            "specificity_floor": self.specificity_floor,
        }


@dataclass(frozen=True)
class Policy:
    version: str
    name: str
    mode: str
    entities: set[str]
    surfaces: set[str]
    rules: list[Rule]
    audit: AuditConfig
    detectors: DetectorConfig = DetectorConfig()
    entity_categories: dict[str, set[str]] = field(default_factory=dict)
    gate_promise: GatePromise | None = None

    def decide(self, finding: Finding) -> PolicyDecision:
        if self.entities and not _entity_in_scope(
            finding.entity, self.entities, self.entity_categories
        ):
            return _default_allow_decision(finding)
        for rule in self.rules:
            if rule.matches(finding, self.entity_categories):
                return PolicyDecision(
                    finding=finding,
                    action=rule.action,
                    rule_id=rule.id,
                    severity=rule.severity,
                    on_fail=rule.on_fail,
                    scope=rule.scope,
                    scope_escalated=_scope_escalated(rule.scope, finding),
                    replacement=rule.replacement,
                    hash_algo=rule.hash_algo,
                    encrypt_key_env=rule.encrypt_key_env,
                )
        return _default_allow_decision(finding)

    def summary(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "name": self.name,
            "mode": self.mode,
            "entity_count": len(self.entities),
            "surface_count": len(self.surfaces),
            "rule_count": len(self.rules),
            "detector_families": list(self.detectors.enabled_families),
            "detector_settings": sorted(self.detectors.family_settings),
            "entity_categories": {key: sorted(value) for key, value in self.entity_categories.items()},
            "gate_promise": self.gate_promise.as_dict() if self.gate_promise else None,
            "rules": [rule.id for rule in self.rules],
        }


def load_policy(path: str | Path) -> Policy:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Policy must be a YAML mapping")
    _require(raw, ["version", "name", "action"])
    action_raw = raw["action"]
    if not isinstance(action_raw, dict):
        raise ValueError("Policy action config must be a YAML mapping")
    _require(action_raw, ["mode", "rules"])
    audit_raw = raw.get("audit", {})
    if bool(audit_raw.get("store_raw_values", False)):
        raise ValueError("audit.store_raw_values=true is not supported by this raw-value-safe MVP")
    if action_raw["mode"] not in VALID_MODES:
        raise ValueError(f"Policy mode must be one of: {', '.join(sorted(VALID_MODES))}")
    detection_raw = raw.get("detection", {})
    if detection_raw is None:
        detection_raw = {}
    if not isinstance(detection_raw, dict):
        raise ValueError("Policy detection config must be a YAML mapping")
    detector_config = _load_detection_config(detection_raw)
    manifest = _load_subtype_manifest(detector_config.enabled_families)
    categories = manifest["categories"]
    entities = set(str(entity) for entity in detection_raw.get("entities", []) or [])
    _validate_detection_entities(entities, manifest)
    surfaces = _policy_surfaces(action_raw["rules"])
    rules = [_rule_from_yaml(rule) for rule in action_raw["rules"]]
    _validate_rules(rules, surfaces, manifest)
    gate_promise = _load_gate_promise(raw.get("gate_promise"), policy_name=str(raw["name"]))
    return Policy(
        version=str(raw["version"]),
        name=str(raw["name"]),
        mode=str(action_raw["mode"]),
        entities=entities,
        surfaces=surfaces,
        rules=sorted(rules, key=_rule_sort_key, reverse=True),
        audit=AuditConfig(
            store_raw_values=bool(audit_raw.get("store_raw_values", False)),
            store_redacted_evidence=bool(audit_raw.get("store_redacted_evidence", True)),
            include_policy_decision=bool(audit_raw.get("include_policy_decision", True)),
        ),
        detectors=detector_config,
        entity_categories=categories,
        gate_promise=gate_promise,
    )


def load_policy_profile(profile: str) -> Policy:
    try:
        filename = POLICY_PROFILES[profile]
    except KeyError as exc:
        valid = ", ".join(sorted(POLICY_PROFILES))
        raise ValueError(f"Unknown policy profile: {profile}. Valid profiles: {valid}") from exc
    return load_policy(POLICY_DIR / filename)


def load_profile_gate_promise(profile: str) -> GatePromise | None:
    try:
        filename = POLICY_PROFILES[profile]
    except KeyError as exc:
        valid = ", ".join(sorted(POLICY_PROFILES))
        raise ValueError(f"Unknown policy profile: {profile}. Valid profiles: {valid}") from exc
    raw = yaml.safe_load((POLICY_DIR / filename).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"Policy profile {profile} must be a YAML mapping")
    return _load_gate_promise(raw.get("gate_promise"), policy_name=str(raw.get("name", profile)))


def load_effective_policy(
    profile: str = "default",
    *,
    domain_packs: list[str] | tuple[str, ...] | None = None,
) -> Policy:
    domain_pack_names = tuple(str(pack) for pack in (domain_packs or ()))
    _validate_profile_pack_composition(profile, domain_pack_names)
    policy = load_policy_profile(profile)
    if not domain_pack_names:
        return policy
    entities = set(policy.entities)
    surfaces = set(policy.surfaces)
    rules = list(policy.rules)
    manifest = _load_subtype_manifest(policy.detectors.enabled_families)
    pack_names: list[str] = []
    for pack in domain_pack_names:
        raw = _load_domain_pack(pack)
        pack_names.append(str(raw["name"]))
        entities.update(str(entity) for entity in raw.get("entities", []))
        surfaces.update(str(surface) for surface in raw.get("surfaces", []))
        pack_rules = _domain_pack_rules(raw)
        surfaces.update(_policy_surfaces(pack_rules))
        for rule in pack_rules:
            rules.append(_rule_from_yaml(rule))
    _validate_detection_entities(entities, manifest)
    _validate_rules(rules, surfaces, manifest)
    name = f"{policy.name}+{'+'.join(pack_names)}"
    return Policy(
        version=policy.version,
        name=name,
        mode=policy.mode,
        entities=entities,
        surfaces=surfaces,
        rules=sorted(rules, key=_rule_sort_key, reverse=True),
        audit=policy.audit,
        detectors=policy.detectors,
        entity_categories=policy.entity_categories,
        gate_promise=policy.gate_promise,
    )


def load_subtype_manifest(
    active_families: tuple[str, ...] | None = None,
    path: Path = SUBTYPE_MANIFEST_PATH,
    fixture_root: Path = FOUNDATION_FIXTURE_ROOT,
) -> dict[str, Any]:
    return _load_subtype_manifest(active_families, path=path, fixture_root=fixture_root)


def release_gated_profile_names() -> tuple[str, ...]:
    names: list[str] = []
    for profile in POLICY_PROFILES:
        if load_profile_gate_promise(profile) is not None:
            names.append(profile)
    return tuple(names)


def policy_validation_notes(
    policy: Policy,
    *,
    profile: str | None = None,
    domain_packs: list[str] | tuple[str, ...] | None = None,
) -> list[str]:
    notes: list[str] = []
    healthcare_involved = (
        profile == "healthcare"
        or "healthcare" in {str(pack) for pack in (domain_packs or ())}
        or policy.name == "healthcare"
        or "+healthcare" in policy.name
    )
    if healthcare_involved and "xpia" in policy.detectors.enabled_families:
        notes.append(PROMPT_INJECTION_HEALTHCARE_NOTE)
    return notes


def _load_gate_promise(raw: Any, *, policy_name: str) -> GatePromise | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError(f"Policy {policy_name} gate_promise must be a YAML mapping")
    allowed = {"corpora", "recall_floor", "specificity_floor"}
    keys = set(raw)
    missing = sorted(allowed - keys)
    extra = sorted(keys - allowed)
    if missing or extra:
        detail = []
        if missing:
            detail.append(f"missing={missing}")
        if extra:
            detail.append(f"extra={extra}")
        raise ValueError(
            f"Policy {policy_name} gate_promise must contain exactly "
            "corpora, recall_floor, and specificity_floor "
            f"({', '.join(detail)})"
        )
    corpora_raw = raw["corpora"]
    if isinstance(corpora_raw, str) or not isinstance(corpora_raw, list):
        raise ValueError(f"Policy {policy_name} gate_promise.corpora must be a list")
    corpora = tuple(str(corpus) for corpus in corpora_raw)
    if not corpora:
        raise ValueError(f"Policy {policy_name} gate_promise.corpora must not be empty")
    recall_floor = _load_gate_floor(raw["recall_floor"], policy_name, "recall_floor")
    specificity_floor = _load_gate_floor(
        raw["specificity_floor"],
        policy_name,
        "specificity_floor",
    )
    return GatePromise(
        corpora=corpora,
        recall_floor=recall_floor,
        specificity_floor=specificity_floor,
    )


def _load_gate_floor(raw: Any, policy_name: str, key: str) -> float:
    try:
        floor = float(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Policy {policy_name} gate_promise.{key} must be numeric") from exc
    if floor < 0.0 or floor > 1.0:
        raise ValueError(
            f"Policy {policy_name} gate_promise.{key} must be between 0.0 and 1.0"
        )
    return floor


def _validate_profile_pack_composition(
    profile: str,
    domain_packs: tuple[str, ...],
) -> None:
    if profile == "healthcare" and "healthcare" in domain_packs:
        raise ValueError(HEALTHCARE_DOUBLE_APPLY_ERROR)


def _load_domain_pack(pack: str) -> dict[str, Any]:
    try:
        filename = DOMAIN_PACKS[pack]
    except KeyError as exc:
        valid = ", ".join(sorted(DOMAIN_PACKS))
        raise ValueError(f"Unknown domain pack: {pack}. Valid domain packs: {valid}") from exc
    raw = yaml.safe_load((DOMAIN_PACK_DIR / filename).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"Domain pack {pack} must be a YAML mapping")
    _require(raw, ["name", "rules"])
    return raw


def _domain_pack_rules(raw: dict[str, Any]) -> list[dict[str, Any]]:
    rules = raw.get("rules", [])
    if rules is None:
        return []
    if not isinstance(rules, list):
        raise ValueError(f"Domain pack {raw.get('name', '<unknown>')} rules must be a list")
    return rules


def _rule_from_yaml(rule: dict[str, Any]) -> Rule:
    rule_id = str(rule["id"])
    action = str(rule["action"])
    replacement = rule.get("replacement")
    hash_algo = rule.get("hash_algo")
    encrypt_key_env = rule.get("encrypt_key_env")
    scope = str(rule.get("scope", "span"))
    if scope not in VALID_SCOPES:
        valid = ", ".join(sorted(VALID_SCOPES))
        raise ValueError(f"Rule {rule_id} has invalid scope: {scope!r}. Valid scopes: {valid}")
    if action == "replace":
        if not isinstance(replacement, str):
            raise ValueError(
                f"Rule {rule_id} action=replace requires `replacement: <string>`"
            )
    elif replacement is not None:
        raise ValueError(
            f"Rule {rule_id} carries `replacement` but action={action!r} ignores it"
        )
    if action == "hash":
        algo = "sha256" if hash_algo is None else str(hash_algo)
        if algo not in VALID_HASH_ALGOS:
            valid = ", ".join(sorted(VALID_HASH_ALGOS))
            raise ValueError(
                f"Rule {rule_id} action=hash uses unsupported hash_algo "
                f"{algo!r}. Valid: {valid}"
            )
        hash_algo = algo
    elif hash_algo is not None:
        raise ValueError(
            f"Rule {rule_id} carries `hash_algo` but action={action!r} ignores it"
        )
    if action == "encrypt":
        if not isinstance(encrypt_key_env, str) or not encrypt_key_env.strip():
            raise ValueError(
                f"Rule {rule_id} action=encrypt requires `encrypt_key_env: <env var name>` "
                f"holding a urlsafe-base64 32-byte Fernet key"
            )
    elif encrypt_key_env is not None:
        raise ValueError(
            f"Rule {rule_id} carries `encrypt_key_env` but action={action!r} ignores it"
        )
    return Rule(
        id=rule_id,
        match=dict(rule.get("match", {})),
        action=action,
        severity=str(rule.get("severity", "medium")),
        priority=int(rule.get("priority", 0)),
        on_fail=_normalise_on_fail(rule.get("on_fail")),
        scope=scope,
        replacement=replacement if action == "replace" else None,
        hash_algo=hash_algo if action == "hash" else None,
        encrypt_key_env=encrypt_key_env if action == "encrypt" else None,
    )


def _normalise_on_fail(value: Any) -> str | None:
    if value is None:
        return None
    candidate = str(value)
    if candidate not in VALID_ON_FAIL:
        valid = ", ".join(sorted(VALID_ON_FAIL))
        raise ValueError(
            f"Rule has invalid on_fail value: {candidate!r}. Valid on_fail values: {valid}"
        )
    return candidate


def _require(raw: dict[str, Any], keys: list[str]) -> None:
    missing = [key for key in keys if key not in raw]
    if missing:
        raise ValueError(f"Policy missing required keys: {', '.join(missing)}")


def _load_detection_config(raw: dict[str, Any]) -> DetectorConfig:
    adapters = raw.get("adapters", [])
    if adapters is None:
        adapters = []
    if isinstance(adapters, str):
        adapters = [adapters]
    if not isinstance(adapters, list):
        raise ValueError("Policy detection.adapters must be a list")
    exclude_engines = raw.get("exclude_engines", [])
    if exclude_engines is None:
        exclude_engines = []
    if isinstance(exclude_engines, str):
        exclude_engines = [exclude_engines]
    if not isinstance(exclude_engines, list):
        raise ValueError("Policy detection.exclude_engines must be a list")
    baseline = [
        family
        for family in DEPENDENCY_LIGHT_DETECTOR_FAMILIES
        if family not in {str(engine) for engine in exclude_engines}
    ]
    families = baseline + [_normalise_adapter_name(str(adapter)) for adapter in adapters]
    return _load_detector_config(
        {
            "enabled_families": families,
            "settings": raw.get("settings", {}),
        }
    )


def _normalise_adapter_name(adapter: str) -> str:
    if adapter == "prompt-injection":
        return "xpia"
    return adapter


def _load_detector_config(raw: Any) -> DetectorConfig:
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError("Policy detectors config must be a YAML mapping")
    enabled = raw.get("enabled_families", raw.get("enabled"))
    if enabled is None:
        return DetectorConfig(family_settings=_load_detector_settings(raw))
    if isinstance(enabled, str):
        enabled = [enabled]
    families = tuple(str(family) for family in enabled)
    active_families = known_detector_families()
    for family in families:
        if family not in active_families:
            valid = ", ".join(active_families)
            raise ValueError(
                f"Unknown detector family: {family}. Valid detector families: {valid}"
            )
    return DetectorConfig(
        enabled_families=families,
        family_settings=_load_detector_settings(raw),
    )


def _load_detector_settings(raw: dict[str, Any]) -> dict[str, dict[str, Any]]:
    settings_raw = raw.get("settings", {})
    if settings_raw is None:
        settings_raw = {}
    if not isinstance(settings_raw, dict):
        raise ValueError("Policy detectors.settings must be a YAML mapping")
    settings: dict[str, dict[str, Any]] = {}
    for family, value in settings_raw.items():
        if value is None:
            settings[str(family)] = {}
            continue
        if not isinstance(value, dict):
            raise ValueError(
                f"Policy detectors.settings.{family} must be a YAML mapping"
            )
        settings[str(family)] = dict(value)

    reserved = {"enabled", "enabled_families", "settings"}
    for key, value in raw.items():
        if key in reserved:
            continue
        if value is None:
            settings[str(key)] = {}
            continue
        if not isinstance(value, dict):
            raise ValueError(f"Policy detectors.{key} must be a YAML mapping")
        settings[str(key)] = dict(value)
    return settings


def _validate_rules(
    rules: list[Rule],
    surfaces: set[str],
    manifest: dict[str, Any],
) -> None:
    for rule in rules:
        if rule.action not in VALID_ACTIONS:
            if rule.action == "require_approval":
                raise ValueError(
                    f"Rule {rule.id} uses require_approval, but LSDF has no executable "
                    "approval workflow yet. Use mode=monitor or on_fail=observe for review-only rollout, or "
                    "block/redact/tokenize for enforceable actions."
                )
            raise ValueError(f"Rule {rule.id} has invalid action: {rule.action}")
        _validate_rule_entities(rule, manifest)
        for surface in _rule_surfaces(rule):
            if surface != "any" and surface not in surfaces:
                raise ValueError(f"Rule {rule.id} references unknown surface: {surface}")
        rule_surfaces = _rule_surfaces(rule)
        if rule.scope == "surface" and (
            not rule_surfaces
            or "any" in rule_surfaces
            or any(surface in STREAMING_SURFACES for surface in rule_surfaces)
        ):
            raise ValueError(
                f"Rule {rule.id} uses scope=surface on a streaming-capable surface"
            )


def _rule_entities(rule: Rule) -> set[str]:
    entities: set[str] = set()
    if "entity" in rule.match:
        entities.add(str(rule.match["entity"]))
    if "entity_any_of" in rule.match:
        entities.update(str(entity) for entity in rule.match["entity_any_of"])
    if "entity_except" in rule.match:
        entities.update(str(entity) for entity in rule.match["entity_except"])
    return entities


def _rule_categories(rule: Rule) -> set[str]:
    categories: set[str] = set()
    if "entity_in_category" in rule.match:
        categories.add(str(rule.match["entity_in_category"]))
    if "entity_in_category_any_of" in rule.match:
        categories.update(str(category) for category in rule.match["entity_in_category_any_of"])
    return categories


def _rule_surfaces(rule: Rule) -> set[str]:
    surfaces: set[str] = set()
    if "surface" in rule.match:
        surfaces.add(str(rule.match["surface"]))
    if "surface_any_of" in rule.match:
        surfaces.update(str(surface) for surface in rule.match["surface_any_of"])
    return surfaces


def _validate_rule_entities(rule: Rule, manifest: dict[str, Any]) -> None:
    categories: dict[str, set[str]] = manifest["categories"]
    if "entity_except" in rule.match and not _rule_categories(rule):
        raise ValueError(
            f"Rule {rule.id} uses entity_except without entity_in_category"
        )
    for category in _rule_categories(rule):
        if category not in categories:
            valid = ", ".join(sorted(categories))
            raise ValueError(
                f"Rule {rule.id} references unknown entity category: {category}. "
                f"Valid categories: {valid}"
            )
    emitted_entities: set[str] = manifest["emitted_entities"]
    all_emitted_entities: set[str] = manifest["all_emitted_entities"]
    reserved_subtypes: dict[str, dict[str, Any]] = manifest["reserved_subtypes"]
    standalone_entities: set[str] = manifest["standalone_entities"]
    for entity in _rule_entities(rule):
        if entity in emitted_entities:
            continue
        if entity in reserved_subtypes:
            hint = reserved_subtypes[entity].get("fallback_emitter", "none")
            warnings.warn(
                f"RESERVED_SUBTYPE_WARNING: Rule {rule.id} references reserved "
                f"subtype {entity}; fallback_emitter={hint}",
                stacklevel=2,
            )
            continue
        if entity in all_emitted_entities or entity in standalone_entities:
            _warn_no_active_emitter(
                entity,
                f"Rule {rule.id}",
                categories,
            )
            continue
        suggestion = _category_suggestion(entity, categories)
        detail = (
            f" did you mean `entity_in_category: {suggestion}`?"
            if suggestion
            else ""
        )
        raise ValueError(f"Rule {rule.id} references unknown entity: {entity}.{detail}")


def _validate_detection_entities(entities: set[str], manifest: dict[str, Any]) -> None:
    categories: dict[str, set[str]] = manifest["categories"]
    emitted_entities: set[str] = manifest["emitted_entities"]
    all_emitted_entities: set[str] = manifest["all_emitted_entities"]
    reserved_subtypes: dict[str, dict[str, Any]] = manifest["reserved_subtypes"]
    standalone_entities: set[str] = manifest["standalone_entities"]
    for entity in entities:
        if entity in categories or entity in emitted_entities:
            continue
        if entity in reserved_subtypes:
            hint = reserved_subtypes[entity].get("fallback_emitter", "none")
            warnings.warn(
                f"RESERVED_SUBTYPE_WARNING: Policy detection.entities references "
                f"reserved subtype {entity}; fallback_emitter={hint}",
                stacklevel=2,
            )
            continue
        if entity in all_emitted_entities or entity in standalone_entities:
            _warn_no_active_emitter(
                entity,
                "Policy detection.entities",
                categories,
            )
            continue
        suggestion = _category_suggestion(entity, categories)
        detail = (
            f" did you mean to scope with category `{suggestion}`?"
            if suggestion
            else ""
        )
        raise ValueError(f"Policy detection.entities references unknown entity: {entity}.{detail}")


def _category_suggestion(entity: str, categories: dict[str, set[str]]) -> str | None:
    if entity in categories:
        return entity
    for category, members in categories.items():
        if entity in members:
            return category
    for category in categories:
        if category in entity:
            return category
    return None


def _warn_no_active_emitter(
    entity: str,
    owner: str,
    categories: dict[str, set[str]],
) -> None:
    suggestion = _category_suggestion(entity, categories)
    detail = (
        f"; use `entity_in_category: {suggestion}` if the broader category is intended"
        if suggestion and suggestion != entity
        else "; rules using this exact entity may fire on no findings"
    )
    warnings.warn(
        f"NO_ACTIVE_EMITTER_WARNING: {owner} references entity {entity}, but "
        f"active detectors cannot emit it{detail}",
        stacklevel=3,
    )


def _match_entity(match: dict[str, Any], entity: str, categories: dict[str, set[str]]) -> bool:
    positive_matches: list[bool] = []
    if match.get("entity"):
        positive_matches.append(str(match["entity"]) == entity)
    if match.get("entity_any_of"):
        positive_matches.append(entity in set(match["entity_any_of"]))
    if match.get("entity_in_category"):
        positive_matches.append(entity in categories.get(str(match["entity_in_category"]), set()))
    if match.get("entity_in_category_any_of"):
        positive_matches.append(
            any(
                entity in categories.get(str(category), set())
                for category in match["entity_in_category_any_of"]
            )
        )
    if positive_matches and not any(positive_matches):
        return False
    if match.get("entity_except") and entity in set(match["entity_except"]):
        return False
    return True


def _match_surface(match: dict[str, Any], surface: str) -> bool:
    if match.get("surface") == "any":
        return True
    if match.get("surface") and match["surface"] != surface:
        return False
    if match.get("surface_any_of") and surface not in set(match["surface_any_of"]):
        return False
    return True


def _policy_surfaces(_rules: list[dict[str, Any]]) -> set[str]:
    return set(DEFAULT_POLICY_SURFACES)


def _load_subtype_manifest(
    active_families: tuple[str, ...] | None = None,
    path: Path = SUBTYPE_MANIFEST_PATH,
    fixture_root: Path = FOUNDATION_FIXTURE_ROOT,
) -> dict[str, Any]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Subtype-emission manifest must be a YAML mapping")
    detectors = raw.get("detectors", {})
    if not isinstance(detectors, dict):
        raise ValueError("Subtype-emission manifest detectors must be a mapping")
    active_family_set = set(active_families or ())
    filter_active = active_families is not None
    emitted_entities: set[str] = set()
    all_emitted_entities: set[str] = set()
    recall_floors: dict[tuple[str, str, str], float] = {}
    specificity_floors: dict[tuple[str, str, str], float] = {}
    out_of_scope_pairs: set[tuple[str, str, str]] = set()
    for detector_id, detector in detectors.items():
        if not isinstance(detector, dict):
            raise ValueError(f"Manifest detector {detector_id} must be a mapping")
        detector_id_text = str(detector_id)
        emits = detector.get("emits", [])
        if not isinstance(emits, list):
            raise ValueError(f"Manifest detector {detector_id}.emits must be a list")
        emitted = {str(entity) for entity in emits}
        all_emitted_entities.update(emitted)
        recall_floors.update(
            _load_manifest_floor_block(
                detector_id_text,
                detector,
                "recall_floor",
                emitted,
                fixture_root,
            )
        )
        specificity_floors.update(
            _load_manifest_floor_block(
                detector_id_text,
                detector,
                "specificity_floor",
                emitted,
                fixture_root,
            )
        )
        out_of_scope_pairs.update(
            _load_manifest_out_of_scope_block(
                detector_id_text,
                detector,
                emitted,
                fixture_root,
            )
        )
        detector_family = _manifest_detector_family(detector_id_text)
        if not filter_active or detector_family in active_family_set:
            emitted_entities.update(emitted)
    if set(recall_floors) != set(specificity_floors):
        recall_only = sorted(set(recall_floors) - set(specificity_floors))
        specificity_only = sorted(set(specificity_floors) - set(recall_floors))
        raise ValueError(
            "Manifest recall_floor and specificity_floor pairs must match; "
            f"recall_only={recall_only}, specificity_only={specificity_only}"
        )
    floor_keys = set(recall_floors) | set(specificity_floors)
    out_of_scope_with_floor = sorted(out_of_scope_pairs & floor_keys)
    if out_of_scope_with_floor:
        raise ValueError(
            "Manifest out_of_scope pairs must not declare recall_floor or "
            f"specificity_floor; overlapping={out_of_scope_with_floor}"
        )
    reserved = raw.get("reserved_subtypes", {})
    if not isinstance(reserved, dict):
        raise ValueError("Subtype-emission manifest reserved_subtypes must be a mapping")
    standalone_raw = raw.get("standalone_entities", [])
    if not isinstance(standalone_raw, list):
        raise ValueError("Subtype-emission manifest standalone_entities must be a list")
    standalone_entities = {str(entity) for entity in standalone_raw}
    categories_raw = raw.get("categories", {})
    if not isinstance(categories_raw, dict):
        raise ValueError("Subtype-emission manifest categories must be a mapping")
    categories: dict[str, set[str]] = {}
    for category, members in categories_raw.items():
        if not isinstance(members, list):
            raise ValueError(f"Manifest category {category} must be a list")
        categories[str(category)] = {str(member) for member in members}
    return {
        "version": raw.get("version"),
        "detectors": detectors,
        "emitted_entities": emitted_entities,
        "all_emitted_entities": all_emitted_entities,
        "reserved_subtypes": reserved,
        "standalone_entities": standalone_entities,
        "categories": categories,
        "recall_floors": recall_floors,
        "specificity_floors": specificity_floors,
        "out_of_scope_pairs": out_of_scope_pairs,
        "foundation_floor_pairs": {
            (detector, entity)
            for detector, corpus, entity in recall_floors
            if corpus == "foundation"
        },
        "foundation_out_of_scope_pairs": {
            (detector, entity)
            for detector, corpus, entity in out_of_scope_pairs
            if corpus == "foundation"
        },
    }


def _load_manifest_floor_block(
    detector_id: str,
    detector: dict[str, Any],
    key: str,
    emitted: set[str],
    fixture_root: Path,
) -> dict[tuple[str, str, str], float]:
    block = detector.get(key, {})
    if block in (None, {}):
        return {}
    if not isinstance(block, dict):
        raise ValueError(f"Manifest detector {detector_id}.{key} must be a mapping")
    floors: dict[tuple[str, str, str], float] = {}
    for corpus, by_entity in block.items():
        corpus_id = str(corpus)
        if corpus_id != "foundation":
            raise ValueError(
                f"Manifest detector {detector_id}.{key} declares unsupported corpus {corpus_id!r}"
            )
        if not isinstance(by_entity, dict):
            raise ValueError(f"Manifest detector {detector_id}.{key}.{corpus_id} must be a mapping")
        for entity, raw_floor in by_entity.items():
            entity_name = str(entity)
            if entity_name not in emitted:
                raise ValueError(
                    f"Manifest detector {detector_id}.{key}.{corpus_id}.{entity_name} "
                    "is not listed in emits"
                )
            try:
                floor = float(raw_floor)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"Manifest detector {detector_id}.{key}.{corpus_id}.{entity_name} "
                    "must be numeric"
                ) from exc
            if floor < 0.0 or floor > 1.0:
                raise ValueError(
                    f"Manifest detector {detector_id}.{key}.{corpus_id}.{entity_name} "
                    "must be between 0.0 and 1.0"
                )
            if key == "recall_floor" and floor <= 0.0:
                raise ValueError(
                    f"Manifest detector {detector_id}.{key}.{corpus_id}.{entity_name} "
                    "must be greater than 0.0; use out_of_scope.foundation when the "
                    "engine does not target the entity"
                )
            _validate_manifest_floor_fixture(detector_id, corpus_id, entity_name, fixture_root, key)
            floors[(detector_id, corpus_id, entity_name)] = floor
    return floors


def _load_manifest_out_of_scope_block(
    detector_id: str,
    detector: dict[str, Any],
    emitted: set[str],
    fixture_root: Path,
) -> set[tuple[str, str, str]]:
    block = detector.get("out_of_scope", {})
    if block in (None, {}):
        return set()
    if not isinstance(block, dict):
        raise ValueError(f"Manifest detector {detector_id}.out_of_scope must be a mapping")
    pairs: set[tuple[str, str, str]] = set()
    for corpus, by_entity in block.items():
        corpus_id = str(corpus)
        if corpus_id != "foundation":
            raise ValueError(
                f"Manifest detector {detector_id}.out_of_scope declares unsupported corpus "
                f"{corpus_id!r}"
            )
        if not isinstance(by_entity, dict):
            raise ValueError(
                f"Manifest detector {detector_id}.out_of_scope.{corpus_id} must be a mapping"
            )
        for entity, marker in by_entity.items():
            entity_name = str(entity)
            if entity_name not in emitted:
                raise ValueError(
                    f"Manifest detector {detector_id}.out_of_scope.{corpus_id}.{entity_name} "
                    "is not listed in emits"
                )
            if marker is not True:
                raise ValueError(
                    f"Manifest detector {detector_id}.out_of_scope.{corpus_id}.{entity_name} "
                    "must be true"
                )
            _validate_manifest_floor_fixture(
                detector_id,
                corpus_id,
                entity_name,
                fixture_root,
                "out_of_scope",
            )
            pairs.add((detector_id, corpus_id, entity_name))
    return pairs


def _validate_manifest_floor_fixture(
    detector_id: str,
    corpus: str,
    entity: str,
    fixture_root: Path,
    key: str,
) -> None:
    fixture_path = fixture_root / detector_id / f"{entity}.json"
    if not fixture_path.exists():
        raise ValueError(
            f"Manifest detector {detector_id} declares {key}.{corpus}.{entity} "
            f"without fixture {fixture_path}"
        )


def _manifest_detector_family(detector_id: str) -> str:
    if detector_id.startswith("contextual-broad."):
        return "contextual-broad"
    if detector_id.startswith("contextual."):
        return "contextual-anchored"
    if detector_id.startswith("medical-regex."):
        return "medical-regex"
    if detector_id.startswith("openai_privacy_filter."):
        return "openai_privacy_filter"
    return detector_id.split(".", 1)[0]


def _rule_sort_key(rule: Rule) -> tuple[int, int, int, int, int]:
    return (
        rule.priority,
        _rule_action_class_rank(rule),
        1 if rule.scope == "surface" else 0,
        _rule_origin_rank(rule.id),
        rule.specificity(),
    )


def _rule_action_class_rank(rule: Rule) -> int:
    if rule.on_fail in ("block", "exception") or rule.action == "block":
        return 3
    if rule.on_fail == "observe":
        return 1
    return 2


def _rule_origin_rank(rule_id: str) -> int:
    pack_prefixes = (
        "healthcare.",
        "financial.",
        "enterprise-dlp.",
        "domain-healthcare-",
        "domain-financial-",
        "domain-enterprise-",
    )
    return 0 if rule_id.startswith(pack_prefixes) else 1


def _entity_in_scope(
    entity: str, entity_scope: set[str], categories: dict[str, set[str]]
) -> bool:
    if entity in entity_scope:
        return True
    return any(entity in categories.get(scope_item, set()) for scope_item in entity_scope)


def _scope_escalated(scope: str, _finding: Finding) -> bool:
    return scope == "surface"


def _default_allow_decision(finding: Finding) -> PolicyDecision:
    return PolicyDecision(
        finding=finding,
        action="allow",
        rule_id="default-allow",
        severity="info",
    )
