# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import os
import re
import subprocess
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from .scanners.contextual import ContextualAnchoredScanner, ContextualBroadScanner
from .scanners.entropy import EntropySecretScanner
from .scanners.gliner import GLiNERDetector
from .scanners.medical import MedicalPHIScanner
from .scanners.openai_privacy_filter import OpenAIPrivacyFilterDetector
from .scanners.presidio import PresidioDetector
from .scanners.regex import RegexScanner
from .scanners.xpia import XPIAScanner
from .surfaces import Surface
from .policy import (
    FOUNDATION_FIXTURE_ROOT,
    _manifest_detector_family,
    load_policy_profile,
    load_subtype_manifest,
    release_gated_profile_names,
)


FOUNDATION_CORPUS = "foundation"
DEFAULT_FIXTURE_ROOT = FOUNDATION_FIXTURE_ROOT
DEFAULT_OUTPUT_PATH = Path("docs/system-recall.md")
DEFAULT_HISTORY_PATH = Path("docs/system-recall-history.jsonl")
PACKAGE_ROOT = Path(__file__).resolve().parents[2]

DETECTOR_ID_MATCHERS = {
    "regex.api_key_family": {
        "regex.github_token",
        "regex.stripe_key",
        "regex.openai_api_key",
        "regex.anthropic_api_key",
        "regex.slack_token",
        "regex.google_api_key",
        "regex.gcp_oauth",
        "regex.twilio_sid",
        "regex.mailgun_key",
        "regex.sendgrid_key",
        "regex.npm_token",
        "regex.pypi_token",
        "regex.discord_bot_token",
        "regex.digitalocean_token",
        "regex.heroku_token",
        "regex.linode_token",
        "regex.square_token",
        "regex.braintree_token",
        "regex.atlassian_token",
        "regex.api_key",
    },
    "regex.aws_key": {
        "regex.aws_access_key",
        "regex.aws_secret_access_key",
        "regex.aws_session_token",
    },
    "regex.jwt": {"regex.jwt"},
    "regex.pem_private_key": {"regex.pem_private_key"},
    "regex.private_key": {"regex.gcp_service_account"},
    "regex.database_url": {"regex.db_connection_url"},
    "regex.bearer_token": {"regex.bearer_token"},
    "regex.azure_key": {"regex.azure_storage_key", "regex.azure_sas_token"},
    "regex.datadog_key": {"regex.datadog_key"},
    "regex.secret_assignment": {"regex.secret_assignment"},
    "regex.strong_identifier_family": {
        "regex.ssn",
        "regex.national_id_anchored",
        "regex.cpf",
    },
    "regex.financial_family": {
        "regex.bank_account_anchored",
        "regex.credit_card_luhn",
        "regex.iban",
    },
    "regex.contact_identity_family": {
        "regex.email",
        "regex.phone",
        "regex.brazil_phone",
        "regex.person_anchored",
        "regex.person_portuguese_context",
        "regex.address_anchored",
        "regex.brazil_address",
        "regex.address_postcode_shape",
        "regex.date_of_birth_anchored",
    },
    "regex.medical_identifier_family": {"regex.mrn"},
    "entropy.secret": {"entropy.secret"},
    "medical-regex.phi_pattern": {"medical-regex.phi_pattern"},
    "contextual.identity_document": ("contextual.identity_document.",),
    "contextual.secret_field": ("contextual.secret_field.",),
    "contextual.xml_identity": ("contextual.xml_",),
    "contextual-broad.generic_identity": {
        "contextual.person_field",
        "contextual.location_field",
        "contextual.date_time_field",
        "contextual.demographic_field",
        "contextual.blood_type_field",
    },
    "contextual-broad.output_shapes": {
        "contextual.url_shape",
        "contextual.ipv4_shape",
        "contextual.ipv6_shape",
        "contextual.geo_coordinate",
        "contextual.building_unit",
        "contextual.date_shape",
        "contextual.time_shape",
        "contextual.international_phone_shape",
        "contextual.strong_identifier_shape",
        "contextual.username_shape",
    },
    "gliner.pii_phi": ("gliner.",),
    "openai_privacy_filter.reference_model": ("openai_privacy_filter.",),
    "presidio.analyzer": ("presidio.",),
    "xpia.indirect_injection": {"xpia.indirect_injection"},
}


@dataclass(frozen=True)
class FoundationResult:
    detector: str
    corpus: str
    entity: str
    recall: float
    specificity: float
    tp: int
    fn: int
    fp: int
    tn: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "corpus": self.corpus,
            "entity": self.entity,
            "recall": self.recall,
            "specificity": self.specificity,
            "tp": self.tp,
            "fn": self.fn,
            "fp": self.fp,
            "tn": self.tn,
        }


def system_recall_report(
    *,
    fixture_root: Path = DEFAULT_FIXTURE_ROOT,
    generated_at: str | None = None,
    commit_sha: str | None = None,
    manifest: dict[str, Any] | None = None,
    profile_names: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or utc_timestamp()
    commit = commit_sha or current_commit_sha()
    loaded_manifest = manifest or load_subtype_manifest()
    rows = [row.as_dict() for row in evaluate_foundation_fixtures(fixture_root=fixture_root)]
    coverage = coverage_gaps_for_gated_profiles(
        manifest=loaded_manifest,
        profile_names=profile_names,
    )
    if coverage["count"]:
        warnings.warn(
            "FOUNDATION_COVERAGE_GAP_WARNING: "
            f"{coverage['count']} profile/entity pairs in gated profiles have "
            "no in-scope detector with a non-zero foundation floor",
            stacklevel=2,
        )
    return {
        "generated_at": timestamp,
        "commit_sha": commit,
        "results": rows,
        "floors": _manifest_floor_rows(loaded_manifest),
        "out_of_scope": _manifest_out_of_scope_rows(loaded_manifest),
        "coverage_gaps": coverage,
    }


def regenerate_system_recall(
    *,
    output_path: Path = DEFAULT_OUTPUT_PATH,
    history_path: Path = DEFAULT_HISTORY_PATH,
    fixture_root: Path = DEFAULT_FIXTURE_ROOT,
    generated_at: str | None = None,
    commit_sha: str | None = None,
) -> dict[str, Any]:
    report = system_recall_report(
        fixture_root=fixture_root,
        generated_at=generated_at,
        commit_sha=commit_sha,
    )
    markdown = format_system_recall_markdown(
        report["results"],
        generated_at=report["generated_at"],
        commit_sha=report["commit_sha"],
        floors=report["floors"],
        out_of_scope=report["out_of_scope"],
        coverage_gaps=report["coverage_gaps"],
    )
    _write_text_atomic(output_path, markdown)
    append_system_recall_history(
        report["results"],
        history_path=history_path,
        timestamp=report["generated_at"],
        commit_sha=report["commit_sha"],
    )
    return report


def format_system_recall_markdown(
    results: Iterable[FoundationResult | dict[str, Any]],
    *,
    generated_at: str | None = None,
    commit_sha: str | None = None,
    floors: Iterable[dict[str, Any]] | None = None,
    out_of_scope: Iterable[dict[str, Any]] | None = None,
    coverage_gaps: dict[str, Any] | None = None,
    include_full_matrix: bool = True,
    include_gaps: bool = True,
) -> str:
    timestamp = generated_at or utc_timestamp()
    commit = commit_sha or current_commit_sha()
    rows = _sorted_rows(_normalize_results(results))
    floor_lookup = _floor_lookup(floors or ())
    out_of_scope_lookup = _out_of_scope_lookup(out_of_scope or ())
    gaps = coverage_gaps or {"count": 0, "pairs": [], "active_pairs": []}
    active_pairs = {
        (pair["detector"], pair["entity"])
        for pair in gaps.get("active_pairs", [])
    }
    summary_rows = [
        row for row in rows
        if not active_pairs or (row["detector"], row["entity"]) in active_pairs
    ]

    lines = [
        "# LSDF System Recall",
        "",
        f"_Generated {timestamp}. Commit {commit}._",
        "",
        (
            "Foundation-layer detector recall and specificity against synthetic "
            "fixtures, independent of profile composition."
        ),
        "",
        (
            "Optional adapter rows use deterministic, capability-aware test "
            "providers in this foundation harness; they exercise entity mapping "
            "and shape recognition without downloading model weights."
        ),
        "",
        (
            f"Coverage gaps: {gaps['count']} profile/entity pairs in gated profiles "
            "have no in-scope detector with a non-zero foundation floor."
        ),
        (
            "Floor met? compares current metrics to the declared manifest floor; "
            "out-of-scope rows are engines that do not target the entity by design."
        ),
        "",
        "## Summary - active-profile detectors",
        "",
    ]
    lines.extend(_format_result_table(summary_rows, floor_lookup, out_of_scope_lookup))
    if include_full_matrix:
        lines.extend(
            [
                "",
                "## Full matrix",
                "",
            ]
        )
        lines.extend(_format_result_table(rows, floor_lookup, out_of_scope_lookup))
    if include_gaps:
        lines.extend(
            [
                "",
                "## Gaps - gated profile entities without an in-scope foundation floor",
                "",
            ]
        )
        lines.extend(_format_gap_table(gaps.get("pairs", [])))
    lines.append("")
    return "\n".join(lines)


def assert_foundation_floors(
    results: Iterable[FoundationResult | dict[str, Any]],
    *,
    manifest: dict[str, Any] | None = None,
) -> None:
    loaded_manifest = manifest or load_subtype_manifest()
    floors = _floor_lookup(_manifest_floor_rows(loaded_manifest))
    out_of_scope = _out_of_scope_lookup(_manifest_out_of_scope_rows(loaded_manifest))
    failures: list[str] = []
    for row in _normalize_results(results):
        key = (row["detector"], row["corpus"], row["entity"])
        if key in out_of_scope:
            continue
        floor = floors.get(key)
        if floor is None:
            failures.append(
                f"missing floor: {row['detector']} {row['corpus']} {row['entity']} "
                "has fixture results but no declared floor or out_of_scope marker"
            )
            continue
        if row["recall"] < floor["recall_floor"]:
            failures.append(
                f"{row['detector']} {row['entity']} recall "
                f"{row['recall']:.3f} < floor {floor['recall_floor']:.3f}"
            )
        if row["specificity"] < floor["specificity_floor"]:
            failures.append(
                f"{row['detector']} {row['entity']} specificity "
                f"{row['specificity']:.3f} < floor {floor['specificity_floor']:.3f}"
            )
    if failures:
        raise AssertionError("; ".join(failures))


def coverage_gaps_for_gated_profiles(
    *,
    manifest: dict[str, Any] | None = None,
    profile_names: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    loaded_manifest = manifest or load_subtype_manifest()
    names = profile_names or _release_gated_profile_names()
    recall_floors = {
        (detector, entity): float(floor)
        for (detector, corpus, entity), floor in loaded_manifest.get("recall_floors", {}).items()
        if corpus == FOUNDATION_CORPUS
    }
    out_of_scope_pairs = set(loaded_manifest.get("foundation_out_of_scope_pairs", set()))
    reached: dict[tuple[str, str], set[str]] = {}
    profile_entities: dict[tuple[str, str], set[str]] = {}
    covered: set[tuple[str, str]] = set()
    for profile_name in names:
        policy = load_policy_profile(profile_name)
        active_families = set(policy.detectors.enabled_families)
        scoped_entities = _profile_scoped_entities(policy.entities, policy.entity_categories)
        active_emitters: dict[str, set[str]] = {
            entity: set()
            for entity in scoped_entities
        }
        for detector, config in loaded_manifest["detectors"].items():
            detector_id = str(detector)
            if _manifest_detector_family(str(detector)) not in active_families:
                continue
            for entity in config.get("emits", []):
                entity_name = str(entity)
                if entity_name in scoped_entities:
                    active_emitters.setdefault(entity_name, set()).add(detector_id)
                    reached.setdefault((detector_id, entity_name), set()).add(profile_name)
                    if (
                        (detector_id, entity_name) not in out_of_scope_pairs
                        and recall_floors.get((detector_id, entity_name), 0.0) > 0.0
                    ):
                        covered.add((profile_name, entity_name))
        for entity_name, enabled_detectors in active_emitters.items():
            profile_entities[(profile_name, entity_name)] = enabled_detectors
    grouped_gaps: dict[str, dict[str, Any]] = {}
    for (profile_name, entity), enabled_detectors in sorted(profile_entities.items()):
        if (profile_name, entity) in covered:
            continue
        row = grouped_gaps.setdefault(
            entity,
            {
                "entity": entity,
                "profiles": [],
                "enabled_detectors": set(),
            },
        )
        row["profiles"].append(profile_name)
        row["enabled_detectors"].update(enabled_detectors)
    gap_pairs = [
        {
            "entity": entity,
            "profiles": sorted(row["profiles"]),
            "enabled_detectors": sorted(row["enabled_detectors"]),
        }
        for entity, row in sorted(grouped_gaps.items())
    ]
    active_pairs = [
        {
            "detector": detector,
            "entity": entity,
            "profiles": sorted(profiles),
        }
        for (detector, entity), profiles in sorted(reached.items())
    ]
    return {
        "available": True,
        "count": sum(len(row["profiles"]) for row in gap_pairs),
        "pairs": gap_pairs,
        "active_pairs": active_pairs,
    }


def _profile_scoped_entities(
    entities: set[str],
    categories: dict[str, set[str]],
) -> set[str]:
    scoped: set[str] = set()
    for entity in entities:
        if entity in categories:
            scoped.update(categories[entity])
        else:
            scoped.add(entity)
    return scoped


def append_system_recall_history(
    results: Iterable[FoundationResult | dict[str, Any]],
    *,
    history_path: Path = DEFAULT_HISTORY_PATH,
    timestamp: str | None = None,
    commit_sha: str | None = None,
) -> None:
    generated_at = timestamp or utc_timestamp()
    commit = commit_sha or current_commit_sha()
    history_path.parent.mkdir(parents=True, exist_ok=True)
    with history_path.open("a", encoding="utf-8") as handle:
        for row in _sorted_rows(_normalize_results(results)):
            record = {
                "timestamp": generated_at,
                "commit_sha": commit,
                "detector": row["detector"],
                "corpus": row["corpus"],
                "entity": row["entity"],
                "recall": row["recall"],
                "specificity": row["specificity"],
                "tp": row["tp"],
                "fn": row["fn"],
                "fp": row["fp"],
                "tn": row["tn"],
            }
            handle.write(json.dumps(record, separators=(",", ":")) + "\n")


def evaluate_foundation_fixtures(
    *,
    fixture_root: Path = DEFAULT_FIXTURE_ROOT,
) -> list[FoundationResult]:
    resolved_root = _resolve_fixture_root(fixture_root)
    results: list[FoundationResult] = []
    paths = _fixture_paths(resolved_root)
    if not paths:
        raise ValueError(f"no foundation fixtures found under {resolved_root}")
    for path in paths:
        fixture = _load_fixture(path)
        scanner = _scanner_for_fixture(fixture)
        results.append(_evaluate_fixture(scanner.scan, fixture))
    return results


def utc_timestamp() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def current_commit_sha() -> str:
    for name in ("LSDF_COMMIT_SHA", "GITHUB_SHA"):
        value = os.environ.get(name)
        if value:
            return value[:12]
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short=12", "HEAD"],
            capture_output=True,
            check=True,
            text=True,
        )
    except Exception:
        return "unknown"
    return result.stdout.strip() or "unknown"


def _resolve_fixture_root(root: Path) -> Path:
    if root.is_absolute():
        if root.exists():
            return root
        raise FileNotFoundError(f"foundation fixture root does not exist: {root}")
    candidates = (
        Path.cwd() / root,
        PACKAGE_ROOT / root,
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    searched = ", ".join(str(candidate) for candidate in candidates)
    raise FileNotFoundError(f"foundation fixture root does not exist: {root} (searched {searched})")


def _fixture_paths(root: Path) -> list[Path]:
    return sorted(root.glob("*/*.json"))


def _load_fixture(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        fixture = json.load(handle)
    for required in ("detector", "entity", "description", "cases"):
        if required not in fixture:
            raise ValueError(f"{path} missing required field {required!r}")
    return fixture


def _evaluate_fixture(
    scan: Callable[[Surface], list[Any]],
    fixture: dict[str, Any],
) -> FoundationResult:
    entity = fixture["entity"]
    tp = fn = fp = tn = 0
    for index, case in enumerate(fixture["cases"]):
        surface = Surface(
            name=case.get("surface", "output.content"),
            pointer=("foundation", fixture["detector"], entity, index),
            value=case["text"],
        )
        matched = any(
            finding.entity == entity
            and _detector_id_matches_fixture(finding.detector_id, fixture["detector"])
            for finding in scan(surface)
        )
        if case["role"] == "positive":
            if matched:
                tp += 1
            else:
                fn += 1
        else:
            if matched:
                fp += 1
            else:
                tn += 1
    return FoundationResult(
        detector=fixture["detector"],
        corpus=FOUNDATION_CORPUS,
        entity=entity,
        recall=_ratio(tp, tp + fn),
        specificity=_ratio(tn, tn + fp),
        tp=tp,
        fn=fn,
        fp=fp,
        tn=tn,
    )


def _scanner_for_fixture(fixture: dict[str, Any]):
    detector = fixture["detector"]
    if detector.startswith("regex."):
        return RegexScanner()
    if detector == "entropy.secret":
        return EntropySecretScanner()
    if detector == "medical-regex.phi_pattern":
        return MedicalPHIScanner()
    if detector.startswith("contextual-broad."):
        return ContextualBroadScanner()
    if detector.startswith("contextual."):
        return ContextualAnchoredScanner()
    if detector == "gliner.pii_phi":
        return GLiNERDetector(_FakeGlinerModel(_mock_spans_by_text(fixture, _gliner_label)))
    if detector == "openai_privacy_filter.reference_model":
        return OpenAIPrivacyFilterDetector(
            _FakePrivacyFilterProvider(
                _mock_spans_by_text(fixture, _privacy_filter_category)
            )
        )
    if detector == "presidio.analyzer":
        return PresidioDetector(
            _FakePresidioAnalyzer(_mock_spans_by_text(fixture, _presidio_entity_type))
        )
    if detector == "xpia.indirect_injection":
        return XPIAScanner()
    raise ValueError(f"no foundation scanner factory for {detector!r}")


def _detector_id_matches_fixture(detector_id: str, fixture_detector: str) -> bool:
    matcher = DETECTOR_ID_MATCHERS.get(fixture_detector)
    if matcher is None:
        raise ValueError(f"no detector-id matcher for {fixture_detector!r}")
    if isinstance(matcher, tuple):
        return detector_id.startswith(matcher)
    return detector_id in matcher


def _ratio(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return round(numerator / denominator, 6)


def _normalize_results(
    results: Iterable[FoundationResult | dict[str, Any]],
) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for row in results:
        data = row.as_dict() if hasattr(row, "as_dict") else dict(row)
        normalized.append(
            {
                "detector": str(data["detector"]),
                "corpus": str(data["corpus"]),
                "entity": str(data["entity"]),
                "recall": float(data["recall"]),
                "specificity": float(data["specificity"]),
                "tp": int(data["tp"]),
                "fn": int(data["fn"]),
                "fp": int(data["fp"]),
                "tn": int(data["tn"]),
            }
        )
    return normalized


def _sorted_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(rows, key=lambda row: (row["detector"], row["corpus"], row["entity"]))


def _format_result_table(
    rows: list[dict[str, Any]],
    floors: dict[tuple[str, str, str], dict[str, float]],
    out_of_scope: set[tuple[str, str, str]],
) -> list[str]:
    lines = [
        "| Detector | Entity | Corpus | Recall | Specificity | Floor met? | TP | FN | FP | TN |",
        "| --- | --- | --- | ---: | ---: | --- | ---: | ---: | ---: | ---: |",
    ]
    if not rows:
        lines.append("| _none_ | _none_ | _none_ | 0.000 | 0.000 | not declared | 0 | 0 | 0 | 0 |")
        return lines
    for row in rows:
        lines.append(
            f"| {_cell(row['detector'])} | {_cell(row['entity'])} | "
            f"{_cell(row['corpus'])} | {row['recall']:.3f} | "
            f"{row['specificity']:.3f} | {_floor_status(row, floors, out_of_scope)} | "
            f"{row['tp']} | {row['fn']} | "
            f"{row['fp']} | {row['tn']} |"
        )
    return lines


def _format_gap_table(gaps: Iterable[dict[str, Any]]) -> list[str]:
    rows = list(gaps)
    lines = [
        "| Entity | Reached via profile(s) | Enabled detector(s) |",
        "| --- | --- | --- |",
    ]
    if not rows:
        lines.append("| _none_ | _none_ | _none_ |")
        return lines
    for row in rows:
        enabled_detectors = row.get("enabled_detectors", [])
        detector_cell = ", ".join(enabled_detectors) if enabled_detectors else "_none_"
        lines.append(
            f"| {_cell(row['entity'])} | {_cell(', '.join(row['profiles']))} | "
            f"{_cell(detector_cell)} |"
        )
    return lines


def _floor_status(
    row: dict[str, Any],
    floors: dict[tuple[str, str, str], dict[str, float]],
    out_of_scope: set[tuple[str, str, str]],
) -> str:
    key = (row["detector"], row["corpus"], row["entity"])
    if key in out_of_scope:
        return "N/A - engine does not target"
    floor = floors.get(key)
    if floor is None:
        return "not declared"
    if row["recall"] >= floor["recall_floor"] and row["specificity"] >= floor["specificity_floor"]:
        return "yes"
    return "no"


def _floor_lookup(
    floors: Iterable[dict[str, Any]],
) -> dict[tuple[str, str, str], dict[str, float]]:
    return {
        (str(row["detector"]), str(row["corpus"]), str(row["entity"])): {
            "recall_floor": float(row["recall_floor"]),
            "specificity_floor": float(row["specificity_floor"]),
        }
        for row in floors
    }


def _out_of_scope_lookup(
    rows: Iterable[dict[str, Any]],
) -> set[tuple[str, str, str]]:
    return {
        (str(row["detector"]), str(row["corpus"]), str(row["entity"]))
        for row in rows
    }


def _manifest_floor_rows(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    recall = manifest.get("recall_floors", {})
    specificity = manifest.get("specificity_floors", {})
    rows = []
    for detector, corpus, entity in sorted(recall):
        rows.append(
            {
                "detector": detector,
                "corpus": corpus,
                "entity": entity,
                "recall_floor": float(recall[(detector, corpus, entity)]),
                "specificity_floor": float(specificity[(detector, corpus, entity)]),
            }
        )
    return rows


def _manifest_out_of_scope_rows(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "detector": detector,
            "corpus": corpus,
            "entity": entity,
            "out_of_scope": True,
        }
        for detector, corpus, entity in sorted(manifest.get("out_of_scope_pairs", set()))
    ]


def _release_gated_profile_names() -> tuple[str, ...]:
    return release_gated_profile_names()


def _cell(value: Any) -> str:
    return str(value).replace("|", "\\|")


def _write_text_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


class _FakeGlinerModel:
    def __init__(self, spans_by_text: dict[str, list[dict[str, Any]]]):
        self.spans_by_text = spans_by_text

    def predict_entities(self, text, labels, *, threshold):
        return [
            span
            for span in self.spans_by_text.get(text, [])
            if span["label"] in labels and span["score"] >= threshold
        ]


class _FakePrivacyFilterProvider:
    def __init__(self, spans_by_text: dict[str, list[dict[str, Any]]]):
        self.spans_by_text = spans_by_text

    def __call__(self, text: str):
        return self.spans_by_text.get(text, [])


class _FakePresidioAnalyzer:
    def __init__(self, spans_by_text: dict[str, list[dict[str, Any]]]):
        self.spans_by_text = spans_by_text

    def analyze(self, *, text, entities, language):
        return [
            span
            for span in self.spans_by_text.get(text, [])
            if not entities or span["entity_type"] in entities
        ]


def _mock_spans_by_text(
    fixture: dict[str, Any],
    label_for_entity: Callable[[str], str],
) -> dict[str, list[dict[str, Any]]]:
    entity = fixture["entity"]
    label = label_for_entity(entity)
    spans: dict[str, list[dict[str, Any]]] = {}
    for case in fixture["cases"]:
        bounds = _capability_span_bounds(entity, case["text"])
        if bounds is None:
            continue
        start, end = bounds
        spans[case["text"]] = [
            {
                "label": label,
                "entity": label,
                "entity_group": label,
                "entity_type": label,
                "category": label,
                "start": start,
                "end": end,
                "score": 0.99,
            }
        ]
    return spans


def _capability_span_bounds(entity: str, text: str) -> tuple[int, int] | None:
    pattern = _CAPABILITY_PATTERNS.get(entity)
    if pattern is None:
        return None
    match = pattern.search(text)
    if match is None:
        return None
    return match.start(), match.end()


_CAPABILITY_PATTERNS = {
    "ADDRESS": re.compile(
        r"\b\d{1,5}\s+[A-Z][A-Za-z]+\s+"
        r"(?:Lane|Street|St|Road|Rd|Avenue|Ave|Boulevard|Blvd|Drive|Dr)\b"
    ),
    "BANK_ACCOUNT": re.compile(r"(?<!\d)\d{8,17}(?!\d)"),
    "BLOOD_TYPE": re.compile(
        r"\b(?:A|B|AB|O)\s+(?:positive|negative)\b|\b(?:A|B|AB|O)[+-]\b",
        re.IGNORECASE,
    ),
    "CREDIT_CARD": re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"),
    "CUSTOMER_ID": re.compile(r"\bCUST-\d{4}\b"),
    "DATE_OF_BIRTH": re.compile(r"\b(?:19|20)\d{2}[-/]\d{2}[-/]\d{2}\b"),
    "DRIVER_LICENSE": re.compile(r"\bD\d{7}\b"),
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "EMPLOYEE_ID": re.compile(r"\bEMP-\d{4}\b"),
    "HEALTH_INSURANCE_ID": re.compile(r"\bHIX-\d{4}-[A-Z]+\b"),
    "IBAN": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"),
    "LICENSE_PLATE": re.compile(r"\b[A-Z]{3}-\d{4}\b"),
    "MEDICAL_CONDITION": re.compile(
        r"\b(?:seasonal asthma|asthma|diabetes|hypertension|migraine)\b",
        re.IGNORECASE,
    ),
    "MEDICATION": re.compile(
        r"\b(?:metformin|lisinopril|amoxicillin)(?:\s+\d+\s*mg)?\b",
        re.IGNORECASE,
    ),
    "MRN": re.compile(r"\bMRN-\d{5}\b"),
    "NATIONAL_ID": re.compile(r"\bNAT-\d{4}-[A-Z]{2}\b"),
    "OTHER_INTERNAL_ID": re.compile(r"\bINT-\d{4}\b"),
    "OTHER_PHI": re.compile(
        r"\b(?:clinic visit summary note|clinical note|medical license|procedure note)\b",
        re.IGNORECASE,
    ),
    "OTHER_SECRET": re.compile(
        r"\b(?:workspace-secret-[a-z]+|secret_[A-Za-z0-9_-]+|"
        r"[A-Za-z]+-secret-[A-Za-z0-9_-]+)\b",
        re.IGNORECASE,
    ),
    "PASSPORT": re.compile(r"\b[A-Z]\d{8}\b"),
    "PERSON": re.compile(r"\b[A-Z][a-z]+ [A-Z][a-z]+\b"),
    "PHONE": re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "STUDENT_ID": re.compile(r"\bSTU-\d{4}\b"),
    "TAX_ID": re.compile(r"\bTIN-\d{2}-\d{4}\b"),
    "USER_ID": re.compile(r"\buser-\d{4}\b", re.IGNORECASE),
    "US_SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
}


def _gliner_label(entity: str) -> str:
    return {
        "PERSON": "person",
        "ADDRESS": "address",
        "DATE_OF_BIRTH": "date of birth",
        "PHONE": "phone number",
        "EMAIL": "email",
        "US_SSN": "social security number",
        "NATIONAL_ID": "national id number",
        "TAX_ID": "tax identification number",
        "PASSPORT": "passport number",
        "DRIVER_LICENSE": "driver's license number",
        "STUDENT_ID": "student id",
        "EMPLOYEE_ID": "employee id",
        "CUSTOMER_ID": "customer id",
        "USER_ID": "user id",
        "LICENSE_PLATE": "license plate",
        "OTHER_INTERNAL_ID": "form id",
        "HEALTH_INSURANCE_ID": "health insurance id number",
        "MEDICAL_CONDITION": "medical condition",
        "MEDICATION": "medication",
        "BLOOD_TYPE": "blood type",
        "MRN": "medical record number",
        "BANK_ACCOUNT": "bank account number",
        "IBAN": "iban",
        "CREDIT_CARD": "credit card number",
    }[entity]


def _privacy_filter_category(entity: str) -> str:
    return {
        "BANK_ACCOUNT": "account_number",
        "ADDRESS": "private_address",
        "DATE_OF_BIRTH": "private_date",
        "EMAIL": "private_email",
        "PERSON": "private_person",
        "PHONE": "private_phone",
        "OTHER_SECRET": "secret",
    }[entity]


def _presidio_entity_type(entity: str) -> str:
    return {
        "CREDIT_CARD": "CREDIT_CARD",
        "EMAIL": "EMAIL_ADDRESS",
        "IBAN": "IBAN_CODE",
        "ADDRESS": "LOCATION",
        "OTHER_PHI": "MEDICAL_LICENSE",
        "PERSON": "PERSON",
        "PHONE": "PHONE_NUMBER",
        "BANK_ACCOUNT": "US_BANK_NUMBER",
        "US_SSN": "US_SSN",
    }[entity]
