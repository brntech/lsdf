# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .detectors import (
    DetectorProviders,
    DetectorUnavailableError,
    build_detector_registry,
)
from .engine import Firewall
from .policy import Policy

DEFAULT_DETECTOR_SETS = (
    ("regex", ("regex",)),
    ("regex_entropy", ("regex", "entropy")),
    ("default", ("regex", "entropy", "medical-regex", "contextual-anchored")),
)


@dataclass(frozen=True)
class DetectorSet:
    name: str
    families: tuple[str, ...]


def compare_detector_sets(
    *,
    policy: Policy,
    dataset: dict[str, Any],
    dataset_path: Path,
    detector_sets: list[DetectorSet] | None = None,
    detector_providers: DetectorProviders | None = None,
    reveal_sensitive_values: bool = False,
) -> dict[str, Any]:
    sets = detector_sets or default_detector_sets()
    results = [
        _evaluate_detector_set(
            policy=policy,
            cases=dataset["cases"],
            detector_set=detector_set,
            detector_providers=detector_providers,
            reveal_sensitive_values=reveal_sensitive_values,
        )
        for detector_set in sets
    ]
    return {
        "dataset": dataset.get("name", dataset_path.name),
        "dataset_path": str(dataset_path),
        "profile": policy.name,
        "mode": policy.mode,
        "case_count": len(dataset["cases"]),
        "detector_sets": results,
    }


def default_detector_sets() -> list[DetectorSet]:
    return [DetectorSet(name, families) for name, families in DEFAULT_DETECTOR_SETS]


def parse_detector_set(value: str) -> DetectorSet:
    if "=" not in value:
        raise ValueError("Detector set must use NAME=family,family syntax")
    name, families_raw = value.split("=", 1)
    name = name.strip()
    families = tuple(family.strip() for family in families_raw.split(",") if family.strip())
    if not name:
        raise ValueError("Detector set name cannot be empty")
    if not families:
        raise ValueError(f"Detector set '{name}' must include at least one detector family")
    return DetectorSet(name=name, families=families)


def _evaluate_detector_set(
    *,
    policy: Policy,
    cases: list[dict[str, Any]],
    detector_set: DetectorSet,
    detector_providers: DetectorProviders | None,
    reveal_sensitive_values: bool,
) -> dict[str, Any]:
    base = {
        "name": detector_set.name,
        "families": list(detector_set.families),
    }
    try:
        registry = build_detector_registry(
            detector_set.families,
            detector_providers=detector_providers,
        )
    except (DetectorUnavailableError, ValueError) as exc:
        return {
            **base,
            "status": "unavailable",
            "reason": str(exc),
        }
    firewall = Firewall(policy, detector_registry=registry)
    report = firewall.evaluate(cases, reveal_sensitive_values=reveal_sensitive_values)
    summary = firewall.detector_summary()
    return {
        **base,
        "status": "ok",
        "detector_ids": summary["detector_ids"],
        "detector_families": summary["detector_families"],
        "passed": report["passed"],
        "failed": report["failed"],
        "blocked": report["blocked"],
        "leaked_after": report["leaked_after"],
        "known_gap_cases": report["known_gap_cases"],
        "known_gap_leaked_after": report["known_gap_leaked_after"],
        "known_gap_would_fail": report["known_gap_would_fail"],
        "sensitive_values_leaked_before": report["sensitive_values_leaked_before"],
        "sensitive_values_leaked_after": report["sensitive_values_leaked_after"],
        "cases_with_sensitive_values_after": report["cases_with_sensitive_values_after"],
        "audit_raw_value_violations": report["audit_raw_value_violations"],
        "cases_with_audit_raw_value_violations": report[
            "cases_with_audit_raw_value_violations"
        ],
        "summary": report["summary"],
        "results": report["results"],
    }
