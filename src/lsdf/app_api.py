# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from pathlib import Path
from typing import Any

from .engine import Firewall, InspectionResult
from .observability import sanitize_observability
from .policy import load_effective_policy, load_policy
from .ux import simulate_policy


def build_firewall(
    *,
    policy_path: str | Path | None = None,
    profile: str = "default",
    domain_packs: list[str] | tuple[str, ...] | None = None,
) -> Firewall:
    policy = load_policy(policy_path) if policy_path else load_effective_policy(profile, domain_packs=domain_packs)
    return Firewall(policy)


def inspect_openai_request(payload: Any, firewall: Firewall | None = None) -> InspectionResult:
    return (firewall or build_firewall()).inspect(payload, unknown_surface="input.messages")


def inspect_openai_response(payload: Any, firewall: Firewall | None = None) -> InspectionResult:
    return (firewall or build_firewall()).inspect(payload, unknown_surface="output.content")


def sanitize_trace_payload(payload: Any, firewall: Firewall | None = None) -> InspectionResult:
    return sanitize_observability(payload, firewall or build_firewall())


def summarize_decisions(result: InspectionResult) -> dict[str, Any]:
    return {
        "blocked": result.blocked,
        "finding_count": len(result.findings),
        "decision_count": len(result.decisions),
        "actions": sorted({decision.action for decision in result.decisions}),
        "entities": sorted({finding.entity for finding in result.findings}),
        "surfaces": sorted({finding.surface for finding in result.findings}),
        "detector_families": sorted({finding.detector_family for finding in result.findings}),
    }


def simulate_policy_fixtures(
    fixture_paths: list[str | Path],
    *,
    policy_path: str | Path | None = None,
    profile: str = "default",
    domain_packs: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    return simulate_policy(
        [Path(path) for path in fixture_paths],
        policy_path=Path(policy_path) if policy_path else None,
        profile=profile,
        domain_packs=domain_packs,
    )
