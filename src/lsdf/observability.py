# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from copy import deepcopy
from typing import Any

from .audit import build_audit_event
from .engine import (
    Firewall, InspectionResult, _decision_applies, _decisions_blocked,
    _raise_for_exception_decisions,
)
from .surfaces import Surface
from .transforms import apply_decisions, transform_scalar_value
from .types import Finding, PolicyDecision


def sanitize_observability(payload: Any, firewall: Firewall) -> InspectionResult:
    """Inspect an arbitrary trace/log payload as logs.traces."""

    surfaces = list(_observability_surfaces(payload))
    findings = _scan_surfaces(firewall, surfaces)
    decisions = [firewall.policy.decide(finding) for finding in findings]
    decisions = [decision for decision in decisions if decision.action != "allow"]
    _raise_for_exception_decisions(decisions)
    blocked = _decisions_blocked(firewall.policy.mode, decisions)
    token_replacer = firewall._vault_token_replacer if firewall.token_vault else None
    transformed = deepcopy(payload)
    applicable = [
        decision
        for decision in decisions
        if _decision_applies(decision, firewall.policy.mode)
    ]
    if applicable:
        root_decisions = [
            decision for decision in applicable if decision.finding.pointer == ()
        ]
        if root_decisions:
            transformed = transform_scalar_value(
                transformed, root_decisions, token_replacer=token_replacer,
            )
        else:
            transformed = apply_decisions(transformed, applicable, token_replacer=token_replacer)
    audit_event = build_audit_event(
        decisions=decisions,
        store_redacted_evidence=firewall.policy.audit.store_redacted_evidence,
        include_policy_decision=firewall.policy.audit.include_policy_decision,
        blocked=blocked,
    )
    return InspectionResult(
        blocked=blocked,
        transformed_payload=transformed,
        findings=findings,
        decisions=decisions,
        audit_event=audit_event,
    )


def _scan_surfaces(firewall: Firewall, surfaces: list[Surface]) -> list[Finding]:
    findings: list[Finding] = []
    for surface in surfaces:
        findings.extend(firewall.scanner.scan(surface))
    return findings


def _observability_surfaces(
    payload: Any,
    pointer: tuple[str | int, ...] = (),
) -> list[Surface]:
    if isinstance(payload, dict):
        surfaces: list[Surface] = []
        for key, value in payload.items():
            surfaces.extend(_observability_surfaces(value, (*pointer, key)))
        return surfaces
    if isinstance(payload, list):
        surfaces = []
        for idx, value in enumerate(payload):
            surfaces.extend(_observability_surfaces(value, (*pointer, idx)))
        return surfaces
    if isinstance(payload, str):
        return [Surface(name="logs.traces", pointer=pointer, value=payload)]
    if isinstance(payload, (int, float, bool)) and payload is not None:
        return [Surface(name="logs.traces", pointer=pointer, value=str(payload))]
    return []
