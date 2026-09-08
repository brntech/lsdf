# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from .audit import build_audit_event
from .detectors import DetectorProviders, DetectorRegistry, build_detector_registry
from .policy import Policy
from .scanners.composite import Scanner
from .surfaces import Surface, extract_surfaces
from .transforms import apply_decisions
from .types import Finding, PolicyDecision, PolicyEnforcementError
from .vault import TokenVault


@dataclass(frozen=True)
class InspectionResult:
    blocked: bool
    transformed_payload: Any
    findings: list[Finding]
    decisions: list[PolicyDecision]
    audit_event: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "blocked": self.blocked,
            "transformed_payload": self.transformed_payload,
            "findings": [finding.safe_dict() for finding in self.findings],
            "decisions": [decision.safe_dict() for decision in self.decisions],
            "audit_event": self.audit_event,
        }


class Firewall:
    def __init__(
        self,
        policy: Policy,
        scanner: Scanner | None = None,
        detector_registry: DetectorRegistry | None = None,
        detector_providers: DetectorProviders | None = None,
        token_vault: TokenVault | None = None,
    ):
        self.policy = policy
        self.token_vault = token_vault
        self.scanner = scanner or detector_registry or build_detector_registry(
            policy.detectors.enabled_families,
            detector_providers=detector_providers,
            detector_settings=policy.detectors.family_settings,
        )

    def inspect(
        self,
        payload: Any,
        *,
        unknown_surface: str = "input.messages",
    ) -> InspectionResult:
        surfaces = extract_surfaces(payload, unknown_surface=unknown_surface)
        findings = self._scan_surfaces(surfaces)
        decisions = [self.policy.decide(finding) for finding in findings]
        decisions = [decision for decision in decisions if decision.action != "allow"]

        # `on_fail: exception` raises before any transform / blocked computation
        # so the operator gets a loud halt rather than a silently-mutated payload.
        for decision in decisions:
            if decision.on_fail == "exception":
                raise PolicyEnforcementError(
                    rule_id=decision.rule_id,
                    entity=decision.finding.entity,
                    surface=decision.finding.surface,
                )

        blocked = _decisions_blocked(self.policy.mode, decisions)
        transformed = deepcopy(payload)
        applicable = [
            decision
            for decision in decisions
            if _decision_applies(decision, self.policy.mode)
        ]
        if applicable:
            transformed = apply_decisions(
                transformed,
                applicable,
                token_replacer=self._vault_token_replacer if self.token_vault else None,
            )
        reask_hint = any(decision.on_fail == "reask" for decision in decisions)
        audit_event = build_audit_event(
            decisions=decisions,
            store_redacted_evidence=self.policy.audit.store_redacted_evidence,
            include_policy_decision=self.policy.audit.include_policy_decision,
            reask_hint=reask_hint,
            blocked=blocked,
        )
        return InspectionResult(
            blocked=blocked,
            transformed_payload=transformed,
            findings=findings,
            decisions=decisions,
            audit_event=audit_event,
        )

    def evaluate(
        self,
        cases: list[dict[str, Any]],
        *,
        reveal_sensitive_values: bool = False,
    ) -> dict[str, Any]:
        results = []
        summary = _new_summary()
        blocked = 0
        leaked_after = 0
        sensitive_values_leaked_before = 0
        sensitive_values_leaked_after = 0
        cases_with_sensitive_values_before = 0
        cases_with_sensitive_values_after = 0
        audit_raw_value_violations = 0
        cases_with_audit_raw_value_violations = 0
        known_gap_cases = 0
        known_gap_leaked_after = 0
        known_gap_would_fail = 0
        failed = 0
        for case in cases:
            try:
                result = self.inspect(case["payload"])
            except (ValueError, RuntimeError) as exc:
                # Per-case inspection errors (e.g. action=encrypt with
                # an unset key env var) must not crash the whole batch.
                # Mark the case failed with the error message so the
                # corpus-level summary surfaces the misconfiguration
                # without obscuring per-case results behind a traceback.
                failed += 1
                results.append(
                    {
                        "id": case.get("id"),
                        "passed": False,
                        "blocked": False,
                        "finding_count": 0,
                        "finding_entities": [],
                        "leaks_after": [],
                        "failures": [
                            {
                                "kind": "inspection_error",
                                "error": f"{type(exc).__name__}: {exc}",
                            }
                        ],
                        "would_failures": [],
                        "audit_raw_value_violations": 0,
                    }
                )
                continue
            known_gap = bool(case.get("known_gap"))
            known_gap_cases += int(known_gap)
            blocked += int(result.blocked)
            before_text = str(case["payload"])
            after_text = str(result.transformed_payload)
            sensitive_values = case.get("sensitive_values", case.get("expected_absent", []))
            before_leaks = [value for value in sensitive_values if value in before_text]
            after_sensitive_leaks = [value for value in sensitive_values if value in after_text]
            sensitive_values_leaked_before += len(before_leaks)
            sensitive_values_leaked_after += len(after_sensitive_leaks)
            cases_with_sensitive_values_before += int(bool(before_leaks))
            cases_with_sensitive_values_after += int(bool(after_sensitive_leaks))
            expected_absent = case.get("expected_absent", [])
            case_leaks = [value for value in expected_absent if value in after_text]
            leaked_after += int(bool(case_leaks))
            failures, audit_violations = _case_failures(
                case,
                result,
                case_leaks,
                reveal_sensitive_values=reveal_sensitive_values,
            )
            audit_raw_value_violations += len(audit_violations)
            cases_with_audit_raw_value_violations += int(bool(audit_violations))
            counted_failures = [] if known_gap else failures
            known_gap_leaked_after += int(known_gap and bool(case_leaks))
            known_gap_would_fail += int(known_gap and bool(failures))
            failed += int(bool(counted_failures))
            passed = not counted_failures
            case_result = {
                "id": case.get("id"),
                "passed": passed,
                "blocked": result.blocked,
                "finding_count": len(result.findings),
                "finding_entities": sorted({f.entity for f in result.findings}),
                "leaks_after": _display_values(case_leaks, reveal_sensitive_values),
                "failures": counted_failures,
                "would_failures": failures if known_gap and failures else [],
                "audit_raw_value_violations": len(audit_violations),
            }
            for key in ("category", "surface", "known_gap"):
                if key in case:
                    case_result[key] = case[key]
            if sensitive_values:
                case_result["sensitive_values_leaked_before"] = _display_values(
                    before_leaks, reveal_sensitive_values
                )
                case_result["sensitive_values_leaked_after"] = _display_values(
                    after_sensitive_leaks, reveal_sensitive_values
                )
                case_result["sensitive_values_leaked_before_count"] = len(before_leaks)
                case_result["sensitive_values_leaked_after_count"] = len(after_sensitive_leaks)
            results.append(case_result)
            _summarize_case(summary, case, result, passed, known_gap, after_sensitive_leaks)
        return {
            "case_count": len(cases),
            "passed": len(cases) - failed,
            "failed": failed,
            "blocked": blocked,
            "leaked_after": leaked_after,
            "known_gap_cases": known_gap_cases,
            "known_gap_leaked_after": known_gap_leaked_after,
            "known_gap_would_fail": known_gap_would_fail,
            "sensitive_values_leaked_before": sensitive_values_leaked_before,
            "sensitive_values_leaked_after": sensitive_values_leaked_after,
            "cases_with_sensitive_values_before": cases_with_sensitive_values_before,
            "cases_with_sensitive_values_after": cases_with_sensitive_values_after,
            "audit_raw_value_violations": audit_raw_value_violations,
            "cases_with_audit_raw_value_violations": cases_with_audit_raw_value_violations,
            "summary": summary,
            "results": results,
        }

    def _scan_surfaces(self, surfaces: list[Surface]) -> list[Finding]:
        findings: list[Finding] = []
        for surface in surfaces:
            findings.extend(self.scanner.scan(surface))
        return findings

    def _vault_token_replacer(self, decision: PolicyDecision) -> str:
        assert self.token_vault is not None
        finding = decision.finding
        return self.token_vault.tokenize(
            finding.value,
            entity=finding.entity,
            metadata={
                "surface": finding.surface,
                "pointer": list(finding.pointer),
                "detector_family": finding.detector_family,
                "detector_id": finding.detector_id,
            },
        )

    def detector_summary(self) -> dict[str, list[str]]:
        if hasattr(self.scanner, "summary"):
            return self.scanner.summary()
        return {"detector_ids": [], "detector_families": []}


def _decision_applies(decision: PolicyDecision, mode: str) -> bool:
    """Return True if a decision should be passed to apply_decisions.

    Per-rule `on_fail` overrides the policy-level mode:

      - observe — log-only; never apply the transform.
      - mask / reask / block — always apply, even in monitor mode (the rule
        has been explicitly opted into enforcement at the rule level).
        `block` also runs the action transform so the redacted/tokenised
        payload is captured in the audit trail and remains safe for any
        downstream surface that still receives it; the request-halt happens
        independently via the `blocked` flag.
      - exception — already raised earlier in inspect(); never reaches here.
      - None (default) — honour the policy-level mode.
    """

    if decision.on_fail == "observe":
        return False
    if decision.on_fail in ("mask", "reask", "block"):
        return True
    return mode in ("redact", "block")


def _decisions_blocked(mode: str, decisions: list[PolicyDecision]) -> bool:
    for decision in decisions:
        if decision.on_fail == "observe":
            continue
        if decision.on_fail in ("block", "exception"):
            return True
        if decision.action == "block":
            return mode in ("redact", "block")
        if mode == "block":
            return True
    return False


def _case_failures(
    case: dict[str, Any],
    result: InspectionResult,
    case_leaks: list[str],
    *,
    reveal_sensitive_values: bool,
) -> tuple[list[str], list[str]]:
    failures: list[str] = []
    if case_leaks:
        failures.append(
            "Sensitive values still present: "
            f"{_display_values(case_leaks, reveal_sensitive_values)}"
        )
    if "expected_blocked" in case and result.blocked != bool(case["expected_blocked"]):
        failures.append(f"Expected blocked={case['expected_blocked']} got {result.blocked}")
    if case.get("expected_unchanged") and result.transformed_payload != case["payload"]:
        failures.append("Expected transformed payload to remain unchanged")
    if case.get("expected_no_findings") and result.findings:
        failures.append(f"Expected no findings; got {len(result.findings)}")
    if case.get("expected_no_decisions") and result.decisions:
        failures.append(f"Expected no decisions; got {len(result.decisions)}")
    _expect_subset(
        failures,
        "entities",
        case.get("expected_entities"),
        {finding.entity for finding in result.findings},
    )
    _expect_subset(
        failures,
        "surfaces",
        case.get("expected_surfaces"),
        {finding.surface for finding in result.findings},
    )
    _expect_subset(
        failures,
        "actions",
        case.get("expected_actions"),
        {decision.action for decision in result.decisions},
    )
    _expect_subset(
        failures,
        "detector ids",
        case.get("expected_detector_ids"),
        {finding.detector_id for finding in result.findings},
    )
    _expect_subset(
        failures,
        "detector families",
        case.get("expected_detector_families"),
        {finding.detector_family for finding in result.findings},
    )
    for pointer in case.get("expected_valid_json_pointers", []):
        value = _get_pointer(result.transformed_payload, pointer)
        try:
            json.loads(value)
        except (TypeError, json.JSONDecodeError) as exc:
            failures.append(f"Pointer {pointer} is not valid JSON: {exc}")
    audit_text = str(result.audit_event)
    audit_violations = [value for value in _audit_forbidden_values(case) if value in audit_text]
    if audit_violations:
        failures.append(
            "Audit event contains forbidden raw values: "
            f"{_display_values(audit_violations, reveal_sensitive_values)}"
        )
    return failures, audit_violations


def _audit_forbidden_values(case: dict[str, Any]) -> list[str]:
    if case.get("allow_sensitive_values_in_audit"):
        return list(case.get("expected_audit_absent", []))
    values: list[str] = []
    for key in ("sensitive_values", "expected_audit_absent"):
        for value in case.get(key, []):
            if value not in values:
                values.append(value)
    return values


def _expect_subset(
    failures: list[str],
    name: str,
    expected: list[str] | None,
    actual: set[str],
) -> None:
    if not expected:
        return
    missing = sorted(set(expected) - actual)
    if missing:
        failures.append(f"Missing expected {name}: {missing}; actual={sorted(actual)}")


def _get_pointer(payload: Any, pointer: list[str | int]) -> Any:
    current = payload
    for part in pointer:
        current = current[part]
    return current


def _new_summary() -> dict[str, Any]:
    return {
        "by_category": {},
        "by_surface": {},
        "by_action": {},
        "by_entity": {},
        "by_detector_family": {},
    }


def _summarize_case(
    summary: dict[str, Any],
    case: dict[str, Any],
    result: InspectionResult,
    passed: bool,
    known_gap: bool,
    after_sensitive_leaks: list[str],
) -> None:
    category = str(case.get("category", "uncategorized"))
    surface = str(case.get("surface") or _first(case.get("expected_surfaces"), "unspecified"))
    _update_case_bucket(summary["by_category"], category, passed, known_gap, after_sensitive_leaks)
    _update_case_bucket(summary["by_surface"], surface, passed, known_gap, after_sensitive_leaks)
    for decision in result.decisions:
        _increment(summary["by_action"], decision.action)
    for finding in result.findings:
        _increment(summary["by_entity"], finding.entity)
        _increment(summary["by_detector_family"], finding.detector_family)


def _update_case_bucket(
    buckets: dict[str, dict[str, int]],
    key: str,
    passed: bool,
    known_gap: bool,
    after_sensitive_leaks: list[str],
) -> None:
    bucket = buckets.setdefault(
        key,
        {
            "cases": 0,
            "passed": 0,
            "failed": 0,
            "known_gap": 0,
            "cases_with_sensitive_values_after": 0,
            "sensitive_values_leaked_after": 0,
        },
    )
    bucket["cases"] += 1
    bucket["passed"] += int(passed)
    bucket["failed"] += int(not passed)
    bucket["known_gap"] += int(known_gap)
    bucket["cases_with_sensitive_values_after"] += int(bool(after_sensitive_leaks))
    bucket["sensitive_values_leaked_after"] += len(after_sensitive_leaks)


def _increment(bucket: dict[str, int], key: str) -> None:
    bucket[key] = bucket.get(key, 0) + 1


def _first(values: Any, default: str) -> str:
    if isinstance(values, list) and values:
        return str(values[0])
    return default


def _display_values(values: list[str], reveal_sensitive_values: bool) -> list[str]:
    if reveal_sensitive_values:
        return list(values)
    return [_redacted_value(value) for value in values]


def _redacted_value(value: str) -> str:
    return f"[REDACTED len={len(value)}]"
