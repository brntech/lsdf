# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import json
import os
from collections import defaultdict
from typing import Any, Callable

from .types import PolicyDecision


TokenReplacer = Callable[[PolicyDecision], str]


# Actions that produce a replacement payload for the matched span. The
# `block` action lives in this set so a halted payload still has the
# raw value redacted on the way to a downstream tracer/logger (see
# the on_fail=block semantics in policy-cookbook.md).
TRANSFORMING_ACTIONS = frozenset(
    {"redact", "mask", "tokenize", "block", "replace", "hash", "encrypt"}
)


def apply_decisions(
    payload: Any,
    decisions: list[PolicyDecision],
    *,
    token_replacer: TokenReplacer | None = None,
) -> Any:
    by_pointer: dict[
        tuple[tuple[str | int, ...], tuple[str | int, ...] | None],
        list[PolicyDecision],
    ] = defaultdict(list)
    for decision in decisions:
        if decision.action in TRANSFORMING_ACTIONS:
            by_pointer[(decision.finding.pointer, decision.finding.json_pointer)].append(decision)
    for (pointer, json_pointer), pointer_decisions in by_pointer.items():
        value = _get(payload, pointer)
        if json_pointer is not None:
            payload = _apply_json_string_decisions(
                payload, pointer, json_pointer, pointer_decisions, token_replacer=token_replacer
            )
        elif isinstance(value, str):
            transformed = _replace_spans(value, pointer_decisions, token_replacer=token_replacer)
            payload = _set(payload, pointer, transformed)
        elif _is_scalar_leaf(value):
            transformed = transform_scalar_value(value, pointer_decisions, token_replacer=token_replacer)
            payload = _set(payload, pointer, transformed)
    return payload


def transform_scalar_value(
    value: Any,
    decisions: list[PolicyDecision],
    *,
    token_replacer: TokenReplacer | None = None,
) -> str:
    return _replace_spans(str(value), decisions, token_replacer=token_replacer)


def _apply_json_string_decisions(
    payload: Any,
    pointer: tuple[str | int, ...],
    json_pointer: tuple[str | int, ...],
    decisions: list[PolicyDecision],
    *,
    token_replacer: TokenReplacer | None = None,
) -> Any:
    raw_value = _get(payload, pointer)
    if not isinstance(raw_value, str):
        return payload
    try:
        parsed = json.loads(raw_value)
    except json.JSONDecodeError:
        return payload
    leaf_value = _get(parsed, json_pointer)
    if not isinstance(leaf_value, str):
        leaf_value = str(leaf_value)
    transformed = _replace_spans(leaf_value, decisions, token_replacer=token_replacer)
    if json_pointer:
        _set(parsed, json_pointer, transformed)
    else:
        parsed = transformed
    return _set(payload, pointer, json.dumps(parsed, separators=(",", ":")))


def _replace_spans(
    value: str,
    decisions: list[PolicyDecision],
    *,
    token_replacer: TokenReplacer | None = None,
) -> str:
    surface_decision = _select_surface_decision(decisions)
    if surface_decision is not None:
        return _replacement(surface_decision, token_replacer=token_replacer)
    output = value
    for decision in sorted(
        _select_non_overlapping(decisions),
        key=lambda item: item.finding.start,
        reverse=True,
    ):
        finding = decision.finding
        replacement = _replacement(decision, token_replacer=token_replacer)
        output = output[: finding.start] + replacement + output[finding.end :]
    return output


def _select_surface_decision(decisions: list[PolicyDecision]) -> PolicyDecision | None:
    surface_decisions = [decision for decision in decisions if decision.scope == "surface"]
    if not surface_decisions:
        return None
    return sorted(surface_decisions, key=_surface_decision_rank)[0]


def _surface_decision_rank(decision: PolicyDecision) -> tuple[int, int, int, int]:
    action_rank = {
        "block": 0,
        "redact": 1,
        "mask": 1,
        "tokenize": 1,
        "replace": 1,
        "hash": 1,
        "encrypt": 1,
    }.get(decision.action, 2)
    finding = decision.finding
    return (
        -_entity_priority(finding.entity),
        action_rank,
        finding.start,
        -(finding.end - finding.start),
    )


def _select_non_overlapping(decisions: list[PolicyDecision]) -> list[PolicyDecision]:
    selected: list[PolicyDecision] = []
    occupied: list[tuple[int, int]] = []
    for decision in sorted(decisions, key=_decision_rank):
        start = decision.finding.start
        end = decision.finding.end
        if any(start < used_end and end > used_start for used_start, used_end in occupied):
            continue
        selected.append(decision)
        occupied.append((start, end))
    return selected


def _decision_rank(decision: PolicyDecision) -> tuple[int, int, int]:
    finding = decision.finding
    return (
        finding.start,
        -_entity_priority(finding.entity),
        -(finding.end - finding.start),
    )


def _entity_priority(entity: str) -> int:
    return {
        "AWS_KEY": 100,
        "API_KEY": 100,
        "AZURE_KEY": 100,
        "DATADOG_KEY": 100,
        "JWT": 100,
        "BEARER_TOKEN": 100,
        "DATABASE_URL": 100,
        "PEM_BLOCK": 100,
        "PRIVATE_KEY": 100,
        "PASSWORD": 95,
        "OTHER_SECRET": 90,
        "US_SSN": 80,
        "PASSPORT": 80,
        "DRIVER_LICENSE": 80,
        "NATIONAL_ID": 80,
        "TAX_ID": 80,
        "BR_CPF": 80,
        "OTHER_STRONG_ID": 80,
        "CREDIT_CARD": 80,
        "MRN": 80,
        "HEALTH_INSURANCE_ID": 80,
        "ICD_CODE": 75,
        "LAB_VALUE": 75,
        "MEDICATION": 75,
        "MEDICAL_CONDITION": 75,
        "DIAGNOSIS_TEXT": 75,
        "OTHER_PHI": 70,
    }.get(entity, 50)


def _replacement(decision: PolicyDecision, *, token_replacer: TokenReplacer | None = None) -> str:
    entity = decision.finding.entity
    action = decision.action
    if action == "mask":
        return _mask(decision.finding.value)
    if action == "tokenize":
        if token_replacer is not None:
            return token_replacer(decision)
        return f"<{entity}:TOKEN>"
    if action == "replace":
        # `replacement` is operator-supplied literal text validated at
        # policy load. Pass through verbatim so operators can produce
        # Presidio-style domain-specific placeholders ("[CUSTOMER]",
        # "<<EMAIL>>", etc.) without LSDF re-formatting them.
        return decision.replacement or f"<{entity}:REPLACED>"
    if action == "hash":
        return _hash_replacement(decision)
    if action == "encrypt":
        return _encrypt_replacement(decision)
    return f"<{entity}:REDACTED>"


def _mask(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"


def _hash_replacement(decision: PolicyDecision) -> str:
    algo = decision.hash_algo or "sha256"
    digest = hashlib.new(algo, decision.finding.value.encode("utf-8")).hexdigest()
    # Truncate to 16 hex chars (64 bits) for in-line readability —
    # full collisions are still ~2^-64 unlikely for the sensitive-value
    # cardinality LSDF sees in practice. Operators who need full-length
    # digests can wrap LSDF and post-process the audit event, where the
    # full algorithm and digest length are spelled out in the decision
    # metadata.
    return f"<{decision.finding.entity}:HASH:{algo}={digest[:16]}>"


def _encrypt_replacement(decision: PolicyDecision) -> str:
    # Lazy-import cryptography.fernet because the cryptography package
    # is already a hard dep (vault), but keeping it lazy avoids paying
    # the import cost on the hot path of fully-configured policies that
    # never use the encrypt operator.
    from cryptography.fernet import Fernet, InvalidToken  # noqa: F401

    env_var = decision.encrypt_key_env
    if not env_var:
        raise ValueError(
            f"Rule {decision.rule_id!r} action=encrypt is missing encrypt_key_env. "
            "Validate at policy load."
        )
    key = os.environ.get(env_var)
    if not key:
        raise ValueError(
            f"Rule {decision.rule_id!r} action=encrypt requires env var "
            f"{env_var!r} to be set with a urlsafe-base64 32-byte Fernet key."
        )
    try:
        cipher = Fernet(key.encode("utf-8") if isinstance(key, str) else key)
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"Rule {decision.rule_id!r} action=encrypt: env var {env_var!r} "
            f"does not hold a valid Fernet key: {exc}"
        ) from exc
    token = cipher.encrypt(decision.finding.value.encode("utf-8")).decode("ascii")
    return f"<{decision.finding.entity}:ENC:{token}>"


def _get(payload: Any, pointer: tuple[str | int, ...]) -> Any:
    current = payload
    for part in pointer:
        current = current[part]
    return current


def _set(payload: Any, pointer: tuple[str | int, ...], value: Any) -> Any:
    if not pointer:
        return value
    current = payload
    for part in pointer[:-1]:
        current = current[part]
    current[pointer[-1]] = value
    return payload


def _is_scalar_leaf(value: Any) -> bool:
    return isinstance(value, (int, float, bool)) and value is not None
