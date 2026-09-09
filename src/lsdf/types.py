# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Finding:
    entity: str
    surface: str
    pointer: tuple[str | int, ...]
    start: int
    end: int
    value: str
    confidence: float
    json_pointer: tuple[str | int, ...] | None = None
    detector_id: str = "unknown"
    detector_family: str = "unknown"
    metadata: dict[str, Any] | None = None
    # Argument object member names use a static ordinal pointer in serialized
    # output so raw member names never cross an audit/API boundary.  Internal
    # transforms continue to use json_pointer.
    safe_json_pointer: tuple[str | int, ...] | None = None
    argument_key_metadata: bool = False

    def safe_dict(self) -> dict[str, Any]:
        data = {
            "entity": self.entity,
            "surface": self.surface,
            "pointer": list(self.pointer),
            "start": self.start,
            "end": self.end,
            "confidence": self.confidence,
            "detector_id": self.detector_id,
            "detector_family": self.detector_family,
            "metadata": _safe_metadata(self.metadata or {}),
            "value_preview": _preview(self.value),
        }
        pointer = (
            self.safe_json_pointer
            if self.safe_json_pointer is not None
            else self.json_pointer
        )
        if pointer is not None:
            data["json_pointer"] = list(pointer)
        return data


@dataclass(frozen=True)
class PolicyDecision:
    finding: Finding
    action: str
    rule_id: str
    severity: str
    on_fail: str | None = None
    scope: str = "span"
    scope_escalated: bool = False
    # Per-rule operator parameters (Presidio-parity vocabulary). None
    # for any operator that doesn't consume the parameter.
    replacement: str | None = None
    hash_algo: str | None = None
    encrypt_key_env: str | None = None

    def safe_dict(self) -> dict[str, Any]:
        data = {
            "finding": self.finding.safe_dict(),
            "action": self.action,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "scope": self.scope,
            "scope_escalated": self.scope_escalated,
        }
        if self.on_fail is not None:
            data["on_fail"] = self.on_fail
        # `replacement` is operator-controlled literal text — not a
        # detected sensitive value — so it's safe to surface verbatim
        # in audit/decision dicts. `hash_algo` and `encrypt_key_env`
        # are configuration metadata, also operator-controlled.
        if self.replacement is not None:
            data["replacement"] = self.replacement
        if self.hash_algo is not None:
            data["hash_algo"] = self.hash_algo
        if self.encrypt_key_env is not None:
            data["encrypt_key_env"] = self.encrypt_key_env
        return data


class PolicyEnforcementError(RuntimeError):
    """Raised when a rule with `on_fail: exception` fires.

    Operators choose `on_fail: exception` for rules where firing should halt
    the request loudly rather than silently transforming, observing, or
    blocking. The bundled `Firewall.inspect` raises this from inside the
    firewall pipeline so a wrapping gateway/proxy can map it to the
    appropriate upstream-facing error response.
    """

    def __init__(self, *, rule_id: str, entity: str, surface: str) -> None:
        super().__init__(
            f"Rule {rule_id!r} fired with on_fail=exception on entity={entity} "
            f"surface={surface}"
        )
        self.rule_id = rule_id
        self.entity = entity
        self.surface = surface


def _preview(value: str) -> str:
    return f"[REDACTED len={len(value)}]"


def _safe_metadata(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _safe_metadata(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_safe_metadata(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_safe_metadata(item) for item in value)
    if isinstance(value, str):
        return f"[REDACTED len={len(value)}]"
    return value
