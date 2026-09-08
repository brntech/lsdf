# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from typing import Any

from .types import Finding, PolicyDecision


class JsonlAuditSink:
    def __init__(
        self,
        path: str | Path,
        *,
        rotate_bytes: int | None = None,
        rotate_backups: int = 3,
    ):
        self.path = Path(path)
        self.rotate_bytes = rotate_bytes
        self.rotate_backups = max(1, rotate_backups)
        self._write_lock = Lock()

    def write(self, event: dict[str, Any]) -> None:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **event,
        }
        line = json.dumps(payload, separators=(",", ":")) + "\n"
        # Coordinates threads sharing this sink; other writers need coordination.
        with self._write_lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._rotate_if_needed()
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line)

    def _rotate_if_needed(self) -> None:
        if not self.rotate_bytes or self.rotate_bytes <= 0 or not self.path.exists():
            return
        if self.path.stat().st_size < self.rotate_bytes:
            return
        for index in range(self.rotate_backups - 1, 0, -1):
            src = self.path.with_suffix(self.path.suffix + f".{index}")
            dst = self.path.with_suffix(self.path.suffix + f".{index + 1}")
            if src.exists():
                if dst.exists():
                    dst.unlink()
                src.replace(dst)
        first = self.path.with_suffix(self.path.suffix + ".1")
        if first.exists():
            first.unlink()
        self.path.replace(first)


def build_audit_event(
    *,
    decisions: list[PolicyDecision],
    store_redacted_evidence: bool = True,
    include_policy_decision: bool = True,
    reask_hint: bool = False,
    blocked: bool | None = None,
) -> dict[str, Any]:
    """Build an audit event without raw sensitive values.

    `blocked` is the canonical request-was-halted signal. Callers that have
    already computed it (notably `Firewall.inspect`, which factors in
    `on_fail` overrides + policy mode) should pass it explicitly so the
    audit trail and `InspectionResult.blocked` cannot drift apart. When
    omitted, the field falls back to the action-only heuristic — correct
    only for callers that do not consume `on_fail`.
    """

    if blocked is None:
        blocked = any(decision.action == "block" for decision in decisions)
    event: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "decision_count": len(decisions),
        "blocked": blocked,
        "decisions": [
            _decision_audit(decision, store_redacted_evidence, include_policy_decision)
            for decision in decisions
        ],
    }
    if reask_hint:
        event["reask_hint"] = True
    return event


def _decision_audit(
    decision: PolicyDecision,
    store_redacted_evidence: bool,
    include_policy_decision: bool,
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "finding": _finding_audit(decision.finding, store_redacted_evidence)
    }
    if include_policy_decision:
        data.update(
            {
                "action": decision.action,
                "rule_id": decision.rule_id,
                "severity": decision.severity,
                "scope": decision.scope,
                "scope_escalated": decision.scope_escalated,
            }
        )
    else:
        data.update(
            {
                "scope": decision.scope,
                "scope_escalated": decision.scope_escalated,
            }
        )
    return data


def _finding_audit(finding: Finding, store_redacted_evidence: bool) -> dict[str, Any]:
    data = finding.safe_dict()
    data.pop("value_preview", None)
    if store_redacted_evidence:
        data["evidence"] = _redacted_evidence(finding.value)
    return data


def _redacted_evidence(value: str) -> str:
    return f"[REDACTED len={len(value)}]"


def purge_rotated_audit_files(
    path: str | Path,
    *,
    older_than_days: int,
    now: datetime | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Delete rotated audit backups older than ``older_than_days``.

    Operates only on rotated backups — files matching ``<path>.<int>``
    where ``<int>`` is the rotation index produced by `JsonlAuditSink`.
    The live audit file at ``path`` is never touched, even if it is older
    than the cutoff. Append-only audit semantics depend on the live file
    surviving across retention sweeps.

    Time comparison uses each file's mtime. The function is raw-value-safe:
    it never reads file contents, so no audit-line data crosses any
    boundary that this function controls.

    Returns a structured report with ``deleted`` / ``kept`` / ``errors``
    lists. Each list entry is a dict with ``path`` plus, where applicable,
    ``mtime`` (ISO-8601) or ``error`` (string). ``errors`` collects per-file
    OSError messages without aborting the sweep, so a single permission
    issue on one rotated file does not block deletion of older ones.

    With ``dry_run=True`` the function classifies files into ``deleted``
    versus ``kept`` exactly as it would in a real sweep but never calls
    ``unlink`` — useful for previewing a retention policy before scheduling
    it in cron. The ``dry_run`` flag is also reflected in the returned
    report so callers can distinguish a preview from a real sweep without
    re-deriving from invocation context.
    """

    if older_than_days < 0:
        raise ValueError("older_than_days must be >= 0")
    target = Path(path)
    if now is None:
        now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=older_than_days)

    report: dict[str, Any] = {
        "live_path": str(target),
        "older_than_days": older_than_days,
        "cutoff": cutoff.isoformat(),
        "dry_run": bool(dry_run),
        "deleted": [],
        "kept": [],
        "errors": [],
    }
    if not target.parent.exists():
        return report

    prefix = target.name + "."
    for candidate in sorted(target.parent.iterdir()):
        if not candidate.name.startswith(prefix):
            continue
        suffix = candidate.name[len(prefix):]
        if not suffix.isascii() or not suffix.isdigit():
            continue
        try:
            mtime = datetime.fromtimestamp(
                candidate.stat().st_mtime, tz=timezone.utc
            )
        except OSError as exc:
            report["errors"].append({"path": str(candidate), "error": str(exc)})
            continue
        if mtime < cutoff:
            if not dry_run:
                try:
                    candidate.unlink()
                except OSError as exc:
                    report["errors"].append(
                        {"path": str(candidate), "error": str(exc)}
                    )
                    continue
            report["deleted"].append(
                {"path": str(candidate), "mtime": mtime.isoformat()}
            )
        else:
            report["kept"].append(
                {"path": str(candidate), "mtime": mtime.isoformat()}
            )
    return report
