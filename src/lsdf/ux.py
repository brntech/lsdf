# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import math
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .detectors import DetectorUnavailableError, OPTIONAL_DETECTOR_FAMILIES
from .engine import Firewall, InspectionResult
from .gateway import (
    DEFAULT_CLIENT_TIMEOUT_SECONDS,
    DEFAULT_MAX_CONCURRENT_REQUESTS,
    DEFAULT_MAX_REQUEST_BYTES,
    DEFAULT_MAX_STREAM_SECONDS,
    DEFAULT_UPSTREAM_TIMEOUT_SECONDS,
    GatewayConfigError,
    resolve_gateway_config,
)
from .metrics import (
    format_metrics_summary_markdown,
    format_metrics_summary_text,
    summarize_metrics_jsonl,
)
from .observability import sanitize_observability
from .policy import DOMAIN_PACKS, POLICY_PROFILES, Policy, load_effective_policy, load_policy, load_policy_profile
from .reporting import format_eval_report_markdown
from .security_ops import diff_policy_files, format_policy_diff_markdown

DEFAULT_PROTECTION_DATASETS = (
    Path("evals/safety_matrix.json"),
    Path("evals/utility_matrix.json"),
    Path("evals/observability_matrix.json"),
)

UPSTREAM_PRESETS = {
    "demo": "http://demo-upstream:8091",
    "vllm": "http://host.docker.internal:8000",
    "litellm": "http://host.docker.internal:4000",
    "lmstudio": "http://host.docker.internal:1234",
    "ollama": "http://host.docker.internal:11434/v1",
    "openrouter": "https://openrouter.ai/api/v1",
}

_SMOKE_TIMEOUT_SECONDS = 5.0
_SMOKE_MAX_RESPONSE_BYTES = 256 * 1024
_SAFE_HEALTH_STATUSES = frozenset({"ok", "degraded", "warning", "error"})
_SAFE_UPSTREAM_STATUSES = frozenset({"ok", "warning", "error"})
_HEALTH_LIMIT_KEYS = (
    "max_request_bytes",
    "max_concurrent_requests",
    "client_timeout_seconds",
    "upstream_timeout_seconds",
    "max_stream_seconds",
    "stream_holdback_chars",
)

DEMO_SECRET = "api_LSDF_FIXTURE_TOKEN_000000"
DEMO_MRN = "LSDF-FIXTURE-00001"
DEMO_SSN = "000-00-0000"


def doctor_report(
    *,
    policy_path: Path | None = None,
    profile: str | None = None,
    domain_packs: list[str] | tuple[str, ...] | None = None,
    upstream_base_url: str | None = None,
    audit_jsonl_path: Path | None = None,
    metrics_jsonl_path: Path | None = None,
    vault_path: Path | None = None,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    errors: list[str] = []
    warnings: list[str] = []
    policy: Policy | None = None

    try:
        policy = _load_policy_for_ux(policy_path, profile, domain_packs=domain_packs)
        checks.append(
            {
                "name": "policy",
                "status": "ok",
                "profile": policy.name,
                "mode": policy.mode,
                "rule_count": len(policy.rules),
            }
        )
    except Exception as exc:
        del exc
        message = "Policy load failed: policy_load_error"
        errors.append(message)
        checks.append({"name": "policy", "status": "error", "message": "policy_load_error"})

    if policy is not None:
        try:
            detector_summary = Firewall(policy).detector_summary()
            checks.append(
                {
                    "name": "detectors",
                    "status": "ok",
                    "families": detector_summary["detector_families"],
                    "detector_ids": detector_summary["detector_ids"],
                }
            )
            optional_enabled = [
                family
                for family in policy.detectors.enabled_families
                if family in OPTIONAL_DETECTOR_FAMILIES
            ]
            if optional_enabled:
                warnings.append(
                    "Optional detector families are enabled; keep their dependencies in "
                    f"the Docker optional profile: {', '.join(optional_enabled)}"
                )
        except DetectorUnavailableError as exc:
            del exc
            families = ",".join(sorted(policy.detectors.enabled_families))
            message = f"Detector unavailable: detector_unavailable ({families})"
            errors.append(message)
            checks.append({"name": "detectors", "status": "error", "message": message})
        except Exception as exc:
            del exc
            message = "Detector setup failed: detector_setup_error"
            errors.append(message)
            checks.append({"name": "detectors", "status": "error", "message": "detector_setup_error"})

    gateway_config_check = _gateway_configuration_check(upstream_base_url)
    checks.append(gateway_config_check)
    if gateway_config_check.get("status") == "error":
        errors.append(str(gateway_config_check.get("message", "Gateway configuration failed.")))

    if upstream_base_url:
        checks.append(_check_upstream(upstream_base_url, errors, warnings))
    else:
        warnings.append("No upstream URL supplied; gateway reachability was not checked.")
        checks.append({"name": "upstream", "status": "warning", "message": "not checked"})

    checks.append(
        {
            "name": "protection",
            "status": "unverified",
            "message": "No protected /v1 request was sent; doctor checks configuration and reachability only.",
        }
    )

    if audit_jsonl_path:
        checks.append(_check_audit_path(audit_jsonl_path, errors))
    else:
        warnings.append("No audit JSONL path supplied; durable gateway telemetry is disabled.")
        checks.append({"name": "audit_jsonl", "status": "warning", "message": "disabled"})

    if metrics_jsonl_path:
        checks.append(_check_audit_path(metrics_jsonl_path, errors, name="metrics_jsonl"))
    if vault_path:
        checks.append({"name": "vault", "status": "ok", "path": str(vault_path), "message": "configured"})

    status = "error" if errors else "ok"
    return {
        "status": status,
        "errors": errors,
        "warnings": warnings,
        "checks": checks,
    }


def format_doctor_text(report: dict[str, Any]) -> str:
    lines = [f"LSDF Doctor: {report['status']}"]
    for check in report.get("checks", []):
        detail = check.get("message") or check.get("profile") or check.get("url") or ""
        if check.get("name") == "gateway_config" and check.get("status") == "ok":
            management = check.get("management", {})
            client = check.get("client", {})
            detail = (
                f"upstream={'configured' if check.get('upstream_configured') else 'not configured'}; "
                f"management_auth={'required' if management.get('auth_required') else 'not required'}; "
                f"client_auth={'required' if client.get('auth_required') else 'not required'}"
            )
        suffix = f" - {detail}" if detail else ""
        lines.append(f"- {check.get('status', 'unknown').upper()} {check.get('name')}{suffix}")
    for warning in report.get("warnings", []):
        lines.append(f"- WARN {warning}")
    for error in report.get("errors", []):
        lines.append(f"- ERROR {error}")
    lines.append("Found a detection gap? File it (synthetic examples only): https://github.com/brntech/lsdf/issues/new?template=coverage-gap.md")
    return "\n".join(lines) + "\n"


def init_env_file(
    *,
    upstream: str,
    upstream_base_url: str | None,
    profile: str,
    output: Path,
    audit_jsonl_path: str | None = None,
    metrics_jsonl_path: str | None = None,
    vault_path: str | None = None,
    tokenization_mode: str = "irreversible",
    domain_packs: list[str] | tuple[str, ...] | None = None,
    force: bool = False,
) -> dict[str, Any]:
    if upstream == "custom" and not upstream_base_url:
        raise ValueError("--upstream-base-url is required with --upstream custom")
    resolved_upstream = upstream_base_url or UPSTREAM_PRESETS[upstream]
    if profile not in POLICY_PROFILES:
        valid = ", ".join(sorted(POLICY_PROFILES))
        raise ValueError(f"Unknown profile: {profile}. Valid profiles: {valid}")
    if output.exists() and not force:
        raise FileExistsError(f"{output} already exists; pass --force to overwrite")

    values = {
        "LSDF_PROFILE": profile,
        "LSDF_UPSTREAM_BASE_URL": resolved_upstream,
        "LSDF_STREAM_HOLDBACK_CHARS": "512",
        "LSDF_CLIENT_TOKEN": "",
        "LSDF_MAX_REQUEST_BYTES": str(DEFAULT_MAX_REQUEST_BYTES),
        "LSDF_MAX_CONCURRENT_REQUESTS": str(DEFAULT_MAX_CONCURRENT_REQUESTS),
        "LSDF_CLIENT_TIMEOUT_SECONDS": str(DEFAULT_CLIENT_TIMEOUT_SECONDS),
        "LSDF_UPSTREAM_TIMEOUT_SECONDS": str(DEFAULT_UPSTREAM_TIMEOUT_SECONDS),
        "LSDF_MAX_STREAM_SECONDS": str(DEFAULT_MAX_STREAM_SECONDS),
    }
    packs = [pack for pack in (domain_packs or []) if pack]
    if packs:
        _validate_domain_packs(packs)
        values["LSDF_DOMAIN_PACKS"] = ",".join(packs)
    if audit_jsonl_path:
        values["LSDF_AUDIT_JSONL_PATH"] = audit_jsonl_path
    if metrics_jsonl_path:
        values["LSDF_METRICS_ENABLED"] = "true"
        values["LSDF_METRICS_JSONL_PATH"] = metrics_jsonl_path
    if vault_path or tokenization_mode == "vault":
        values["LSDF_TOKENIZATION_MODE"] = tokenization_mode
        if vault_path:
            values["LSDF_VAULT_PATH"] = vault_path
            values["LSDF_VAULT_KEY"] = "${LSDF_VAULT_KEY}"
    lines = [f"{key}={value}" for key, value in values.items()]
    if upstream in {"openrouter", "litellm", "custom"}:
        lines.extend(
            [
                "",
                "# Provider API keys should be supplied through your shell, secret manager,",
                "# or an uncommitted env file. Do not commit real upstream keys.",
                "# LSDF_UPSTREAM_API_KEY=${LSDF_UPSTREAM_API_KEY}",
            ]
        )
    lines.extend(
        [
            "",
            "# Client and management authentication are independent. Supply tokens",
            "# through a shell, secret manager, or uncommitted env file when needed.",
            "# LSDF_MANAGEMENT_TOKEN=${LSDF_MANAGEMENT_TOKEN}",
        ]
    )
    content = "\n".join(lines) + "\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")
    return {
        "path": str(output),
        "upstream": upstream,
        "values": values,
        "written": True,
    }


def demo_report(*, profile: str = "default", domain_packs: list[str] | tuple[str, ...] | None = None) -> dict[str, Any]:
    firewall = Firewall(load_effective_policy(profile, domain_packs=domain_packs))
    scenarios = [
        _scenario_summary(
            "request_preflight_block",
            firewall.inspect(
                {"messages": [{"role": "user", "content": f"Use {DEMO_SECRET}"}]},
                unknown_surface="input.messages",
            ),
        ),
        _scenario_summary(
            "response_redaction",
            firewall.inspect(
                {"choices": [{"message": {"content": f"Patient MRN: {DEMO_MRN} leaked."}}]},
                unknown_surface="output.content",
            ),
        ),
        _scenario_summary(
            "tool_call_argument_block",
            firewall.inspect(
                {
                    "choices": [
                        {
                            "message": {
                                "tool_calls": [
                                    {
                                        "type": "function",
                                        "function": {
                                            "name": "lookup",
                                            "arguments": json.dumps({"api_key": DEMO_SECRET}),
                                        },
                                    }
                                ]
                            }
                        }
                    ]
                },
                unknown_surface="output.content",
            ),
        ),
        _scenario_summary(
            "observability_sanitization",
            sanitize_observability(
                {
                    "trace_id": "demo",
                    "spans": [
                        {
                            "name": "tool.dispatch",
                            "attributes": {"account_note": f"Customer SSN is {DEMO_SSN}."},
                        }
                    ],
                },
                firewall,
            ),
        ),
    ]
    return {
        "profile": profile,
        "raw_value_safe": _raw_value_safe(scenarios),
        "scenario_count": len(scenarios),
        "scenarios": scenarios,
    }


def format_demo_text(report: dict[str, Any]) -> str:
    lines = [
        "LSDF Demo",
        f"- Profile: {report['profile']}",
        f"- Scenarios: {report['scenario_count']}",
        f"- Raw-value-safe report: {str(report['raw_value_safe']).lower()}",
    ]
    for scenario in report["scenarios"]:
        lines.append(
            "- "
            f"{scenario['name']}: blocked={str(scenario['blocked']).lower()} "
            f"decisions={scenario['decision_count']} "
            f"actions={','.join(scenario['actions']) or 'none'} "
            f"surfaces={','.join(scenario['surfaces']) or 'none'}"
        )
    return "\n".join(lines) + "\n"


def demo_script(*, output_format: str = "text") -> str:
    if output_format == "markdown":
        return _DEMO_SCRIPT_MARKDOWN
    return _DEMO_SCRIPT_TEXT


def explain_payload(
    payload: Any,
    *,
    policy_path: Path | None = None,
    profile: str | None = None,
    domain_packs: list[str] | tuple[str, ...] | None = None,
    unknown_surface: str = "input.messages",
    include_transformed_payload: bool = False,
) -> dict[str, Any]:
    firewall = Firewall(_load_policy_for_ux(policy_path, profile, domain_packs=domain_packs))
    result = (
        sanitize_observability(payload, firewall)
        if unknown_surface == "logs.traces"
        else firewall.inspect(payload, unknown_surface=unknown_surface)
    )
    report: dict[str, Any] = {
        "blocked": result.blocked,
        "finding_count": len(result.findings),
        "decision_count": len(result.decisions),
        "findings": [finding.safe_dict() for finding in result.findings],
        "decisions": [decision.safe_dict() for decision in result.decisions],
        "next_step": _next_step(result),
    }
    if include_transformed_payload:
        report["transformed_payload"] = result.transformed_payload
    return report


def format_explain_text(report: dict[str, Any]) -> str:
    lines = [
        "LSDF Explain",
        f"- Blocked: {str(report['blocked']).lower()}",
        f"- Findings: {report['finding_count']}",
        f"- Decisions: {report['decision_count']}",
        f"- Next step: {report['next_step']}",
    ]
    for decision in report.get("decisions", []):
        finding = decision.get("finding", {})
        lines.append(
            "- "
            f"{decision.get('action', 'unknown')} "
            f"{finding.get('entity', 'unknown')} "
            f"on {finding.get('surface', 'unknown')} "
            f"via {decision.get('rule_id', 'unknown')} "
            f"({finding.get('detector_family', 'unknown')})"
        )
    if "transformed_payload" in report:
        lines.append(json.dumps({"transformed_payload": report["transformed_payload"]}, indent=2))
    return "\n".join(lines) + "\n"


def audit_summary(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Audit JSONL not found: {path}")
    summary: dict[str, Any] = {
        "path": str(path),
        "event_count": 0,
        "malformed_lines": 0,
        "blocked_events": 0,
        "by_stage": {},
        "by_stream_state": {},
        "by_action": {},
        "by_entity": {},
        "by_surface": {},
        "by_detector_family": {},
    }
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            summary["malformed_lines"] += 1
            continue
        summary["event_count"] += 1
        if event.get("blocked"):
            summary["blocked_events"] += 1
        _increment(summary["by_stage"], event.get("stage", "unknown"))
        if event.get("stream_state"):
            _increment(summary["by_stream_state"], event["stream_state"])
        for surface in event.get("surfaces_inspected", []) or []:
            _increment(summary["by_surface"], surface)
        _summarize_audit_decisions(summary, event.get("audit_event", {}))
    return summary


def format_audit_summary_text(summary: dict[str, Any]) -> str:
    lines = [
        "LSDF Audit Summary",
        f"- Path: {summary['path']}",
        f"- Events: {summary['event_count']}",
        f"- Malformed lines: {summary['malformed_lines']}",
        f"- Blocked events: {summary['blocked_events']}",
        _format_counts("Stages", summary["by_stage"]),
        _format_counts("Stream states", summary["by_stream_state"]),
        _format_counts("Actions", summary["by_action"]),
        _format_counts("Entities", summary["by_entity"]),
        _format_counts("Surfaces", summary["by_surface"]),
        _format_counts("Detector families", summary["by_detector_family"]),
    ]
    return "\n".join(lines) + "\n"


def benchmark_payload(
    payload: Any,
    *,
    policy_path: Path | None = None,
    profile: str | None = None,
    domain_packs: list[str] | tuple[str, ...] | None = None,
    mode: str = "scan",
    iterations: int = 50,
) -> dict[str, Any]:
    if iterations < 1:
        raise ValueError("--iterations must be at least 1")
    firewall = Firewall(_load_policy_for_ux(policy_path, profile, domain_packs=domain_packs))
    timings_ms: list[float] = []
    result: InspectionResult | None = None
    for _ in range(iterations):
        started = time.perf_counter()
        result = (
            sanitize_observability(payload, firewall)
            if mode == "observability"
            else firewall.inspect(payload)
        )
        timings_ms.append((time.perf_counter() - started) * 1000)
    assert result is not None
    total_ms = sum(timings_ms)
    return {
        "mode": mode,
        "iterations": iterations,
        "payload_bytes": len(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
        "finding_count": len(result.findings),
        "decision_count": len(result.decisions),
        "blocked": result.blocked,
        "blocked_rate": 1.0 if result.blocked else 0.0,
        "throughput_per_second": iterations / (total_ms / 1000) if total_ms else 0,
        "latency_ms": {
            "min": min(timings_ms),
            "p50": _percentile(timings_ms, 50),
            "p95": _percentile(timings_ms, 95),
            "max": max(timings_ms),
            "avg": total_ms / iterations,
        },
    }


def format_benchmark_markdown(report: dict[str, Any]) -> str:
    latency = report["latency_ms"]
    return (
        "# LSDF Benchmark\n\n"
        f"- Mode: {report['mode']}\n"
        f"- Iterations: {report['iterations']}\n"
        f"- Payload bytes: {report['payload_bytes']}\n"
        f"- Findings: {report['finding_count']}\n"
        f"- Decisions: {report['decision_count']}\n"
        f"- Blocked: {str(report['blocked']).lower()}\n"
        f"- Throughput/sec: {report['throughput_per_second']:.2f}\n\n"
        "| Metric | Milliseconds |\n"
        "| --- | ---: |\n"
        f"| min | {latency['min']:.3f} |\n"
        f"| p50 | {latency['p50']:.3f} |\n"
        f"| p95 | {latency['p95']:.3f} |\n"
        f"| max | {latency['max']:.3f} |\n"
        f"| avg | {latency['avg']:.3f} |\n"
    )


def protection_report(
    *,
    policy_path: Path | None = None,
    profile: str | None = None,
    domain_packs: list[str] | tuple[str, ...] | None = None,
    dataset_paths: list[Path] | None = None,
) -> dict[str, Any]:
    policy = _load_policy_for_ux(policy_path, profile, domain_packs=domain_packs)
    firewall = Firewall(policy)
    datasets = dataset_paths or list(DEFAULT_PROTECTION_DATASETS)
    reports = []
    totals = _new_totals()
    summary = {
        "by_category": {},
        "by_surface": {},
        "by_action": {},
        "by_entity": {},
        "by_detector_family": {},
    }
    for dataset_path in datasets:
        dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
        report = firewall.evaluate(dataset["cases"])
        annotated = _annotate_eval_report(report, dataset, dataset_path, policy, firewall)
        reports.append(_dataset_summary(annotated))
        _add_totals(totals, annotated)
        _merge_eval_summary(summary, annotated.get("summary", {}))
    return {
        "profile": policy.name,
        "mode": policy.mode,
        "detector_families": firewall.detector_summary()["detector_families"],
        "dataset_count": len(reports),
        "datasets": reports,
        "totals": totals,
        "summary": summary,
    }


def format_protection_report_markdown(report: dict[str, Any]) -> str:
    totals = report["totals"]
    lines = [
        "# LSDF Protection Report",
        "",
        f"- Profile: {report.get('profile', 'unknown')}",
        f"- Mode: {report.get('mode', 'unknown')}",
        f"- Detector families: {', '.join(report.get('detector_families', []))}",
        f"- Datasets: {report.get('dataset_count', 0)}",
        f"- Cases: {totals['case_count']}",
        f"- Passed: {totals['passed']}",
        f"- Failed: {totals['failed']}",
        f"- Blocked: {totals['blocked']}",
        f"- Known gaps: {totals['known_gap_cases']}",
        f"- Known-gap leaks: {totals['known_gap_leaked_after']}",
        f"- Known-gap would-fail: {totals['known_gap_would_fail']}",
        f"- Sensitive values after: {totals['sensitive_values_leaked_after']}",
        f"- Audit raw-value violations: {totals['audit_raw_value_violations']}",
        "",
        "## Datasets",
        "",
        "| Dataset | Cases | Passed | Failed | Known Gaps | After-Leak Values |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for dataset in report.get("datasets", []):
        lines.append(
            "| "
            f"{_cell(dataset['dataset'])} | "
            f"{dataset['case_count']} | "
            f"{dataset['passed']} | "
            f"{dataset['failed']} | "
            f"{dataset['known_gap_cases']} | "
            f"{dataset['sensitive_values_leaked_after']} |"
        )
    lines.extend(["", "## Coverage", ""])
    _add_count_lines(lines, "By Surface", report["summary"]["by_surface"])
    _add_count_lines(lines, "By Entity", report["summary"]["by_entity"])
    _add_count_lines(lines, "By Action", report["summary"]["by_action"])
    return "\n".join(lines).rstrip() + "\n"


def metrics_summary(path: Path) -> dict[str, Any]:
    return summarize_metrics_jsonl(path)


def format_metrics_summary(summary: dict[str, Any], output_format: str) -> str:
    if output_format == "markdown":
        return format_metrics_summary_markdown(summary)
    return format_metrics_summary_text(summary)


_LOCAL_MANAGEMENT_HOSTS = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "::1",
        "host.docker.internal",
        "gateway",
        "gateway-ml",
        "demo-gateway",
        "runtime-gateway",
        "runtime-smoke-gateway",
        "litellm-demo-gateway",
    }
)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirectHandler)


def _validated_http_base_url(raw_url: str) -> str:
    if not isinstance(raw_url, str) or not raw_url or any(char in raw_url for char in "\r\n\t"):
        raise ValueError("invalid HTTP URL")
    parsed = urllib.parse.urlsplit(raw_url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise ValueError("invalid HTTP URL")
    try:
        hostname = parsed.hostname
        parsed.port
    except ValueError as exc:
        raise ValueError("invalid HTTP URL") from exc
    if not hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("invalid HTTP URL")
    if parsed.query or parsed.fragment:
        raise ValueError("invalid HTTP URL")
    return urllib.parse.urlunsplit(
        (parsed.scheme.lower(), parsed.netloc, parsed.path.rstrip("/"), "", "")
    )


def _safe_url_for_report(raw_url: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(raw_url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return "<invalid-url>"
        port = parsed.port
        hostname = parsed.hostname
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        netloc = hostname if port is None else f"{hostname}:{port}"
        return f"{parsed.scheme.lower()}://{netloc}"
    except (TypeError, ValueError):
        return "<invalid-url>"


def _is_printable_ascii_token(value: str) -> bool:
    return value.isascii() and all(0x20 <= ord(char) < 0x7F for char in value)


def _management_token_allowed(raw_url: str) -> bool:
    try:
        hostname = urllib.parse.urlsplit(raw_url).hostname
    except ValueError:
        return False
    return bool(hostname and hostname.lower() in _LOCAL_MANAGEMENT_HOSTS)


def _set_response_timeout(response: Any, timeout: float) -> None:
    candidates = [
        getattr(response, "_sock", None),
        getattr(getattr(response, "fp", None), "raw", None),
        getattr(getattr(getattr(response, "fp", None), "raw", None), "_sock", None),
    ]
    for candidate in candidates:
        setter = getattr(candidate, "settimeout", None)
        if callable(setter):
            try:
                setter(max(timeout, 0.001))
            except OSError:
                pass
            return


def _read_bounded_response(response: Any) -> bytes:
    deadline = time.monotonic() + _SMOKE_TIMEOUT_SECONDS
    chunks: list[bytes] = []
    total = 0
    while total <= _SMOKE_MAX_RESPONSE_BYTES:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("management response deadline exceeded")
        _set_response_timeout(response, remaining)
        read_size = min(8192, _SMOKE_MAX_RESPONSE_BYTES + 1 - total)
        reader = getattr(response, "read1", None)
        chunk = reader(read_size) if callable(reader) else response.read(read_size)
        if not chunk:
            return b"".join(chunks)
        if not isinstance(chunk, bytes):
            raise ValueError("management response was not bytes")
        chunks.append(chunk)
        total += len(chunk)
    raise ValueError("management response exceeded size limit")


def _fetch_management_json(url: str, *, management_token: str | None) -> tuple[int, Any, int]:
    headers = {"Accept": "application/json"}
    if management_token:
        headers["Authorization"] = f"Bearer {management_token}"
    request = urllib.request.Request(url, headers=headers, method="GET")
    with _NO_REDIRECT_OPENER.open(request, timeout=_SMOKE_TIMEOUT_SECONDS) as response:
        body = _read_bounded_response(response)
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("management response was not JSON") from exc
        return int(getattr(response, "status", 200)), payload, len(body)


def _safe_health_summary(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    summary: dict[str, Any] = {}
    status = payload.get("status")
    if isinstance(status, str) and status in _SAFE_HEALTH_STATUSES:
        summary["status"] = status
    upstream = payload.get("upstream")
    upstream_status = upstream.get("status") if isinstance(upstream, dict) else None
    if isinstance(upstream_status, str) and upstream_status in _SAFE_UPSTREAM_STATUSES:
        summary["upstream_status"] = upstream_status
    for section in ("management", "client"):
        value = payload.get(section)
        if isinstance(value, dict) and isinstance(value.get("auth_required"), bool):
            summary[section] = {"auth_required": value["auth_required"]}
    limits = payload.get("limits")
    if isinstance(limits, dict):
        safe_limits: dict[str, int | float] = {}
        for key in _HEALTH_LIMIT_KEYS:
            value = limits.get(key)
            if isinstance(value, bool):
                continue
            if isinstance(value, int):
                if value < 0 or value > 10**15:
                    continue
            elif isinstance(value, float):
                if not math.isfinite(value) or value < 0 or value > 10**15:
                    continue
            else:
                continue
            safe_limits[key] = value
        if safe_limits:
            summary["limits"] = safe_limits
    return summary


def _safe_metrics_summary(payload: Any) -> dict[str, int]:
    if not isinstance(payload, dict):
        return {}
    counters = payload.get("counters")
    durations = payload.get("durations")
    summary: dict[str, int] = {}
    if isinstance(counters, dict):
        summary["counter_count"] = sum(
            1 for value in counters.values() if isinstance(value, int) and not isinstance(value, bool)
        )
    if isinstance(durations, dict):
        summary["duration_count"] = sum(1 for value in durations.values() if isinstance(value, dict))
    return summary


def smoke_report(
    *,
    gateway_base_url: str | None = None,
    upstream_base_url: str | None = None,
    audit_jsonl_path: Path | None = None,
    management_token: str | None = None,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    errors: list[str] = []
    base_url = gateway_base_url or upstream_base_url
    if not base_url:
        raise ValueError("--gateway-base-url is required")
    display_url = _safe_url_for_report(base_url)
    try:
        base = _validated_http_base_url(base_url)
    except ValueError:
        return {
            "status": "error",
            "gateway_base_url": display_url,
            "checks": [{"name": "gateway_url", "status": "error", "error_type": "ValueError"}],
            "errors": ["gateway URL failed: ValueError"],
        }
    if management_token is not None and not _is_printable_ascii_token(management_token):
        return {
            "status": "error",
            "gateway_base_url": display_url,
            "checks": [{"name": "management_auth", "status": "error", "error_type": "ValueError"}],
            "errors": ["management authentication failed: ValueError"],
        }
    effective_token = management_token if management_token and _management_token_allowed(base) else None
    if management_token and effective_token is None:
        checks.append(
            {
                "name": "management_auth",
                "status": "unverified",
                "message": "Management token was withheld for a non-local target.",
            }
        )
    for name, path in (("health", "/lsdf/health"), ("metrics", "/lsdf/metrics?format=json")):
        try:
            status_code, payload, body_size = _fetch_management_json(
                f"{base}{path}", management_token=effective_token
            )
            check = {
                "name": name,
                "status": "ok",
                "http_status": status_code,
                "bytes": body_size,
            }
            safe_summary = (
                _safe_health_summary(payload)
                if name == "health"
                else _safe_metrics_summary(payload)
            )
            if safe_summary:
                check["summary"] = safe_summary
            checks.append(check)
        except urllib.error.HTTPError as exc:
            try:
                exc.close()
            except Exception:
                pass
            error_type = "management_http_error"
            errors.append(f"{name} failed: {error_type}")
            check = {"name": name, "status": "error", "error_type": error_type}
            if isinstance(exc.code, int):
                check["http_status"] = exc.code
            checks.append(check)
        except Exception:
            errors.append(f"{name} failed: management_transport_error")
            checks.append({"name": name, "status": "error", "error_type": "management_transport_error"})
    checks.append(
        {
            "name": "protection",
            "status": "unverified",
            "message": "No protected /v1 request was sent; management checks do not prove client authentication.",
        }
    )
    if audit_jsonl_path is not None:
        try:
            checks.append({"name": "audit_summary", "status": "ok", "summary": audit_summary(audit_jsonl_path)})
        except Exception:
            errors.append("audit summary failed: audit_summary_error")
            checks.append({"name": "audit_summary", "status": "error", "error_type": "audit_summary_error"})
    return {
        "status": "error" if errors else "ok",
        "gateway_base_url": display_url,
        "checks": checks,
        "errors": errors,
    }


def format_smoke_text(report: dict[str, Any]) -> str:
    lines = [f"LSDF Smoke: {report['status']}"]
    if report.get("gateway_base_url"):
        lines.append(f"- Gateway: {report['gateway_base_url']}")
    for check in report["checks"]:
        suffix = f" - {check.get('http_status')}" if "http_status" in check else ""
        if check.get("message"):
            suffix += f" - {check['message']}"
        lines.append(f"- {check['status'].upper()} {check['name']}{suffix}")
    for error in report.get("errors", []):
        lines.append(f"- ERROR {error}")
    return "\n".join(lines) + "\n"


def quickstart_report(
    *,
    gateway_base_url: str,
    audit_jsonl_path: Path | None = None,
    metrics_jsonl_path: Path | None = None,
    management_token: str | None = None,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    errors: list[str] = []
    try:
        smoke = smoke_report(
            gateway_base_url=gateway_base_url,
            audit_jsonl_path=audit_jsonl_path,
            management_token=management_token,
        )
    except Exception as exc:
        smoke = {"status": "error", "checks": [], "errors": ["smoke_error"]}
    checks.append({"name": "gateway_smoke", "status": smoke["status"], "summary": smoke})
    management_auth = next(
        (check for check in smoke.get("checks", []) if check.get("name") == "management_auth"),
        None,
    )
    if management_auth is not None:
        checks.append(
            {
                "name": "management_auth",
                "status": management_auth.get("status", "unverified"),
                "message": management_auth.get(
                    "message", "Management authentication was not verified."
                ),
            }
        )
    protection = next(
        (check for check in smoke.get("checks", []) if check.get("name") == "protection"),
        {"message": "No protected /v1 request was sent."},
    )
    checks.append(
        {
            "name": "protection",
            "status": "unverified",
            "message": protection.get("message", "No protected /v1 request was sent."),
        }
    )
    errors.extend(smoke.get("errors", []))
    if metrics_jsonl_path is not None:
        try:
            summary = metrics_summary(metrics_jsonl_path)
            checks.append({"name": "metrics_summary", "status": "ok", "summary": summary})
        except Exception:
            errors.append("metrics summary failed: metrics_summary_error")
            checks.append({"name": "metrics_summary", "status": "error", "error_type": "metrics_summary_error"})
    return {
        "status": "error" if errors else "ok",
        "gateway_base_url": _safe_url_for_report(gateway_base_url),
        "checks": checks,
        "errors": errors,
    }


def format_quickstart_report_text(report: dict[str, Any]) -> str:
    lines = [
        f"LSDF Quickstart Report: {report['status']}",
        f"- Gateway: {report['gateway_base_url']}",
    ]
    for check in report["checks"]:
        suffix = f" - {check['message']}" if check.get("message") else ""
        lines.append(f"- {check['status'].upper()} {check['name']}{suffix}")
    for error in report.get("errors", []):
        lines.append(f"- ERROR {error}")
    return "\n".join(lines) + "\n"


def format_quickstart_report_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# LSDF Quickstart Report",
        "",
        f"- Status: {report['status']}",
        f"- Gateway: {report['gateway_base_url']}",
        "",
        "| Check | Status |",
        "| --- | --- |",
    ]
    for check in report["checks"]:
        status = check["status"]
        if check.get("message"):
            status = f"{status}: {_cell(check['message'])}"
        lines.append(f"| {_cell(check['name'])} | {status} |")
    if report.get("errors"):
        lines.extend(["", "## Errors", ""])
        for error in report["errors"]:
            lines.append(f"- `{_cell(error)}`")
    return "\n".join(lines).rstrip() + "\n"


def simulate_policy(
    fixture_paths: list[Path],
    *,
    policy_path: Path | None = None,
    profile: str | None = None,
    domain_packs: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    policy = _load_policy_for_ux(policy_path, profile, domain_packs=domain_packs)
    firewall = Firewall(policy)
    results: list[dict[str, Any]] = []
    failed = 0
    known_gap_would_fail = 0
    for path in fixture_paths:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict) and "cases" in payload:
            report = firewall.evaluate(payload["cases"])
            failed += report["failed"]
            known_gap_would_fail += report.get("known_gap_would_fail", 0)
            results.append({"path": str(path), "kind": "dataset", **_dataset_summary(report | {"dataset": payload.get("name", path.name)})})
        else:
            result = firewall.inspect(payload)
            failed += int(result.blocked)
            results.append(
                {
                    "path": str(path),
                    "kind": "payload",
                    "blocked": result.blocked,
                    "finding_count": len(result.findings),
                    "decision_count": len(result.decisions),
                    "actions": sorted({decision.action for decision in result.decisions}),
                    "surfaces": sorted({finding.surface for finding in result.findings}),
                }
            )
    return {
        "profile": policy.name,
        "fixture_count": len(fixture_paths),
        "failed": failed,
        "known_gap_would_fail": known_gap_would_fail,
        "results": results,
    }


def format_simulate_policy_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# LSDF Policy Simulation",
        "",
        f"- Profile: {report['profile']}",
        f"- Fixtures: {report['fixture_count']}",
        f"- Failed: {report['failed']}",
        f"- Known-gap would-fail: {report['known_gap_would_fail']}",
        "",
        "| Fixture | Kind | Blocked/Failed | Decisions |",
        "| --- | --- | ---: | ---: |",
    ]
    for item in report["results"]:
        blocked = item.get("blocked", item.get("failed", 0))
        decisions = item.get("decision_count", item.get("case_count", 0))
        lines.append(f"| {_cell(item['path'])} | {item['kind']} | {blocked} | {decisions} |")
    return "\n".join(lines).rstrip() + "\n"


def audit_export(path: Path, *, target: str) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Audit JSONL not found: {path}")
    exported: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        exported.append(_normalize_audit_event(event, target=target))
    return exported


def security_report(
    *,
    policy_path: Path | None = None,
    profile: str | None = None,
    domain_packs: list[str] | tuple[str, ...] | None = None,
    audit_jsonl_path: Path | None = None,
) -> dict[str, Any]:
    policy = _load_policy_for_ux(policy_path, profile, domain_packs=domain_packs)
    firewall = Firewall(policy)
    report = {
        "profile": policy.name,
        "mode": policy.mode,
        "policy": policy.summary(),
        "detectors": firewall.detector_summary(),
        "domain_packs": list(domain_packs or []),
        "non_certification": "LSDF is a runtime firewall and proof system, not a compliance certification.",
    }
    if audit_jsonl_path is not None and audit_jsonl_path.exists():
        report["audit_summary"] = audit_summary(audit_jsonl_path)
    return report


def format_security_report_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# LSDF Security Report",
        "",
        f"- Profile: {report['profile']}",
        f"- Mode: {report['mode']}",
        f"- Detector families: {', '.join(report['detectors'].get('detector_families', []))}",
        f"- Domain packs: {', '.join(report.get('domain_packs', [])) or 'none'}",
        f"- Note: {report['non_certification']}",
    ]
    if "audit_summary" in report:
        audit = report["audit_summary"]
        lines.extend(
            [
                "",
                "## Audit",
                "",
                f"- Events: {audit['event_count']}",
                f"- Blocked events: {audit['blocked_events']}",
                f"- Malformed lines: {audit['malformed_lines']}",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def proof_bundle(
    *,
    output: Path,
    policy_path: Path | None = None,
    profile: str | None = None,
    domain_packs: list[str] | tuple[str, ...] | None = None,
    audit_jsonl_path: Path | None = None,
    metrics_jsonl_path: Path | None = None,
    output_format: str = "markdown",
) -> dict[str, Any]:
    output.mkdir(parents=True, exist_ok=True)
    policy = _load_policy_for_ux(policy_path, profile, domain_packs=domain_packs)
    protection = protection_report(
        policy_path=policy_path,
        profile=profile,
        domain_packs=domain_packs,
    )
    security = security_report(
        policy_path=policy_path,
        profile=profile,
        domain_packs=domain_packs,
        audit_jsonl_path=audit_jsonl_path,
    )
    files: dict[str, str] = {}
    _write_json(output / "policy-summary.json", policy.summary(), files)
    _write_json(output / "protection-report.json", protection, files)
    _write_json(output / "security-report.json", security, files)
    _write_json(output / "audit-schema.json", _audit_schema_summary(), files)
    if audit_jsonl_path is not None and audit_jsonl_path.exists():
        _write_json(output / "audit-summary.json", audit_summary(audit_jsonl_path), files)
    if metrics_jsonl_path is not None and metrics_jsonl_path.exists():
        _write_json(output / "metrics-summary.json", metrics_summary(metrics_jsonl_path), files)
    manifest = {
        "status": "ok",
        "output": str(output),
        "format": output_format,
        "profile": policy.name,
        "domain_packs": list(domain_packs or []),
        "detector_families": protection["detector_families"],
        "known_gap_cases": protection["totals"]["known_gap_cases"],
        "known_gap_leaked_after": protection["totals"]["known_gap_leaked_after"],
        "known_gap_would_fail": protection["totals"]["known_gap_would_fail"],
        "management": {
            "recommendation": "Protect /lsdf/* with LSDF_MANAGEMENT_TOKEN or a trusted reverse proxy.",
        },
        "vault": {
            "posture": "irreversible tokens by default; encrypted local vault when explicitly configured.",
        },
        "non_certification": "LSDF is a runtime firewall and proof system, not a compliance certification.",
        "files": files,
    }
    files["readme"] = str(output / "README.md")
    files["manifest"] = str(output / "manifest.json")
    manifest["files"] = files
    readme = format_proof_bundle_markdown(manifest)
    (output / "README.md").write_text(readme, encoding="utf-8")
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def format_proof_bundle_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# LSDF Proof Bundle",
        "",
        f"- Status: {report['status']}",
        f"- Profile: {report['profile']}",
        f"- Domain packs: {', '.join(report.get('domain_packs', [])) or 'none'}",
        f"- Detector families: {', '.join(report.get('detector_families', []))}",
        f"- Known gaps: {report['known_gap_cases']}",
        f"- Known-gap leaks: {report['known_gap_leaked_after']}",
        f"- Known-gap would-fail: {report['known_gap_would_fail']}",
        f"- Note: {report['non_certification']}",
        "",
        "## Files",
        "",
    ]
    for name, path in sorted(report.get("files", {}).items()):
        lines.append(f"- `{name}`: `{path}`")
    return "\n".join(lines).rstrip() + "\n"


def format_single_eval_markdown(report: dict[str, Any]) -> str:
    return format_eval_report_markdown(report)


def _load_policy_for_ux(
    policy_path: Path | None,
    profile: str | None,
    *,
    domain_packs: list[str] | tuple[str, ...] | None = None,
) -> Policy:
    if policy_path is not None:
        return load_policy(policy_path)
    return load_effective_policy(profile or "default", domain_packs=domain_packs)


def _limits_from_gateway_config(config: Any) -> dict[str, int | float]:
    return {
        "max_request_bytes": config.max_request_bytes,
        "max_concurrent_requests": config.max_concurrent_requests,
        "client_timeout_seconds": config.client_timeout_seconds,
        "upstream_timeout_seconds": config.upstream_timeout_seconds,
        "max_stream_seconds": config.max_stream_seconds,
        "stream_holdback_chars": config.stream_holdback_chars,
    }


def _gateway_configuration_check(upstream_base_url: str | None) -> dict[str, Any]:
    configured_upstream = upstream_base_url or os.environ.get("LSDF_UPSTREAM_BASE_URL")
    # resolve_gateway_config validates auth and limit environment values without
    # opening a network connection. A synthetic URL keeps the check useful when
    # doctor is run before an upstream has been configured.
    validation_url = configured_upstream or "http://lsdf-doctor.invalid"
    try:
        config = resolve_gateway_config(
            upstream_base_url=validation_url,
            environ=dict(os.environ),
        )
    except GatewayConfigError as exc:
        return {
            "name": "gateway_config",
            "status": "error",
            "message": "Gateway configuration failed: gateway_config_error",
        }
    return {
        "name": "gateway_config",
        "status": "ok",
        "upstream_configured": bool(configured_upstream),
        "management": {
            "enabled": config.management_enabled,
            "auth_required": bool(config.management_token),
        },
        "client": {"auth_required": bool(config.client_token)},
        "limits": _limits_from_gateway_config(config),
    }


def _check_upstream(
    upstream_base_url: str, errors: list[str], warnings: list[str]
) -> dict[str, Any]:
    display_url = _safe_url_for_report(upstream_base_url)
    try:
        validated_url = _validated_http_base_url(upstream_base_url)
    except ValueError:
        message = "Upstream URL must include http(s) scheme and host"
        errors.append(message)
        return {"name": "upstream", "status": "error", "url": display_url, "message": message}
    request = urllib.request.Request(validated_url, method="GET")
    try:
        with _NO_REDIRECT_OPENER.open(request, timeout=3) as response:
            return {
                "name": "upstream",
                "status": "ok",
                "url": display_url,
                "http_status": response.status,
            }
    except urllib.error.HTTPError as exc:
        warnings.append(
            f"Upstream responded with HTTP {exc.code}; network path is reachable."
        )
        return {
            "name": "upstream",
            "status": "warning",
            "url": display_url,
            "http_status": exc.code,
            "message": "reachable with non-2xx response",
        }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        message = "Upstream reachability failed: upstream_transport_error"
        errors.append(message)
        return {"name": "upstream", "status": "error", "url": display_url, "message": message}


def _check_audit_path(path: Path, errors: list[str], *, name: str = "audit_jsonl") -> dict[str, Any]:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8"):
            pass
    except Exception as exc:
        message = "Audit path is not writable: audit_path_error"
        errors.append(message)
        return {"name": name, "status": "error", "path": str(path), "message": message}
    return {"name": name, "status": "ok", "path": str(path)}


def _write_json(path: Path, payload: dict[str, Any], files: dict[str, str]) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    files[path.stem] = str(path)


def _audit_schema_summary() -> dict[str, Any]:
    return {
        "raw_value_safe": True,
        "event_shape": {
            "source": "gateway",
            "stage": "request_preflight|response_inspection|stream_terminal",
            "blocked": "boolean",
            "decision_count": "integer",
            "scope": "span|surface on each decision",
            "scope_escalated": "boolean on each decision",
            "audit_event": "raw-value-safe decision metadata",
        },
        "evidence": "non-reversible placeholders only",
    }


def _validate_domain_packs(domain_packs: list[str] | tuple[str, ...]) -> None:
    for pack in domain_packs:
        if pack not in DOMAIN_PACKS:
            valid = ", ".join(sorted(DOMAIN_PACKS))
            raise ValueError(f"Unknown domain pack: {pack}. Valid domain packs: {valid}")


def _scenario_summary(name: str, result: InspectionResult) -> dict[str, Any]:
    return {
        "name": name,
        "blocked": result.blocked,
        "finding_count": len(result.findings),
        "decision_count": len(result.decisions),
        "actions": sorted({decision.action for decision in result.decisions}),
        "entities": sorted({finding.entity for finding in result.findings}),
        "surfaces": sorted({finding.surface for finding in result.findings}),
        "audit_decision_count": result.audit_event.get("decision_count", 0),
    }


def _raw_value_safe(value: Any) -> bool:
    text = json.dumps(value, sort_keys=True)
    return all(raw not in text for raw in (DEMO_SECRET, DEMO_MRN, DEMO_SSN))


def _next_step(result: InspectionResult) -> str:
    if result.blocked:
        return "Do not forward this payload until the blocked surface is removed or policy changes."
    if result.decisions:
        return "Forward the transformed payload and review the policy decisions."
    return "No sensitive-data policy action was required."


def _summarize_audit_decisions(summary: dict[str, Any], audit_event: dict[str, Any]) -> None:
    for decision in audit_event.get("decisions", []) or []:
        if "action" in decision:
            _increment(summary["by_action"], decision["action"])
        finding = decision.get("finding", {})
        if finding.get("entity"):
            _increment(summary["by_entity"], finding["entity"])
        if finding.get("surface"):
            _increment(summary["by_surface"], finding["surface"])
        if finding.get("detector_family"):
            _increment(summary["by_detector_family"], finding["detector_family"])


def _normalize_audit_event(event: dict[str, Any], *, target: str) -> dict[str, Any]:
    audit_event = event.get("audit_event", {}) or {}
    actions: list[str] = []
    entities: list[str] = []
    surfaces: list[str] = []
    detector_families: list[str] = []
    for decision in audit_event.get("decisions", []) or []:
        if decision.get("action"):
            actions.append(decision["action"])
        finding = decision.get("finding", {}) or {}
        if finding.get("entity"):
            entities.append(finding["entity"])
        if finding.get("surface"):
            surfaces.append(finding["surface"])
        if finding.get("detector_family"):
            detector_families.append(finding["detector_family"])
    return {
        "target": target,
        "timestamp": event.get("timestamp"),
        "source": event.get("source", "gateway"),
        "stage": event.get("stage", "unknown"),
        "stream": bool(event.get("stream", False)),
        "stream_state": event.get("stream_state"),
        "blocked": bool(event.get("blocked", False)),
        "decision_count": int(event.get("decision_count", audit_event.get("decision_count", 0) or 0)),
        "status": event.get("status"),
        "actions": sorted(set(actions)),
        "entities": sorted(set(entities)),
        "surfaces": sorted(set(surfaces) | set(event.get("surfaces_inspected", []) or [])),
        "detector_families": sorted(set(detector_families)),
    }


def _format_counts(title: str, counts: dict[str, int]) -> str:
    if not counts:
        return f"- {title}: none"
    values = ", ".join(f"{key}={counts[key]}" for key in sorted(counts))
    return f"- {title}: {values}"


def _percentile(values: list[float], percentile: int) -> float:
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    index = round((percentile / 100) * (len(ordered) - 1))
    return ordered[index]


def _new_totals() -> dict[str, int]:
    return {
        "case_count": 0,
        "passed": 0,
        "failed": 0,
        "blocked": 0,
        "known_gap_cases": 0,
        "known_gap_leaked_after": 0,
        "known_gap_would_fail": 0,
        "sensitive_values_leaked_after": 0,
        "audit_raw_value_violations": 0,
    }


def _annotate_eval_report(
    report: dict[str, Any],
    dataset: dict[str, Any],
    path: Path,
    policy: Policy,
    firewall: Firewall,
) -> dict[str, Any]:
    detector_summary = firewall.detector_summary()
    return {
        "dataset": dataset.get("name", path.name),
        "dataset_path": str(path),
        "profile": policy.name,
        "mode": policy.mode,
        "detector_families": detector_summary["detector_families"],
        "detector_ids": detector_summary["detector_ids"],
        **report,
    }


def _dataset_summary(report: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "dataset",
        "dataset_path",
        "case_count",
        "passed",
        "failed",
        "blocked",
        "known_gap_cases",
        "known_gap_leaked_after",
        "known_gap_would_fail",
        "sensitive_values_leaked_after",
        "audit_raw_value_violations",
    )
    return {key: report.get(key, 0) for key in keys}


def _add_totals(totals: dict[str, int], report: dict[str, Any]) -> None:
    for key in totals:
        totals[key] += int(report.get(key, 0))


def _merge_eval_summary(target: dict[str, Any], source: dict[str, Any]) -> None:
    for summary_key, rows in source.items():
        if summary_key not in target:
            continue
        for key, value in rows.items():
            if isinstance(value, dict):
                count = int(value.get("cases", value.get("count", 0)))
            else:
                count = int(value)
            _increment(target[summary_key], key, count)


def _add_count_lines(lines: list[str], title: str, counts: dict[str, int]) -> None:
    lines.extend([f"### {title}", ""])
    if not counts:
        lines.extend(["No data.", ""])
        return
    lines.extend(["| Key | Count |", "| --- | ---: |"])
    for key in sorted(counts):
        lines.append(f"| {_cell(key)} | {counts[key]} |")
    lines.append("")


def _cell(value: Any) -> str:
    return str(value).replace("|", "\\|")


def _increment(bucket: dict[str, int], key: Any, amount: int = 1) -> None:
    text = str(key)
    bucket[text] = bucket.get(text, 0) + amount


_DEMO_SCRIPT_TEXT = """LSDF Golden Demo Script

Command:
docker compose --profile demo up --build --abort-on-container-exit --exit-code-from demo-runner demo-runner
docker compose --profile demo down

Narration:
1. LSDF starts a dependency-free OpenAI-compatible demo upstream and the gateway.
2. The first check blocks an unsafe request before it reaches the model.
3. The second check redacts unsafe model output before it reaches the client.
4. The streaming check releases only sanitized chunks and preserves [DONE].
5. The tool-call check blocks unsafe streamed arguments before raw fragments leak.
6. The observability check sanitizes trace/log-shaped payloads outside the proxy.
7. Health, metrics, audit summary, and metrics summary prove operational visibility.
8. The report is raw-value-safe by design; real sensitive values are never printed.

Expected result:
LSDF Golden Demo: ok
"""

_DEMO_SCRIPT_MARKDOWN = """# LSDF Golden Demo Script

```bash
docker compose --profile demo up --build --abort-on-container-exit --exit-code-from demo-runner demo-runner
docker compose --profile demo down
```

## Narration

1. LSDF starts a dependency-free OpenAI-compatible demo upstream and the gateway.
2. The first check blocks an unsafe request before it reaches the model.
3. The second check redacts unsafe model output before it reaches the client.
4. The streaming check releases only sanitized chunks and preserves `[DONE]`.
5. The tool-call check blocks unsafe streamed arguments before raw fragments leak.
6. The observability check sanitizes trace/log-shaped payloads outside the proxy.
7. Health, metrics, audit summary, and metrics summary prove operational visibility.
8. The report is raw-value-safe by design; real sensitive values are never printed.

## Expected Result

```text
LSDF Golden Demo: ok
```
"""
