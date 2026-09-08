# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .engine import Firewall
from .observability import sanitize_observability
from .policy import load_policy
from .ux import audit_summary, metrics_summary

RAW_SECRET = "api_LSDF_FIXTURE_TOKEN_000000"
RAW_MRN = "LSDF-FIXTURE-00001"


def run_demo(
    *,
    gateway_base_url: str,
    audit_jsonl_path: Path | None = None,
    metrics_jsonl_path: Path | None = None,
) -> dict[str, Any]:
    base = gateway_base_url.rstrip("/")
    checks: list[dict[str, Any]] = []
    _wait_for_gateway(base, checks)
    checks.append(_request_block_check(base))
    checks.append(_response_redaction_check(base))
    checks.append(_stream_redaction_check(base))
    checks.append(_tool_call_block_check(base))
    checks.append(_observability_check())
    checks.append(_get_check(base, "/lsdf/health", "health"))
    checks.append(_get_check(base, "/lsdf/metrics", "metrics"))
    if audit_jsonl_path is not None:
        checks.append(_summary_check("audit_summary", audit_jsonl_path, audit_summary))
    if metrics_jsonl_path is not None:
        checks.append(_summary_check("metrics_summary", metrics_jsonl_path, metrics_summary))
    return {
        "status": "error" if any(check["status"] != "ok" for check in checks) else "ok",
        "gateway_base_url": base,
        "checks": checks,
    }


def format_demo_runner_text(report: dict[str, Any]) -> str:
    lines = [
        f"LSDF Golden Demo: {report['status']}",
        f"- Gateway: {report['gateway_base_url']}",
    ]
    for check in report["checks"]:
        detail = check.get("message", "")
        suffix = f" - {detail}" if detail else ""
        lines.append(f"- {check['status'].upper()} {check['name']}{suffix}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lsdf-demo-runner")
    parser.add_argument("--gateway-base-url", default="http://demo-gateway:8080")
    parser.add_argument("--audit-jsonl-path", type=Path, default=None)
    parser.add_argument("--metrics-jsonl-path", type=Path, default=None)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    report = run_demo(
        gateway_base_url=args.gateway_base_url,
        audit_jsonl_path=args.audit_jsonl_path,
        metrics_jsonl_path=args.metrics_jsonl_path,
    )
    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print(format_demo_runner_text(report), end="")
    return 1 if report["status"] == "error" else 0


def _wait_for_gateway(base: str, checks: list[dict[str, Any]]) -> None:
    for _ in range(60):
        try:
            health = json.loads(_get_bytes(f"{base}/lsdf/health"))
            if isinstance(health, dict) and health.get("status") == "ok":
                checks.append({"name": "gateway_ready", "status": "ok"})
                return
        except Exception:
            pass
        time.sleep(0.25)
    checks.append({"name": "gateway_ready", "status": "error", "message": "not reachable"})


def _request_block_check(base: str) -> dict[str, Any]:
    status, body = _post_json(base, _fixture("request_block.json"))
    return _check(
        "request_block",
        status == 403 and b"sensitive_data_blocked" in body and RAW_SECRET.encode() not in body,
    )


def _response_redaction_check(base: str) -> dict[str, Any]:
    status, body = _post_json(base, _fixture("response_redact_request.json"))
    return _check(
        "response_redaction",
        status == 200 and b"<MRN:REDACTED>" in body and RAW_MRN.encode() not in body,
    )


def _stream_redaction_check(base: str) -> dict[str, Any]:
    status, body = _post_json(base, _fixture("stream_redact_request.json"))
    return _check(
        "stream_redaction",
        status == 200 and b"[DONE]" in body and RAW_SECRET.encode() not in body,
    )


def _tool_call_block_check(base: str) -> dict[str, Any]:
    status, body = _post_json(base, _fixture("tool_call_block_request.json"))
    return _check(
        "tool_call_block",
        status == 200 and b"sensitive_data_blocked" in body and RAW_SECRET.encode() not in body,
    )


def _observability_check() -> dict[str, Any]:
    payload = _fixture("observability.json")
    result = sanitize_observability(payload, Firewall(load_policy("policies/default.yaml")))
    text = json.dumps(result.to_dict())
    return _check("observability_sanitize", "000-00-0000" not in text and result.decisions)


def _get_check(base: str, path: str, name: str) -> dict[str, Any]:
    try:
        body = _get_bytes(f"{base}{path}")
    except Exception as exc:
        return {"name": name, "status": "error", "message": type(exc).__name__}
    return _check(name, RAW_SECRET.encode() not in body)


def _summary_check(name: str, path: Path, summary_fn) -> dict[str, Any]:
    try:
        summary = summary_fn(path)
    except Exception as exc:
        return {"name": name, "status": "error", "message": type(exc).__name__}
    return _check(name, RAW_SECRET not in json.dumps(summary))


def _post_json(base: str, payload: Any) -> tuple[int, bytes]:
    request = urllib.request.Request(
        f"{base}/v1/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _get_bytes(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=5) as response:
        return response.read()


def _fixture(name: str) -> Any:
    return json.loads(Path("examples/quickstart", name).read_text(encoding="utf-8"))


def _check(name: str, ok: bool) -> dict[str, Any]:
    return {"name": name, "status": "ok" if ok else "error"}


if __name__ == "__main__":
    raise SystemExit(main())
