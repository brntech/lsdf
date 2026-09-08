from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from lsdf import Firewall, load_policy
from lsdf.observability import sanitize_observability

SCENARIOS = {
    "python-client": "Standard OpenAI-compatible chat payload.",
    "javascript-client": "JavaScript SDK equivalent request shape.",
    "streaming-chat": "Streaming chat request.",
    "rag-context": "RAG context with input-side tokenization.",
    "tool-call": "Tool-call argument protection.",
    "observability": "Trace/log sanitizer payload.",
    "langchain": "LangChain OpenAI-compatible request shape.",
    "llamaindex": "LlamaIndex OpenAI-compatible request shape.",
    "litellm": "LiteLLM OpenAI-compatible request shape.",
    "litellm-proxy": "LSDF in front of a LiteLLM Proxy-style upstream, including SSE streaming.",
    "end-to-end": "Runs the quickstart block/redact/stream/tool-call fixtures.",
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lsdf-runnable-client-examples")
    parser.add_argument("--gateway-base-url", default="http://localhost:8080/v1")
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), required=True)
    args = parser.parse_args(argv)
    if args.scenario == "observability":
        payload = json.loads(Path("examples/quickstart/observability.json").read_text(encoding="utf-8"))
        result = sanitize_observability(payload, Firewall(load_policy("policies/default.yaml")))
        print(
            json.dumps(
                {
                    "scenario": args.scenario,
                    "blocked": result.blocked,
                    "finding_count": len(result.findings),
                    "decision_count": len(result.decisions),
                    "transformed_payload": result.transformed_payload,
                },
                indent=2,
            )
        )
        return 0
    if args.scenario == "end-to-end":
        return _run_end_to_end(args.gateway_base_url)
    status, body = _post(args.gateway_base_url, _scenario_payload(args.scenario))
    safe = body.replace("api_LSDF_FIXTURE_TOKEN_000000", "[REDACTED]")
    safe = safe.replace("000-00-0000", "[REDACTED]")
    print(json.dumps({"scenario": args.scenario, "http_status": status, "body": safe[:500]}, indent=2))
    return 0 if status < 500 else 1


def _run_end_to_end(gateway_base_url: str) -> int:
    results = []
    for name in (
        "request_block.json",
        "response_redact_request.json",
        "stream_redact_request.json",
        "tool_call_block_request.json",
    ):
        status, body = _post(
            gateway_base_url,
            json.loads(Path("examples/quickstart", name).read_text(encoding="utf-8")),
        )
        results.append({"fixture": name, "http_status": status, "bytes": len(body)})
    print(json.dumps({"scenario": "end-to-end", "results": results}, indent=2))
    return 0 if all(result["http_status"] < 500 for result in results) else 1


def _scenario_payload(name: str) -> dict[str, Any]:
    if name == "streaming-chat":
        return json.loads(Path("examples/quickstart/stream_redact_request.json").read_text(encoding="utf-8"))
    if name == "tool-call":
        return json.loads(Path("examples/quickstart/tool_call_block_request.json").read_text(encoding="utf-8"))
    if name == "rag-context":
        return {
            "model": "local-model",
            "messages": [
                {"role": "system", "content": "Use the supplied context safely."},
                {"role": "user", "content": "Context: customer SSN 000-00-0000. Summarize it."},
            ],
        }
    if name == "litellm-proxy":
        return {
            "model": "local-model",
            "stream": True,
            "messages": [{"role": "user", "content": "Route this through the LSDF gateway."}],
            "metadata": {"topology": "app -> LSDF gateway -> LiteLLM Proxy -> provider fleet"},
        }
    return {
        "model": "local-model",
        "messages": [{"role": "user", "content": f"{SCENARIOS[name]} Say hello."}],
    }


def _wait_for_gateway(base_url: str, attempts: int = 60, delay_seconds: float = 0.25) -> None:
    """Wait for healthy gateway/upstream status before sending demo traffic."""
    root = base_url.rstrip("/")
    if root.endswith("/v1"):
        root = root[: -len("/v1")]
    for _ in range(attempts):
        try:
            with urllib.request.urlopen(f"{root}/lsdf/health", timeout=2) as response:
                health = json.loads(response.read())
            if isinstance(health, dict) and health.get("status") == "ok":
                return
        except Exception:
            pass
        time.sleep(delay_seconds)


def _post(base_url: str, payload: dict[str, Any]) -> tuple[int, str]:
    _wait_for_gateway(base_url)
    url = f"{base_url.rstrip('/')}/chat/completions"
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"content-type": "application/json", "authorization": "Bearer not-used-by-lsdf"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")


if __name__ == "__main__":
    raise SystemExit(main())
