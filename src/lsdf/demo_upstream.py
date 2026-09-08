# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

DEMO_SECRET = "api_LSDF_FIXTURE_TOKEN_000000"
DEMO_MRN = "LSDF-FIXTURE-00001"


class DemoUpstreamHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path not in {"/", "/health"}:
            self._send_json(404, {"error": {"message": "Not found", "type": "not_found"}})
            return
        self._send_json(200, {"status": "ok", "service": "lsdf-demo-upstream"})

    def do_POST(self) -> None:
        if self.path != "/v1/chat/completions":
            self._send_json(404, {"error": {"message": "Not found", "type": "not_found"}})
            return
        try:
            payload = self._read_json()
        except ValueError as exc:
            self._send_json(400, {"error": {"message": str(exc), "type": "invalid_request"}})
            return
        if isinstance(payload, dict) and payload.get("stream") is True:
            self._send_stream(payload)
            return
        self._send_json(200, _completion_response(payload))

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _read_json(self) -> Any:
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON body: {exc}") from exc

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_stream(self, payload: Any) -> None:
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("cache-control", "no-cache")
        self.end_headers()
        for chunk in _stream_chunks(payload):
            self.wfile.write(chunk)
            self.wfile.flush()
            time.sleep(0.01)


def serve_demo_upstream(host: str = "0.0.0.0", port: int = 8091) -> None:
    server = ThreadingHTTPServer((host, port), DemoUpstreamHandler)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lsdf-demo-upstream")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8091)
    args = parser.parse_args(argv)
    serve_demo_upstream(args.host, args.port)
    return 0


def _completion_response(payload: Any) -> dict[str, Any]:
    mode = _mode(payload)
    if mode == "reasoning":
        message = {
            "role": "assistant",
            "content": "I cannot show the hidden reasoning.",
            "reasoning_content": f"Use {DEMO_SECRET} for the internal call.",
        }
    else:
        message = {
            "role": "assistant",
            "content": f"Demo upstream leaked patient MRN: {DEMO_MRN}.",
        }
    return {
        "id": "chatcmpl-lsdf-demo",
        "object": "chat.completion",
        "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
    }


def _stream_chunks(payload: Any) -> list[bytes]:
    mode = _mode(payload)
    if mode == "tool":
        return [
            _sse(
                {
                    "choices": [
                        {
                            "index": 0,
                            "delta": {
                                "tool_calls": [
                                    {
                                        "index": 0,
                                        "id": "call_demo",
                                        "type": "function",
                                        "function": {"name": "lookup_account"},
                                    }
                                ]
                            },
                        }
                    ]
                }
            ),
            _sse(
                {
                    "choices": [
                        {
                            "index": 0,
                            "delta": {
                                "tool_calls": [
                                    {
                                        "index": 0,
                                        "function": {"arguments": "{\"api_key\":\"api_abcdef"},
                                    }
                                ]
                            },
                        }
                    ]
                }
            ),
            _sse(
                {
                    "choices": [
                        {
                            "index": 0,
                            "delta": {
                                "tool_calls": [
                                    {
                                        "index": 0,
                                        "function": {"arguments": "ghijklmnopqrstuvwxyz\"}"},
                                    }
                                ]
                            },
                        }
                    ]
                }
            ),
            _sse({"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}),
            b"data: [DONE]\n\n",
        ]
    if mode == "reasoning":
        return [
            _sse(
                {
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"reasoning_content": f"Use {DEMO_SECRET} internally."},
                        }
                    ]
                }
            ),
            b"data: [DONE]\n\n",
        ]
    return [
        _sse({"choices": [{"index": 0, "delta": {"role": "assistant"}}]}),
        _sse({"choices": [{"index": 0, "delta": {"content": "Demo stream leaked api_abcdef"}}]}),
        _sse({"choices": [{"index": 0, "delta": {"content": "ghijklmnopqrstuvwxyz."}}]}),
        _sse({"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}),
        b"data: [DONE]\n\n",
    ]


def _mode(payload: Any) -> str:
    text = json.dumps(payload).lower() if isinstance(payload, (dict, list)) else str(payload)
    if "tool" in text:
        return "tool"
    if "reasoning" in text:
        return "reasoning"
    return "content"


def _sse(payload: dict[str, Any]) -> bytes:
    return f"data: {json.dumps(payload)}\n\n".encode("utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
