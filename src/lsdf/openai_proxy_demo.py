# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class OpenAIProxyDemoHandler(BaseHTTPRequestHandler):
    upstream_base_url = os.environ.get("LSDF_DEMO_PROXY_UPSTREAM_BASE_URL", "http://demo-upstream:8091")

    def do_GET(self) -> None:
        if self.path not in {"/", "/health"}:
            self._send_json(404, {"error": {"message": "Not found", "type": "not_found"}})
            return
        self._send_json(200, {"status": "ok", "service": "lsdf-openai-proxy-demo"})

    def do_POST(self) -> None:
        if self.path != "/v1/chat/completions":
            self._send_json(404, {"error": {"message": "Not found", "type": "not_found"}})
            return
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)
        upstream_url = _join_openai_url(self.upstream_base_url, "/v1/chat/completions")
        headers = {"content-type": self.headers.get("content-type", "application/json")}
        if authorization := self.headers.get("authorization"):
            headers["authorization"] = authorization
        request = urllib.request.Request(upstream_url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                response_headers = dict(response.headers.items())
                if "text/event-stream" in _header(response_headers, "content-type", ""):
                    self._send_stream(response.status, response_headers, response)
                else:
                    self._send_bytes(response.status, response_headers, response.read())
        except urllib.error.HTTPError as exc:
            self._send_bytes(exc.code, dict(exc.headers.items()), exc.read())
        except (urllib.error.URLError, TimeoutError, OSError):
            self._send_json(502, {"error": {"message": "Demo proxy upstream unavailable", "type": "upstream_transport_error"}})

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        self._send_bytes(status, {"content-type": "application/json"}, json.dumps(payload).encode("utf-8"))

    def _send_bytes(self, status: int, headers: dict[str, str], body: bytes) -> None:
        self.send_response(status)
        content_type = _header(headers, "content-type", "application/octet-stream")
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_stream(self, status: int, headers: dict[str, str], response) -> None:
        self.send_response(status)
        self.send_header("content-type", _header(headers, "content-type", "text/event-stream"))
        self.send_header("cache-control", _header(headers, "cache-control", "no-cache"))
        self.end_headers()
        while True:
            chunk = response.read(4096)
            if not chunk:
                break
            self.wfile.write(chunk)
            self.wfile.flush()


def serve_openai_proxy_demo(host: str = "0.0.0.0", port: int = 4000) -> None:
    server = ThreadingHTTPServer((host, port), OpenAIProxyDemoHandler)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lsdf-openai-proxy-demo")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=4000)
    parser.add_argument("--upstream-base-url", default=None)
    args = parser.parse_args(argv)
    if args.upstream_base_url:
        OpenAIProxyDemoHandler.upstream_base_url = args.upstream_base_url
    serve_openai_proxy_demo(args.host, args.port)
    return 0


def _header(headers: dict[str, str], name: str, default: str) -> str:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return default


def _join_openai_url(base_url: str, path: str) -> str:
    base = base_url.rstrip("/")
    request_path = path if path.startswith("/") else f"/{path}"
    if base.endswith("/v1") and request_path.startswith("/v1/"):
        request_path = request_path[len("/v1") :]
    return f"{base}{request_path}"


if __name__ == "__main__":
    raise SystemExit(main())
