# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import http.client
import hmac
import json
import math
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterable

from .audit import JsonlAuditSink
from .engine import Firewall
from .metrics import MetricsRecorder
from .policy import load_effective_policy, load_policy, load_policy_bytes, load_policy_profile
from .security_ops import verify_policy_signature
from .streaming import DEFAULT_STREAM_HOLDBACK_CHARS, format_sse_event, stream_chat_completion_chunks
from .types import PolicyEnforcementError
from .vault import EncryptedSqliteTokenVault

UPSTREAM_TRANSPORT_ERROR_TYPE = "upstream_transport_error"
UPSTREAM_TRANSPORT_ERRORS = (
    urllib.error.URLError,
    TimeoutError,
    OSError,
    http.client.HTTPException,
)

DEFAULT_MAX_REQUEST_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_CONCURRENT_REQUESTS = 8
DEFAULT_CLIENT_TIMEOUT_SECONDS = 15.0
DEFAULT_UPSTREAM_TIMEOUT_SECONDS = 120.0
DEFAULT_MAX_STREAM_SECONDS = 300.0
_BASE_THREADING_HTTP_SERVER = ThreadingHTTPServer


class GatewayRequestError(ValueError):
    def __init__(self, status: int, error_type: str, message: str, *, not_inspected: bool = False):
        super().__init__(message)
        self.status = status
        self.error_type = error_type
        self.message = message
        self.not_inspected = not_inspected


class UnsupportedContentError(GatewayRequestError):
    def __init__(self, message: str):
        super().__init__(400, "unsupported_content", message, not_inspected=True)


class StreamDurationExceeded(RuntimeError):
    pass


@dataclass(frozen=True)
class GatewayConfig:
    policy_path: str | None
    policy_profile: str
    upstream_base_url: str
    upstream_api_key: str | None = None
    stream_holdback_chars: int = DEFAULT_STREAM_HOLDBACK_CHARS
    audit_jsonl_path: str | None = None
    audit_rotate_bytes: int | None = None
    audit_rotate_backups: int = 3
    metrics_enabled: bool = False
    metrics_jsonl_path: str | None = None
    health_upstream_timeout_ms: int = 1000
    vault_path: str | None = None
    vault_key: str | None = None
    tokenization_mode: str = "irreversible"
    domain_packs: tuple[str, ...] = ()
    require_policy_signature: bool = False
    policy_public_key: str | None = None
    management_enabled: bool = True
    management_token: str | None = None
    client_token: str | None = None
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES
    max_concurrent_requests: int = DEFAULT_MAX_CONCURRENT_REQUESTS
    client_timeout_seconds: float = DEFAULT_CLIENT_TIMEOUT_SECONDS
    upstream_timeout_seconds: float = DEFAULT_UPSTREAM_TIMEOUT_SECONDS
    max_stream_seconds: float = DEFAULT_MAX_STREAM_SECONDS


class GatewayConfigError(ValueError):
    pass


class LSDFGatewayServer(ThreadingHTTPServer):
    """Threading server with a permit acquired before a handler thread starts."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address,
        request_handler_class,
        *,
        max_concurrent_requests: int,
        metrics: MetricsRecorder | None = None,
        client_timeout_seconds: float = DEFAULT_CLIENT_TIMEOUT_SECONDS,
    ):
        self._request_slots = threading.BoundedSemaphore(max_concurrent_requests)
        self._metrics = metrics
        self._overload_socket_timeout = max(0.001, min(client_timeout_seconds, 0.05))
        super().__init__(server_address, request_handler_class)

    def process_request(self, request, client_address):
        if not self._request_slots.acquire(blocking=False):
            if self._metrics is not None:
                self._metrics.increment("gateway_concurrency_rejections_total")
            _send_socket_error(
                request,
                503,
                "gateway_overloaded",
                "Gateway is busy.",
                timeout=self._overload_socket_timeout,
            )
            try:
                self.shutdown_request(request)
            except OSError:
                pass
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


class _IngressDeadlineReader:
    """Read request-line/headers with one absolute ingress deadline."""

    def __init__(self, raw, request, owner: "LSDFGatewayHandler") -> None:
        self._raw = raw
        self._request = request
        self._owner = owner

    def _prepare_read(self) -> None:
        if not self._owner._header_deadline_active:
            return
        remaining = self._owner._header_deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout("request header deadline exceeded")
        self._request.settimeout(max(remaining, 0.001))

    def read(self, size: int = -1):
        self._prepare_read()
        return self._raw.read(size)

    def read1(self, size: int = -1):
        self._prepare_read()
        reader = getattr(self._raw, "read1", None)
        return (reader or self._raw.read)(size)

    def readline(self, size: int = -1):
        if not self._owner._header_deadline_active:
            return self._raw.readline(size)
        limit = None if size is None or size < 0 else size
        line = bytearray()
        while limit is None or len(line) < limit:
            chunk = self.read(1)
            if not chunk:
                break
            line.extend(chunk)
            if chunk == b"\n":
                break
        return bytes(line)

    def __getattr__(self, name: str):
        return getattr(self._raw, name)


def _send_socket_error(
    request,
    status: int,
    error_type: str,
    message: str,
    *,
    timeout: float = 1.0,
) -> None:
    """Write a minimal safe response before a request handler thread exists."""
    reasons = {
        400: "Bad Request",
        401: "Unauthorized",
        413: "Request Entity Too Large",
        503: "Service Unavailable",
    }
    body = json.dumps(
        {"error": {"message": message, "type": error_type}},
        separators=(",", ":"),
    ).encode("utf-8")
    response = (
        f"HTTP/1.1 {status} {reasons.get(status, 'Error')}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii") + body
    try:
        setter = getattr(request, "settimeout", None)
        if callable(setter):
            setter(max(timeout, 0.001))
        request.sendall(response)
    except OSError:
        return


def resolve_gateway_config(
    *,
    policy_path: str | None = None,
    policy_profile: str | None = None,
    upstream_base_url: str | None = None,
    upstream_api_key: str | None = None,
    audit_jsonl_path: str | None = None,
    domain_packs: Iterable[str] | None = None,
    environ: dict[str, str] | None = None,
) -> GatewayConfig:
    env = os.environ if environ is None else environ
    resolved_policy_path = policy_path or env.get("LSDF_POLICY")
    resolved_profile = (
        "default"
        if resolved_policy_path
        else policy_profile or env.get("LSDF_PROFILE", "default")
    )
    resolved_upstream_base_url = upstream_base_url or env.get("LSDF_UPSTREAM_BASE_URL")
    if not resolved_upstream_base_url:
        raise GatewayConfigError("Missing --upstream-base-url or LSDF_UPSTREAM_BASE_URL")
    resolved_upstream_api_key = upstream_api_key or env.get("LSDF_UPSTREAM_API_KEY")
    resolved_audit_jsonl_path = audit_jsonl_path or env.get("LSDF_AUDIT_JSONL_PATH") or None
    stream_holdback_chars = _resolve_stream_holdback_chars(env)
    resolved_domain_packs = tuple(
        str(pack).strip()
        for pack in (domain_packs or _split_env_list(env.get("LSDF_DOMAIN_PACKS", "")))
        if str(pack).strip()
    )
    tokenization_mode = env.get("LSDF_TOKENIZATION_MODE", "irreversible") or "irreversible"
    if tokenization_mode not in {"irreversible", "vault"}:
        raise GatewayConfigError("LSDF_TOKENIZATION_MODE must be irreversible or vault")
    resolved_management_token = _resolve_ascii_token(env, "LSDF_MANAGEMENT_TOKEN")
    resolved_client_token = _resolve_ascii_token(env, "LSDF_CLIENT_TOKEN")
    return GatewayConfig(
        policy_path=resolved_policy_path,
        policy_profile=resolved_profile,
        upstream_base_url=resolved_upstream_base_url.rstrip("/"),
        upstream_api_key=resolved_upstream_api_key,
        stream_holdback_chars=stream_holdback_chars,
        audit_jsonl_path=resolved_audit_jsonl_path,
        audit_rotate_bytes=_resolve_optional_int(env, "LSDF_AUDIT_ROTATE_BYTES"),
        audit_rotate_backups=_resolve_int(env, "LSDF_AUDIT_ROTATE_BACKUPS", 3),
        metrics_enabled=_resolve_bool(env, "LSDF_METRICS_ENABLED", False),
        metrics_jsonl_path=env.get("LSDF_METRICS_JSONL_PATH") or None,
        health_upstream_timeout_ms=_resolve_int(env, "LSDF_HEALTH_UPSTREAM_TIMEOUT_MS", 1000),
        vault_path=env.get("LSDF_VAULT_PATH") or None,
        vault_key=env.get("LSDF_VAULT_KEY") or None,
        tokenization_mode=tokenization_mode,
        domain_packs=resolved_domain_packs,
        require_policy_signature=_resolve_bool(env, "LSDF_REQUIRE_POLICY_SIGNATURE", False),
        policy_public_key=env.get("LSDF_POLICY_PUBLIC_KEY") or None,
        management_enabled=_resolve_bool(env, "LSDF_MANAGEMENT_ENABLED", True),
        management_token=resolved_management_token,
        client_token=resolved_client_token,
        max_request_bytes=_resolve_positive_int(
            env, "LSDF_MAX_REQUEST_BYTES", DEFAULT_MAX_REQUEST_BYTES
        ),
        max_concurrent_requests=_resolve_positive_int(
            env, "LSDF_MAX_CONCURRENT_REQUESTS", DEFAULT_MAX_CONCURRENT_REQUESTS
        ),
        client_timeout_seconds=_resolve_positive_float(
            env, "LSDF_CLIENT_TIMEOUT_SECONDS", DEFAULT_CLIENT_TIMEOUT_SECONDS
        ),
        upstream_timeout_seconds=_resolve_positive_float(
            env, "LSDF_UPSTREAM_TIMEOUT_SECONDS", DEFAULT_UPSTREAM_TIMEOUT_SECONDS
        ),
        max_stream_seconds=_resolve_positive_float(
            env, "LSDF_MAX_STREAM_SECONDS", DEFAULT_MAX_STREAM_SECONDS
        ),
    )


def serve_gateway(
    host: str = "127.0.0.1",
    port: int = 8080,
    config: GatewayConfig | None = None,
) -> None:
    config = config or resolve_gateway_config()
    policy_bytes: bytes | None = None
    if config.require_policy_signature and config.policy_path:
        try:
            policy_bytes = Path(config.policy_path).read_bytes()
            verification = verify_policy_signature(
                Path(config.policy_path),
                public_key_path=Path(config.policy_public_key) if config.policy_public_key else None,
                policy_bytes=policy_bytes,
            )
        except Exception as exc:
            raise GatewayConfigError(
                f"Custom policy signature verification failed: {type(exc).__name__}"
            ) from exc
        if (
            not verification["valid"]
            or verification.get("legacy")
            or verification.get("algorithm") != "ed25519"
        ):
            raise GatewayConfigError("Custom policy signature verification failed")
    if policy_bytes is not None:
        policy = load_policy_bytes(policy_bytes)
    elif config.policy_path:
        policy = load_policy(config.policy_path)
    else:
        policy = load_effective_policy(config.policy_profile, domain_packs=config.domain_packs)
    token_vault = _build_gateway_vault(config)
    firewall = Firewall(policy, token_vault=token_vault)
    audit_sink = (
        JsonlAuditSink(
            config.audit_jsonl_path,
            rotate_bytes=config.audit_rotate_bytes,
            rotate_backups=config.audit_rotate_backups,
        )
        if config.audit_jsonl_path
        else None
    )
    metrics = MetricsRecorder(
        enabled=config.metrics_enabled,
        jsonl_path=config.metrics_jsonl_path,
    )

    class Handler(LSDFGatewayHandler):
        gateway_config = config
        gateway_firewall = firewall
        gateway_audit_sink = audit_sink
        gateway_metrics = metrics
        gateway_token_vault = token_vault

    # Keep the historical ``ThreadingHTTPServer`` patch point for embedding and
    # tests.  Normal execution uses the bounded subclass; a patched class is a
    # deliberate test double and should receive the handler unchanged.
    server_class = (
        LSDFGatewayServer if ThreadingHTTPServer is _BASE_THREADING_HTTP_SERVER else ThreadingHTTPServer
    )
    server_kwargs = {
        "max_concurrent_requests": config.max_concurrent_requests,
        "metrics": metrics,
        "client_timeout_seconds": config.client_timeout_seconds,
    }
    server = server_class(
        (host, port),
        Handler,
        **server_kwargs,
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()


class LSDFGatewayHandler(BaseHTTPRequestHandler):
    gateway_config: GatewayConfig
    gateway_firewall: Firewall
    gateway_audit_sink: JsonlAuditSink | None = None
    gateway_metrics: MetricsRecorder | None = None
    gateway_token_vault: EncryptedSqliteTokenVault | None = None

    def setup(self) -> None:
        super().setup()
        self._header_deadline = time.monotonic()
        self._header_deadline_active = False
        self.rfile = _IngressDeadlineReader(self.rfile, self.request, self)
        self.request.settimeout(self.gateway_config.client_timeout_seconds)

    def handle_one_request(self) -> None:
        self._header_deadline = time.monotonic() + self.gateway_config.client_timeout_seconds
        self._header_deadline_active = True
        try:
            super().handle_one_request()
        finally:
            self._header_deadline_active = False
            try:
                self.request.settimeout(self.gateway_config.client_timeout_seconds)
            except OSError:
                pass

    def parse_request(self) -> bool:
        try:
            return super().parse_request()
        except (TimeoutError, socket.timeout):
            self.close_connection = True
            self._header_deadline_active = False
            self._send_static_error(400, "invalid_request", "Request headers could not be read.")
            return False
        finally:
            self._header_deadline_active = False
            try:
                self.request.settimeout(self.gateway_config.client_timeout_seconds)
            except OSError:
                pass

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        """Keep BaseHTTPRequestHandler parser errors raw-value-safe."""
        self.close_connection = True
        # BaseHTTPRequestHandler treats malformed request lines as HTTP/0.9;
        # force an ordinary framed response so the static JSON is not emitted
        # as an unframed body.
        self.request_version = self.protocol_version
        status = code if 400 <= code < 600 else 400
        self._send_json(
            status,
            {"error": {"message": "Malformed HTTP request.", "type": "invalid_request"}},
            {"connection": "close"},
        )

    def do_GET(self) -> None:
        if self.path.startswith("/lsdf/"):
            if not self.gateway_config.management_enabled:
                self._send_json(404, {"error": {"message": "Not found", "type": "not_found"}})
                return
            if not self._management_authorized():
                self._send_json(
                    401,
                    {"error": {"message": "Unauthorized", "type": "management_unauthorized"}},
                )
                return
        if self.path.startswith("/lsdf/health"):
            self._send_json(200, self._health_payload())
            return
        if self.path.startswith("/lsdf/metrics"):
            parsed = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed.query)
            metrics = self.gateway_metrics or MetricsRecorder(enabled=False)
            if query.get("format") == ["json"]:
                self._send_json(200, metrics.to_dict())
            else:
                body = metrics.prometheus_text().encode("utf-8")
                self._send_raw(200, body, {"content-type": "text/plain; version=0.0.4"}, {})
            return
        self._send_json(404, {"error": {"message": "Not found", "type": "not_found"}})

    def do_POST(self) -> None:
        if self.path != "/v1/chat/completions":
            self._send_json(404, {"error": {"message": "Not found", "type": "not_found"}})
            return
        if not self._client_authorized():
            self._record_rejection("client_auth")
            self._send_static_error(401, "client_unauthorized", "Unauthorized.")
            return
        try:
            payload = self._read_json()
            _validate_supported_chat_payload(payload)
        except GatewayRequestError as exc:
            self._record_rejection(exc.error_type)
            self._send_static_error(
                exc.status,
                exc.error_type,
                exc.message,
                not_inspected=exc.not_inspected,
            )
            return

        if _is_streaming_request(payload):
            status, response_headers, body, headers = handle_streaming_chat_completion(
                payload,
                self.gateway_firewall,
                self._forward_stream,
                holdback_chars=self.gateway_config.stream_holdback_chars,
                max_stream_seconds=self.gateway_config.max_stream_seconds,
                audit_sink=self.gateway_audit_sink,
                metrics=self.gateway_metrics,
            )
            self._send_iter(status, body, response_headers, headers)
            return

        status, response_headers, body, headers = handle_chat_completion(
            payload,
            self.gateway_firewall,
            self._forward,
            audit_sink=self.gateway_audit_sink,
            metrics=self.gateway_metrics,
        )
        self._send_raw(status, body, response_headers, headers)

    def _health_payload(self) -> dict[str, Any]:
        policy = self.gateway_firewall.policy
        detector_summary = self.gateway_firewall.detector_summary()
        upstream = _check_upstream_health(
            self.gateway_config.upstream_base_url,
            self.gateway_config.health_upstream_timeout_ms,
        )
        status = "ok" if upstream["status"] in {"ok", "warning"} else "degraded"
        return {
            "status": status,
            "policy": policy.summary(),
            "detectors": detector_summary,
            "upstream": upstream,
            "audit": {"enabled": self.gateway_audit_sink is not None},
            "metrics": {"enabled": bool(self.gateway_metrics and self.gateway_metrics.enabled)},
            "vault": {
                "enabled": self.gateway_token_vault is not None,
                "mode": self.gateway_config.tokenization_mode,
            },
            "stream_holdback_chars": self.gateway_config.stream_holdback_chars,
            "limits": {
                "max_request_bytes": self.gateway_config.max_request_bytes,
                "max_concurrent_requests": self.gateway_config.max_concurrent_requests,
                "client_timeout_seconds": self.gateway_config.client_timeout_seconds,
                "upstream_timeout_seconds": self.gateway_config.upstream_timeout_seconds,
                "max_stream_seconds": self.gateway_config.max_stream_seconds,
                "stream_holdback_chars": self.gateway_config.stream_holdback_chars,
            },
            "domain_packs": list(self.gateway_config.domain_packs),
            "management": {
                "enabled": self.gateway_config.management_enabled,
                "auth_required": bool(self.gateway_config.management_token),
            },
            "client": {
                "auth_required": bool(self.gateway_config.client_token),
            },
        }

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _read_json(self) -> Any:
        transfer_encoding = self.headers.get("transfer-encoding", "")
        if transfer_encoding and transfer_encoding.lower() != "identity":
            raise GatewayRequestError(
                400,
                "invalid_request",
                "Chunked request bodies are not supported.",
            )
        raw_length = self.headers.get("content-length", "0")
        try:
            length = int(raw_length, 10)
        except (TypeError, ValueError) as exc:
            raise GatewayRequestError(400, "invalid_request", "Invalid request length.") from exc
        if length < 0:
            raise GatewayRequestError(400, "invalid_request", "Invalid request length.")
        if length > self.gateway_config.max_request_bytes:
            self.close_connection = True
            raise GatewayRequestError(
                413,
                "request_too_large",
                "Request body exceeds the configured limit.",
            )
        try:
            body = self._read_body_with_deadline(length)
        except (OSError, TimeoutError, socket.timeout) as exc:
            self.close_connection = True
            raise GatewayRequestError(400, "invalid_request", "Request body could not be read.") from exc
        if len(body) != length:
            self.close_connection = True
            raise GatewayRequestError(400, "invalid_request", "Request body could not be read.")
        try:
            return json.loads(body)
        except (TypeError, RecursionError, UnicodeDecodeError, ValueError) as exc:
            raise GatewayRequestError(400, "invalid_request", "Invalid JSON request.") from exc

    def _read_body_with_deadline(self, length: int) -> bytes:
        if length == 0:
            return b""
        deadline = time.monotonic() + self.gateway_config.client_timeout_seconds
        read_once = getattr(self.rfile, "read1", None) or self.rfile.read
        remaining_bytes = length
        chunks: list[bytes] = []
        try:
            while remaining_bytes:
                remaining_seconds = deadline - time.monotonic()
                if remaining_seconds <= 0:
                    raise socket.timeout("request body deadline exceeded")
                self.request.settimeout(max(remaining_seconds, 0.001))
                chunk = read_once(min(65536, remaining_bytes))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining_bytes -= len(chunk)
        finally:
            self.request.settimeout(self.gateway_config.client_timeout_seconds)
        return b"".join(chunks)

    def _forward(self, payload: Any) -> tuple[int, dict[str, str], bytes]:
        return forward_upstream(payload, self.path, self.gateway_config)

    def _forward_stream(self, payload: Any) -> tuple[int, dict[str, str], Iterable[bytes]]:
        return forward_upstream_stream(payload, self.path, self.gateway_config)

    def _management_authorized(self) -> bool:
        expected = self.gateway_config.management_token
        if not expected:
            return True
        header = self.headers.get("authorization", "")
        bearer = ""
        if header.lower().startswith("bearer "):
            bearer = header[7:].strip()
        direct = self.headers.get("x-lsdf-management-token", "")
        if not all(value.isascii() for value in (expected, bearer, direct)):
            return False
        bearer_matches = _constant_time_token_matches(expected, bearer)
        direct_matches = _constant_time_token_matches(expected, direct)
        return bearer_matches or direct_matches

    def _client_authorized(self) -> bool:
        expected = self.gateway_config.client_token
        if not expected:
            return True
        header = self.headers.get("authorization", "")
        bearer = header[7:].strip() if header.lower().startswith("bearer ") else ""
        direct = self.headers.get("x-lsdf-client-token", "")
        if not all(value.isascii() for value in (expected, bearer, direct)):
            return False
        bearer_matches = _constant_time_token_matches(expected, bearer)
        direct_matches = _constant_time_token_matches(expected, direct)
        return bearer_matches or direct_matches

    def _record_rejection(self, reason: str) -> None:
        if self.gateway_metrics is not None:
            self.gateway_metrics.increment("gateway_request_rejections_total", reason=reason)

    def _send_static_error(
        self,
        status: int,
        error_type: str,
        message: str,
        *,
        not_inspected: bool = False,
    ) -> None:
        self.close_connection = True
        payload: dict[str, Any] = {"error": {"message": message, "type": error_type}}
        if not_inspected:
            payload["error"]["not_inspected"] = True
        self._send_json(status, payload, {"connection": "close"})

    def _send_json(
        self,
        status: int,
        payload: dict[str, Any],
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        body = json.dumps(payload).encode("utf-8")
        self._send_raw(status, body, {"content-type": "application/json"}, extra_headers or {})

    def _send_raw(
        self,
        status: int,
        body: bytes,
        upstream_headers: dict[str, str],
        extra_headers: dict[str, str],
    ) -> None:
        try:
            self.send_response(status)
            content_type = _header_value(upstream_headers, "content-type", "application/json")
            self.send_header("content-type", content_type)
            self.send_header("content-length", str(len(body)))
            for key, value in extra_headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()
        except (TimeoutError, socket.timeout):
            self.close_connection = True
            if self.gateway_metrics is not None:
                self.gateway_metrics.increment("gateway_client_write_timeouts_total", stream=False)
        except (BrokenPipeError, ConnectionResetError, OSError, ValueError):
            self.close_connection = True
            if self.gateway_metrics is not None:
                self.gateway_metrics.increment("gateway_client_disconnects_total", stream=False)

    def _send_iter(
        self,
        status: int,
        body: Iterable[bytes],
        upstream_headers: dict[str, str],
        extra_headers: dict[str, str],
    ) -> None:
        try:
            self.send_response(status)
            content_type = _header_value(upstream_headers, "content-type", "text/event-stream")
            self.send_header("content-type", content_type)
            self.send_header("cache-control", "no-cache")
            for key, value in extra_headers.items():
                self.send_header(key, value)
            self.end_headers()
            for chunk in body:
                self.wfile.write(chunk)
                self.wfile.flush()
        except (TimeoutError, socket.timeout):
            self.close_connection = True
            if self.gateway_metrics is not None:
                self.gateway_metrics.increment("gateway_client_write_timeouts_total", stream=True)
        except (BrokenPipeError, ConnectionResetError, OSError, ValueError):
            self.close_connection = True
            if self.gateway_metrics is not None:
                self.gateway_metrics.increment("gateway_client_disconnects_total", stream=True)
        finally:
            close = getattr(body, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    self.close_connection = True


def _try_parse_json(body: bytes) -> Any:
    try:
        return json.loads(body)
    except (RecursionError, UnicodeDecodeError, ValueError, TypeError):
        return None


def handle_chat_completion(
    payload: Any,
    firewall: Firewall,
    forward,
    *,
    audit_sink: JsonlAuditSink | None = None,
    metrics: MetricsRecorder | None = None,
) -> tuple[int, dict[str, str], bytes, dict[str, str]]:
    metrics = metrics or MetricsRecorder(enabled=False)
    metrics.increment("gateway_requests_total", stream=False)
    try:
        with metrics.time_ms("request_inspection_ms", stream=False):
            request_result = firewall.inspect(payload, unknown_surface="input.messages")
    except Exception as exc:
        return _inspection_failure_response(
            exc, stage="request_preflight", stream=False, audit_sink=audit_sink, metrics=metrics,
        )
    _record_inspection_metrics(metrics, "request_preflight", request_result)
    _write_inspection_audit(
        audit_sink,
        stage="request_preflight",
        stream=False,
        result=request_result,
    )
    if request_result.blocked:
        metrics.increment("gateway_blocks_total", stage="request_preflight")
        return (
            403,
            {"content-type": "application/json"},
            json.dumps(
                {
                    "error": {
                        "message": "Request blocked by LLM Sensitive Data Firewall policy.",
                        "type": "sensitive_data_blocked",
                    },
                    "audit_event": request_result.audit_event,
                }
            ).encode("utf-8"),
            _decision_headers(request_result.blocked, len(request_result.decisions)),
        )

    try:
        with metrics.time_ms("upstream_request_ms", stream=False):
            status, response_headers, response_body = forward(request_result.transformed_payload)
    except UPSTREAM_TRANSPORT_ERRORS:
        metrics.increment("gateway_upstream_errors_total", error_type=UPSTREAM_TRANSPORT_ERROR_TYPE)
        status, response_headers, response_body = _upstream_transport_error_response_bytes()
        return status, response_headers, response_body, _decision_headers(False, 0)
    _record_returned_upstream_transport_error(
        metrics,
        status,
        response_body,
        stream=False,
    )
    response_payload = _try_parse_json(response_body)
    if not isinstance(response_payload, dict):
        _write_gateway_audit(
            audit_sink,
            {
                "source": "gateway",
                "stage": "response_passthrough",
                "stream": False,
                "blocked": False,
                "decision_count": 0,
                "status": status,
            },
        )
        return status, response_headers, response_body, _decision_headers(False, 0)

    try:
        with metrics.time_ms("response_inspection_ms", stream=False, status=status):
            response_result = firewall.inspect(response_payload, unknown_surface="output.content")
    except Exception as exc:
        return _inspection_failure_response(
            exc, stage="response_inspection", stream=False, audit_sink=audit_sink, metrics=metrics,
        )
    _record_inspection_metrics(metrics, "response_inspection", response_result)
    headers = _decision_headers(response_result.blocked, len(response_result.decisions))
    _write_inspection_audit(
        audit_sink,
        stage="response_inspection",
        stream=False,
        result=response_result,
        status=502 if response_result.blocked else status,
    )
    if response_result.blocked:
        metrics.increment("gateway_blocks_total", stage="response_inspection")
        return (
            502,
            {"content-type": "application/json"},
            json.dumps(
                {
                    "error": {
                        "message": "Upstream response blocked by LLM Sensitive Data Firewall policy.",
                        "type": "sensitive_data_blocked",
                    },
                    "audit_event": response_result.audit_event,
                }
            ).encode("utf-8"),
            headers,
        )
    return (
        status,
        response_headers,
        json.dumps(response_result.transformed_payload).encode("utf-8"),
        headers,
    )


def handle_streaming_chat_completion(
    payload: Any,
    firewall: Firewall,
    forward_stream,
    *,
    holdback_chars: int = DEFAULT_STREAM_HOLDBACK_CHARS,
    max_stream_seconds: float = DEFAULT_MAX_STREAM_SECONDS,
    audit_sink: JsonlAuditSink | None = None,
    metrics: MetricsRecorder | None = None,
) -> tuple[int, dict[str, str], Iterable[bytes], dict[str, str]]:
    metrics = metrics or MetricsRecorder(enabled=False)
    metrics.increment("gateway_requests_total", stream=True)
    try:
        with metrics.time_ms("request_inspection_ms", stream=True):
            request_result = firewall.inspect(payload, unknown_surface="input.messages")
    except Exception as exc:
        status, response_headers, body, headers = _inspection_failure_response(
            exc, stage="request_preflight", stream=True, audit_sink=audit_sink, metrics=metrics,
        )
        return status, response_headers, [body], headers
    _record_inspection_metrics(metrics, "request_preflight", request_result)
    _write_inspection_audit(
        audit_sink,
        stage="request_preflight",
        stream=True,
        result=request_result,
    )
    if request_result.blocked:
        metrics.increment("gateway_blocks_total", stage="request_preflight", stream=True)
        return (
            403,
            {"content-type": "application/json"},
            [
                json.dumps(
                    {
                        "error": {
                            "message": "Request blocked by LLM Sensitive Data Firewall policy.",
                            "type": "sensitive_data_blocked",
                        },
                        "audit_event": request_result.audit_event,
                    }
                ).encode("utf-8")
            ],
            _decision_headers(request_result.blocked, len(request_result.decisions)),
        )

    try:
        with metrics.time_ms("upstream_stream_open_ms", stream=True):
            status, response_headers, response_body = forward_stream(
                request_result.transformed_payload
            )
    except UPSTREAM_TRANSPORT_ERRORS:
        metrics.increment("gateway_upstream_errors_total", error_type=UPSTREAM_TRANSPORT_ERROR_TYPE, stream=True)
        status, response_headers, response_body = _upstream_transport_error_response_bytes()
        return status, response_headers, [response_body], _decision_headers(False, 0)
    _record_returned_upstream_transport_error(
        metrics,
        status,
        response_body,
        stream=True,
    )
    headers = _decision_headers(False, 0)
    if "text/event-stream" not in _header_value(response_headers, "content-type", ""):
        try:
            response_bytes = b"".join(response_body)
        except (UPSTREAM_TRANSPORT_ERRORS + (StreamDurationExceeded,)):
            metrics.increment("gateway_upstream_errors_total", error_type=UPSTREAM_TRANSPORT_ERROR_TYPE, stream=True)
            status, response_headers, response_bytes = _upstream_transport_error_response_bytes()
            return status, response_headers, [response_bytes], _decision_headers(False, 0)
        response_payload = _try_parse_json(response_bytes)
        if isinstance(response_payload, dict):
            try:
                with metrics.time_ms("response_inspection_ms", stream=True, status=status):
                    response_result = firewall.inspect(response_payload, unknown_surface="output.content")
            except Exception as exc:
                status, response_headers, body, headers = _inspection_failure_response(
                    exc, stage="stream_response_inspection", stream=True,
                    audit_sink=audit_sink, metrics=metrics,
                )
                return status, response_headers, [body], headers
            _record_inspection_metrics(metrics, "stream_response_inspection", response_result)
            headers = _decision_headers(response_result.blocked, len(response_result.decisions))
            _write_inspection_audit(
                audit_sink,
                stage="stream_response_inspection",
                stream=True,
                result=response_result,
                status=502 if response_result.blocked else status,
            )
            if response_result.blocked:
                metrics.increment("gateway_blocks_total", stage="stream_response_inspection", stream=True)
                return (
                    502,
                    {"content-type": "application/json"},
                    [
                        json.dumps(
                            {
                                "error": {
                                    "message": "Upstream response blocked by LLM Sensitive Data Firewall policy.",
                                    "type": "sensitive_data_blocked",
                                },
                                "audit_event": response_result.audit_event,
                            }
                        ).encode("utf-8")
                    ],
                    headers,
                )
            return (
                status,
                response_headers,
                [json.dumps(response_result.transformed_payload).encode("utf-8")],
                headers,
            )
        _write_gateway_audit(
            audit_sink,
            {
                "source": "gateway",
                "stage": "stream_response_passthrough",
                "stream": True,
                "blocked": False,
                "decision_count": 0,
                "status": status,
            },
        )
        return status, response_headers, [response_bytes], headers
    return (
        status,
        {"content-type": "text/event-stream"},
        _stream_with_duration_limit(
            response_body,
            firewall,
            holdback_chars=holdback_chars,
            max_stream_seconds=max_stream_seconds,
            telemetry_callback=_stream_terminal_callback(audit_sink, metrics),
            metrics=metrics,
        ),
        headers,
    )


def _stream_with_duration_limit(
    response_body: Iterable[bytes],
    firewall: Firewall,
    *,
    holdback_chars: int,
    max_stream_seconds: float,
    telemetry_callback,
    metrics: MetricsRecorder,
) -> Iterable[bytes]:
    """Bound upstream reads and preserve a terminal SSE error after headers."""
    bounded_body = _bounded_stream_chunks(response_body, max_stream_seconds)
    try:
        yield from stream_chat_completion_chunks(
            bounded_body,
            firewall,
            holdback_chars=holdback_chars,
            telemetry_callback=telemetry_callback,
            metrics_recorder=metrics,
        )
    except StreamDurationExceeded:
        if metrics is not None:
            metrics.increment("gateway_stream_timeouts_total", stream=True)
        if telemetry_callback is not None:
            telemetry_callback(
                {
                    "stream_state": "stream_timeout",
                    "blocked": False,
                    "error_type": "stream_timeout",
                }
            )
        yield format_sse_event(
            {
                "error": {
                    "message": "Upstream stream exceeded the configured duration.",
                    "type": "stream_timeout",
                },
                "lsdf": {"stream_state": "stream_timeout", "blocked": False},
            }
        )


def _bounded_stream_chunks(response_body: Iterable[bytes], max_stream_seconds: float) -> Iterable[bytes]:
    deadline = time.monotonic() + max_stream_seconds
    try:
        for chunk in response_body:
            if time.monotonic() >= deadline:
                raise StreamDurationExceeded()
            yield chunk
        if time.monotonic() >= deadline:
            raise StreamDurationExceeded()
    finally:
        close = getattr(response_body, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                pass


def _inspection_failure_response(
    exc: Exception,
    *,
    stage: str,
    stream: bool,
    audit_sink: JsonlAuditSink | None,
    metrics: MetricsRecorder,
) -> tuple[int, dict[str, str], bytes, dict[str, str]]:
    enforcement = isinstance(exc, PolicyEnforcementError)
    error_type = "policy_enforcement_error" if enforcement else "inspection_error"
    status = (403 if stage == "request_preflight" else 502) if enforcement else 500
    metrics.increment(
        "gateway_inspection_errors_total", stage=stage, stream=stream, error_type=error_type,
    )
    metrics.increment("gateway_blocks_total", stage=stage, stream=stream)
    _write_gateway_audit(
        audit_sink,
        {
            "source": "gateway",
            "stage": stage,
            "stream": stream,
            "blocked": True,
            "decision_count": 0,
            "outcome": "inspection_failed",
            "error_type": error_type,
            "status": status,
        },
    )
    message = (
        "Policy enforcement halted inspection."
        if enforcement else "LSDF inspection failed; content was withheld."
    )
    body = json.dumps({"error": {"message": message, "type": error_type}}).encode("utf-8")
    return status, {"content-type": "application/json"}, body, _decision_headers(True, 0)


def _write_inspection_audit(
    audit_sink: JsonlAuditSink | None,
    *,
    stage: str,
    stream: bool,
    result,
    status: int | None = None,
) -> None:
    event: dict[str, Any] = {
        "source": "gateway",
        "stage": stage,
        "stream": stream,
        "blocked": result.blocked,
        "decision_count": len(result.decisions),
        "audit_event": result.audit_event,
    }
    if status is not None:
        event["status"] = status
    _write_gateway_audit(audit_sink, event)


def _stream_terminal_callback(audit_sink: JsonlAuditSink | None, metrics: MetricsRecorder | None):
    if audit_sink is None and metrics is None:
        return None
    def callback(event: dict[str, Any]) -> None:
        if metrics is not None:
            metrics.increment(
                "gateway_stream_terminal_total",
                stream_state=event.get("stream_state", "unknown"),
                blocked=bool(event.get("blocked", False)),
            )
            if event.get("blocked"):
                metrics.increment("gateway_blocks_total", stage="stream_terminal", stream=True)
        _write_gateway_audit(
            audit_sink,
            {
                "source": "gateway",
                "stage": "stream_terminal",
                "stream": True,
                **event,
            },
        )

    return callback


def _record_inspection_metrics(
    metrics: MetricsRecorder,
    stage: str,
    result,
) -> None:
    metrics.increment(
        "inspection_decisions_total",
        len(result.decisions),
        stage=stage,
        blocked=result.blocked,
    )
    for decision in result.decisions:
        finding = decision.finding
        metrics.increment("inspection_action_total", stage=stage, action=decision.action)
        metrics.increment("inspection_entity_total", stage=stage, entity=finding.entity)
        metrics.increment("inspection_surface_total", stage=stage, surface=finding.surface)
        metrics.increment(
            "inspection_detector_family_total",
            stage=stage,
            detector_family=finding.detector_family,
        )


def _write_gateway_audit(
    audit_sink: JsonlAuditSink | None,
    event: dict[str, Any],
) -> None:
    if audit_sink is not None:
        try:
            audit_sink.write(event)
        except Exception as exc:  # pragma: no cover - defensive around external sinks.
            stage = str(event.get("stage", "unknown"))
            print(
                "LSDF audit sink write failed "
                f"stage={stage} error_type={type(exc).__name__}",
                file=sys.stderr,
            )


def _record_returned_upstream_transport_error(
    metrics: MetricsRecorder,
    status: int,
    response_body: Any,
    *,
    stream: bool,
) -> None:
    if status != 502:
        return
    raw_body = _known_body_bytes(response_body)
    if raw_body is None:
        return
    payload = _try_parse_json(raw_body)
    if not isinstance(payload, dict):
        return
    error = payload.get("error")
    if not isinstance(error, dict) or error.get("type") != UPSTREAM_TRANSPORT_ERROR_TYPE:
        return
    labels: dict[str, Any] = {"error_type": UPSTREAM_TRANSPORT_ERROR_TYPE}
    if stream:
        labels["stream"] = True
    metrics.increment("gateway_upstream_errors_total", **labels)


def _known_body_bytes(response_body: Any) -> bytes | None:
    if isinstance(response_body, bytes):
        return response_body
    if isinstance(response_body, bytearray):
        return bytes(response_body)
    if isinstance(response_body, (list, tuple)) and all(
        isinstance(chunk, (bytes, bytearray)) for chunk in response_body
    ):
        return b"".join(bytes(chunk) for chunk in response_body)
    return None


def forward_upstream(
    payload: Any,
    path: str,
    config: GatewayConfig,
) -> tuple[int, dict[str, str], bytes]:
    url = _join_upstream_url(config.upstream_base_url, path)
    headers = {"content-type": "application/json"}
    if config.upstream_api_key:
        headers["authorization"] = f"Bearer {config.upstream_api_key}"
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    deadline = time.monotonic() + config.upstream_timeout_seconds
    try:
        with urllib.request.urlopen(request, timeout=config.upstream_timeout_seconds) as response:
            body = b"".join(
                _iter_response_bytes(
                    response,
                    deadline=deadline,
                    read_timeout=config.upstream_timeout_seconds,
                )
            )
            return response.status, dict(response.headers.items()), body
    except urllib.error.HTTPError as exc:
        try:
            body = b"".join(
                _iter_response_bytes(
                    exc,
                    deadline=deadline,
                    read_timeout=config.upstream_timeout_seconds,
                )
            )
        except (UPSTREAM_TRANSPORT_ERRORS + (StreamDurationExceeded,)):
            return _upstream_transport_error_response_bytes()
        return exc.code, dict(exc.headers.items()), body
    except (UPSTREAM_TRANSPORT_ERRORS + (StreamDurationExceeded,)):
        return _upstream_transport_error_response_bytes()


def forward_upstream_stream(
    payload: Any,
    path: str,
    config: GatewayConfig,
) -> tuple[int, dict[str, str], Iterable[bytes]]:
    url = _join_upstream_url(config.upstream_base_url, path)
    headers = {"content-type": "application/json", "accept": "text/event-stream"}
    if config.upstream_api_key:
        headers["authorization"] = f"Bearer {config.upstream_api_key}"
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    deadline = time.monotonic() + config.max_stream_seconds
    try:
        response = urllib.request.urlopen(
            request,
            timeout=min(config.upstream_timeout_seconds, config.max_stream_seconds),
        )
    except urllib.error.HTTPError as exc:
        try:
            body = b"".join(
                _iter_response_bytes(
                    exc,
                    deadline=deadline,
                    read_timeout=config.upstream_timeout_seconds,
                )
            )
        except (UPSTREAM_TRANSPORT_ERRORS + (StreamDurationExceeded,)):
            status, headers, transport_body = _upstream_transport_error_response_bytes()
            return status, headers, [transport_body]
        return exc.code, dict(exc.headers.items()), [body]
    except UPSTREAM_TRANSPORT_ERRORS:
        status, headers, body = _upstream_transport_error_response_bytes()
        return status, headers, [body]
    response_headers = dict(response.headers.items())
    return response.status, response_headers, _iter_response_bytes(
        response,
        deadline=deadline,
        read_timeout=config.upstream_timeout_seconds,
    )


def _iter_response_bytes(
    response,
    *,
    deadline: float | None = None,
    read_timeout: float | None = None,
) -> Iterable[bytes]:
    try:
        while True:
            timeout = read_timeout
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise StreamDurationExceeded()
                deadline_limited = read_timeout is None or remaining <= read_timeout
                timeout = remaining if timeout is None else min(timeout, remaining)
            else:
                deadline_limited = False
            if timeout is not None:
                _set_response_socket_timeout(response, timeout)
            read_once = getattr(response, "read1", None) or response.read
            try:
                chunk = read_once(4096)
            except (socket.timeout, TimeoutError):
                if deadline_limited:
                    raise StreamDurationExceeded() from None
                raise
            if not chunk:
                break
            yield chunk
    finally:
        try:
            response.close()
        except Exception:
            pass


def _set_response_socket_timeout(response, timeout: float) -> None:
    fp = getattr(response, "fp", None)
    candidates = (
        fp,
        getattr(fp, "fp", None),
        getattr(fp, "raw", None),
        getattr(getattr(fp, "fp", None), "raw", None),
    )
    for candidate in candidates:
        raw = getattr(candidate, "raw", candidate)
        sock = getattr(raw, "_sock", None)
        setter = getattr(sock, "settimeout", None)
        if callable(setter):
            setter(max(timeout, 0.001))
            return


def _upstream_transport_error_response_bytes() -> tuple[int, dict[str, str], bytes]:
    return (
        502,
        {"content-type": "application/json"},
        json.dumps(
            {
                "error": {
                    "message": "Upstream transport error.",
                    "type": UPSTREAM_TRANSPORT_ERROR_TYPE,
                }
            }
        ).encode("utf-8"),
    )


def _decision_headers(blocked: bool, decision_count: int) -> dict[str, str]:
    return {
        "x-lsdf-blocked": str(blocked).lower(),
        "x-lsdf-decision-count": str(decision_count),
    }


def _header_value(headers: dict[str, str], name: str, default: str) -> str:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return default


def _is_streaming_request(payload: Any) -> bool:
    return isinstance(payload, dict) and payload.get("stream") is True


def _constant_time_token_matches(expected: str, candidate: str) -> bool:
    try:
        expected_bytes = expected.encode("ascii")
        candidate_bytes = candidate.encode("ascii")
    except UnicodeEncodeError:
        return False
    return hmac.compare_digest(expected_bytes, candidate_bytes)


_UNSUPPORTED_MEDIA_BLOCK_TYPES = frozenset(
    {
        "image_url",
        "image",
        "input_image",
        "audio",
        "input_audio",
        "file",
        "input_file",
        "video",
        "input_video",
    }
)
_UNSUPPORTED_TOP_LEVEL_FIELDS = frozenset(
    {
        "audio",
        "attachments",
        "files",
        "input",
        "input_audio",
        "input_file",
        "previous_response_id",
        "conversation",
    }
)
_UNSUPPORTED_MESSAGE_FIELDS = frozenset(
    {
        "audio",
        "attachments",
        "file",
        "files",
        "images",
    }
)


def _validate_supported_chat_payload(payload: Any) -> None:
    """Reject request forms that LSDF cannot inspect before upstream forwarding."""
    if not isinstance(payload, dict):
        raise GatewayRequestError(400, "invalid_request", "Request JSON must be an object.")

    unsupported_fields = _UNSUPPORTED_TOP_LEVEL_FIELDS.intersection(payload)
    if unsupported_fields:
        raise UnsupportedContentError("Request content or state is not inspected by LSDF.")

    messages = payload.get("messages")
    if messages is not None:
        if not isinstance(messages, list):
            raise GatewayRequestError(400, "invalid_request", "messages must be an array.")
        for message in messages:
            if not isinstance(message, dict):
                raise GatewayRequestError(400, "invalid_request", "messages entries must be objects.")
            if _UNSUPPORTED_MESSAGE_FIELDS.intersection(message):
                raise UnsupportedContentError("Message content or attachments are not inspected by LSDF.")
            if "content" in message:
                _validate_message_content(message["content"])
            if "tool_calls" in message:
                _validate_tool_calls(message["tool_calls"])

    if "tools" in payload:
        tools = payload["tools"]
        if not isinstance(tools, list):
            raise GatewayRequestError(400, "invalid_request", "tools must be an array.")
        for tool in tools:
            if not isinstance(tool, dict):
                raise GatewayRequestError(400, "invalid_request", "tools entries must be objects.")
            if tool.get("type") != "function":
                raise UnsupportedContentError("Hosted tool types are not inspected by LSDF.")
            if not isinstance(tool.get("function"), dict):
                raise GatewayRequestError(400, "invalid_request", "Function tools require a function object.")

    if "functions" in payload:
        functions = payload["functions"]
        if not isinstance(functions, list) or any(not isinstance(item, dict) for item in functions):
            raise GatewayRequestError(400, "invalid_request", "functions must be an array of objects.")

    tool_choice = payload.get("tool_choice")
    if isinstance(tool_choice, dict):
        if tool_choice.get("type") != "function":
            raise UnsupportedContentError("Hosted tool choices are not inspected by LSDF.")
        if not isinstance(tool_choice.get("function"), dict):
            raise GatewayRequestError(400, "invalid_request", "Function tool choices require a function object.")

    modalities = payload.get("modalities")
    if isinstance(modalities, list) and any(item == "audio" for item in modalities):
        raise UnsupportedContentError("Audio input or output is not inspected by LSDF.")


def _validate_message_content(content: Any) -> None:
    if isinstance(content, str) or content is None:
        return
    if not isinstance(content, list):
        raise UnsupportedContentError("Non-text message content is not inspected by LSDF.")
    for block in content:
        if not isinstance(block, dict):
            raise UnsupportedContentError("Non-text message content is not inspected by LSDF.")
        block_type = block.get("type")
        if any(
            key in block
            for key in ("image_url", "audio_url", "file_id", "file_data", "audio", "image", "file")
        ):
            raise UnsupportedContentError("Image, audio, and file content is not inspected by LSDF.")
        if block_type == "text":
            if not isinstance(block.get("text"), str):
                raise GatewayRequestError(400, "invalid_request", "Text content blocks require text.")
            continue
        if block_type in _UNSUPPORTED_MEDIA_BLOCK_TYPES:
            raise UnsupportedContentError("Image, audio, and file content is not inspected by LSDF.")
        raise UnsupportedContentError("Message content block is not inspected by LSDF.")


def _validate_tool_calls(tool_calls: Any) -> None:
    if not isinstance(tool_calls, list):
        raise GatewayRequestError(400, "invalid_request", "tool_calls must be an array.")
    for call in tool_calls:
        if not isinstance(call, dict):
            raise GatewayRequestError(400, "invalid_request", "tool_calls entries must be objects.")
        if call.get("type") not in (None, "function"):
            raise UnsupportedContentError("Hosted tool calls are not inspected by LSDF.")
        function = call.get("function")
        if function is not None and not isinstance(function, dict):
            raise GatewayRequestError(400, "invalid_request", "Function tool calls require a function object.")


def _join_upstream_url(base_url: str, path: str) -> str:
    base = base_url.rstrip("/")
    request_path = path if path.startswith("/") else f"/{path}"
    if base.endswith("/v1") and request_path.startswith("/v1/"):
        request_path = request_path[len("/v1") :]
    return f"{base}{request_path}"


def _resolve_stream_holdback_chars(env: dict[str, str]) -> int:
    raw_value = env.get("LSDF_STREAM_HOLDBACK_CHARS")
    if raw_value is None or raw_value == "":
        return DEFAULT_STREAM_HOLDBACK_CHARS
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise GatewayConfigError("LSDF_STREAM_HOLDBACK_CHARS must be an integer") from exc
    if value < 0:
        raise GatewayConfigError("LSDF_STREAM_HOLDBACK_CHARS must be non-negative")
    return value


def _resolve_ascii_token(env: dict[str, str], name: str) -> str | None:
    raw = env.get(name)
    if raw is None or raw == "":
        return None
    if not raw.isascii() or any(ord(char) < 0x20 or ord(char) == 0x7F for char in raw):
        raise GatewayConfigError(f"{name} must contain printable ASCII characters")
    return raw


def _resolve_positive_int(env: dict[str, str], name: str, default: int) -> int:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw, 10)
    except (TypeError, ValueError) as exc:
        raise GatewayConfigError(f"{name} must be a positive integer") from exc
    if value <= 0:
        raise GatewayConfigError(f"{name} must be a positive integer")
    return value


def _resolve_positive_float(env: dict[str, str], name: str, default: float) -> float:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise GatewayConfigError(f"{name} must be a positive finite number") from exc
    if not math.isfinite(value) or value <= 0:
        raise GatewayConfigError(f"{name} must be a positive finite number")
    return value


def _resolve_bool(env: dict[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    lowered = raw.lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    raise GatewayConfigError(f"{name} must be true or false")


def _resolve_int(env: dict[str, str], name: str, default: int) -> int:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise GatewayConfigError(f"{name} must be an integer") from exc


def _resolve_optional_int(env: dict[str, str], name: str) -> int | None:
    raw = env.get(name)
    if raw is None or raw == "":
        return None
    try:
        value = int(raw)
    except ValueError as exc:
        raise GatewayConfigError(f"{name} must be an integer") from exc
    if value < 1:
        raise GatewayConfigError(f"{name} must be positive")
    return value


def _split_env_list(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _build_gateway_vault(config: GatewayConfig) -> EncryptedSqliteTokenVault | None:
    if config.tokenization_mode == "irreversible":
        return None
    if not config.vault_path or not config.vault_key:
        raise GatewayConfigError("Vault mode requires LSDF_VAULT_PATH and LSDF_VAULT_KEY")
    return EncryptedSqliteTokenVault(config.vault_path, config.vault_key)


def _check_upstream_health(upstream_base_url: str, timeout_ms: int) -> dict[str, Any]:
    try:
        request = urllib.request.Request(upstream_base_url, method="GET")
        with urllib.request.urlopen(request, timeout=max(timeout_ms, 1) / 1000) as response:
            return {"status": "ok", "http_status": response.status}
    except urllib.error.HTTPError as exc:
        try:
            return {
                "status": "warning",
                "http_status": exc.code,
                "message": "reachable with non-2xx response",
            }
        finally:
            try:
                exc.close()
            except Exception:
                pass
    except UPSTREAM_TRANSPORT_ERRORS:
        return {"status": "error", "error_type": UPSTREAM_TRANSPORT_ERROR_TYPE}
