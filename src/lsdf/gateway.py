# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import http.client
import hmac
import json
import os
import sys
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
from .policy import load_effective_policy, load_policy, load_policy_profile
from .security_ops import verify_policy_signature
from .streaming import DEFAULT_STREAM_HOLDBACK_CHARS, stream_chat_completion_chunks
from .vault import EncryptedSqliteTokenVault

UPSTREAM_TRANSPORT_ERROR_TYPE = "upstream_transport_error"
UPSTREAM_TRANSPORT_ERRORS = (
    urllib.error.URLError,
    TimeoutError,
    OSError,
    http.client.HTTPException,
)


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


class GatewayConfigError(ValueError):
    pass


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
        management_token=env.get("LSDF_MANAGEMENT_TOKEN") or None,
    )


def serve_gateway(
    host: str = "127.0.0.1",
    port: int = 8080,
    config: GatewayConfig | None = None,
) -> None:
    config = config or resolve_gateway_config()
    if config.require_policy_signature and config.policy_path:
        try:
            verification = verify_policy_signature(
                Path(config.policy_path),
                public_key_path=Path(config.policy_public_key) if config.policy_public_key else None,
            )
        except Exception as exc:
            raise GatewayConfigError(
                f"Custom policy signature verification failed: {type(exc).__name__}"
            ) from exc
        if not verification["valid"]:
            raise GatewayConfigError("Custom policy signature verification failed")
    policy = (
        load_policy(config.policy_path)
        if config.policy_path
        else load_effective_policy(config.policy_profile, domain_packs=config.domain_packs)
    )
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

    server = ThreadingHTTPServer((host, port), Handler)
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
        try:
            payload = self._read_json()
        except ValueError as exc:
            self._send_json(400, {"error": {"message": str(exc), "type": "invalid_request"}})
            return

        if _is_streaming_request(payload):
            status, response_headers, body, headers = handle_streaming_chat_completion(
                payload,
                self.gateway_firewall,
                self._forward_stream,
                holdback_chars=self.gateway_config.stream_holdback_chars,
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
            "domain_packs": list(self.gateway_config.domain_packs),
            "management": {
                "enabled": self.gateway_config.management_enabled,
                "auth_required": bool(self.gateway_config.management_token),
            },
        }

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _read_json(self) -> Any:
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON body: {exc}") from exc

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
        return hmac.compare_digest(expected, bearer) or hmac.compare_digest(expected, direct)

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
        self.send_response(status)
        content_type = _header_value(upstream_headers, "content-type", "application/json")
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        for key, value in extra_headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_iter(
        self,
        status: int,
        body: Iterable[bytes],
        upstream_headers: dict[str, str],
        extra_headers: dict[str, str],
    ) -> None:
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


def _try_parse_json(body: bytes) -> Any:
    try:
        return json.loads(body)
    except json.JSONDecodeError:
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
    with metrics.time_ms("request_inspection_ms", stream=False):
        request_result = firewall.inspect(payload, unknown_surface="input.messages")
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

    with metrics.time_ms("response_inspection_ms", stream=False, status=status):
        response_result = firewall.inspect(response_payload, unknown_surface="output.content")
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
    audit_sink: JsonlAuditSink | None = None,
    metrics: MetricsRecorder | None = None,
) -> tuple[int, dict[str, str], Iterable[bytes], dict[str, str]]:
    metrics = metrics or MetricsRecorder(enabled=False)
    metrics.increment("gateway_requests_total", stream=True)
    with metrics.time_ms("request_inspection_ms", stream=True):
        request_result = firewall.inspect(payload, unknown_surface="input.messages")
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
        response_bytes = b"".join(response_body)
        response_payload = _try_parse_json(response_bytes)
        if isinstance(response_payload, dict):
            with metrics.time_ms("response_inspection_ms", stream=True, status=status):
                response_result = firewall.inspect(response_payload, unknown_surface="output.content")
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
        stream_chat_completion_chunks(
            response_body,
            firewall,
            holdback_chars=holdback_chars,
            telemetry_callback=_stream_terminal_callback(audit_sink, metrics),
            metrics_recorder=metrics,
        ),
        headers,
    )


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
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            return response.status, dict(response.headers.items()), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers.items()), exc.read()
    except UPSTREAM_TRANSPORT_ERRORS:
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
    try:
        response = urllib.request.urlopen(request, timeout=120)
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers.items()), [exc.read()]
    except UPSTREAM_TRANSPORT_ERRORS:
        status, headers, body = _upstream_transport_error_response_bytes()
        return status, headers, [body]
    response_headers = dict(response.headers.items())
    return response.status, response_headers, _iter_response_bytes(response)


def _iter_response_bytes(response) -> Iterable[bytes]:
    try:
        while True:
            chunk = response.read(4096)
            if not chunk:
                break
            yield chunk
    finally:
        response.close()


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
            return {"status": "ok", "http_status": response.status, "url": upstream_base_url}
    except urllib.error.HTTPError as exc:
        return {
            "status": "warning",
            "http_status": exc.code,
            "url": upstream_base_url,
            "message": "reachable with non-2xx response",
        }
    except UPSTREAM_TRANSPORT_ERRORS as exc:
        return {
            "status": "error",
            "url": upstream_base_url,
            "error_type": type(exc).__name__,
        }
