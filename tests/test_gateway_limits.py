import http.client
import json
import queue
import socket
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from lsdf import Firewall, load_policy
from lsdf.gateway import (
    GatewayConfig,
    GatewayConfigError,
    LSDFGatewayHandler,
    LSDFGatewayServer,
    resolve_gateway_config,
)
from lsdf.metrics import MetricsRecorder


class _GatewayFixture:
    def __init__(
        self,
        config: GatewayConfig,
        *,
        max_concurrent_requests: int | None = None,
        block_forward: bool = False,
        use_default_forward: bool = False,
    ):
        self.config = config
        self.forwarded: list[dict] = []
        self.forward_entered = threading.Event()
        self.forward_release = threading.Event()
        self.use_default_forward = use_default_forward
        self.metrics = MetricsRecorder(enabled=True)
        if not block_forward:
            self.forward_release.set()
        fixture = self

        class Handler(LSDFGatewayHandler):
            gateway_config = fixture.config
            gateway_firewall = Firewall(load_policy("policies/default.yaml"))
            gateway_metrics = fixture.metrics

            def _forward(self, payload):
                if fixture.use_default_forward:
                    return super()._forward(payload)
                fixture.forwarded.append(payload)
                fixture.forward_entered.set()
                if not fixture.forward_release.is_set():
                    fixture.forward_release.wait(3)
                return 200, {"content-type": "application/json"}, b'{"choices":[]}'

            def _forward_stream(self, payload):
                if fixture.use_default_forward:
                    return super()._forward_stream(payload)
                fixture.forwarded.append(payload)
                fixture.forward_entered.set()
                if not fixture.forward_release.is_set():
                    fixture.forward_release.wait(3)
                return 200, {"content-type": "text/event-stream"}, [b"data: [DONE]\n\n"]

        self.handler = Handler
        self.server = LSDFGatewayServer(
            ("127.0.0.1", 0),
            Handler,
            max_concurrent_requests=max_concurrent_requests or config.max_concurrent_requests,
            metrics=self.metrics,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def address(self):
        return self.server.server_address

    def stop(self):
        self.forward_release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


def _post(address, payload, headers=None, timeout=3):
    conn = http.client.HTTPConnection(*address, timeout=timeout)
    try:
        request_headers = {"content-type": "application/json"}
        if headers:
            request_headers.update(headers)
        conn.request("POST", "/v1/chat/completions", json.dumps(payload), request_headers)
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        conn.close()


def _post_empty(address, timeout=3):
    conn = http.client.HTTPConnection(*address, timeout=timeout)
    try:
        conn.putrequest("POST", "/v1/chat/completions")
        conn.putheader("content-type", "application/json")
        conn.putheader("content-length", "0")
        conn.endheaders()
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        conn.close()


class GatewayConfigLimitTests(unittest.TestCase):
    def test_defaults_are_bounded_and_values_are_positive_finite(self):
        config = resolve_gateway_config(
            upstream_base_url="http://127.0.0.1:1",
            environ={},
        )
        self.assertEqual(config.max_request_bytes, 8 * 1024 * 1024)
        self.assertEqual(config.max_concurrent_requests, 8)
        self.assertEqual(config.client_timeout_seconds, 15.0)
        self.assertEqual(config.upstream_timeout_seconds, 120.0)
        self.assertEqual(config.max_stream_seconds, 300.0)

        for name, value in (
            ("LSDF_MAX_REQUEST_BYTES", "0"),
            ("LSDF_MAX_CONCURRENT_REQUESTS", "false"),
            ("LSDF_CLIENT_TIMEOUT_SECONDS", "nan"),
            ("LSDF_UPSTREAM_TIMEOUT_SECONDS", "inf"),
            ("LSDF_MAX_STREAM_SECONDS", "True"),
        ):
            with self.subTest(name=name):
                with self.assertRaises(GatewayConfigError):
                    resolve_gateway_config(
                        upstream_base_url="http://127.0.0.1:1",
                        environ={name: value},
                    )

    def test_management_and_client_tokens_are_independent_and_ascii_validated(self):
        config = resolve_gateway_config(
            upstream_base_url="http://127.0.0.1:1",
            environ={
                "LSDF_MANAGEMENT_TOKEN": "management-only",
                "LSDF_CLIENT_TOKEN": "client-only",
            },
        )
        self.assertEqual(config.management_token, "management-only")
        self.assertEqual(config.client_token, "client-only")
        with self.assertRaises(GatewayConfigError):
            resolve_gateway_config(
                upstream_base_url="http://127.0.0.1:1",
                environ={"LSDF_MANAGEMENT_TOKEN": "né"},
            )

    def test_request_size_auth_and_unsupported_content_fail_before_forward(self):
        config = GatewayConfig(
            None,
            "default",
            "http://127.0.0.1:1",
            client_token="client-only",
            management_token="management-only",
            max_request_bytes=512,
        )
        fixture = _GatewayFixture(config)
        try:
            payload = {"messages": [{"role": "user", "content": "hello"}]}
            status, _headers, body = _post(fixture.address, payload)
            self.assertEqual(status, 401)
            self.assertEqual(json.loads(body)["error"]["type"], "client_unauthorized")

            status, _headers, body = _post(
                fixture.address,
                payload,
                headers={"X-LSDF-Management-Token": "management-only"},
            )
            self.assertEqual(status, 401)
            self.assertEqual(json.loads(body)["error"]["type"], "client_unauthorized")
            self.assertEqual(fixture.forwarded, [])

            status, _headers, body = _post(
                fixture.address,
                {"messages": [{"role": "user", "content": "x" * 800}]},
                headers={"X-LSDF-Client-Token": "client-only"},
            )
            self.assertEqual(status, 413)
            self.assertEqual(json.loads(body)["error"]["type"], "request_too_large")
            self.assertEqual(fixture.forwarded, [])

            status, _headers, body = _post(
                fixture.address,
                {
                    "messages": [
                        {
                            "role": "user",
                            "content": [{"type": "image_url", "image_url": {"url": "opaque-media"}}],
                        }
                    ]
                },
                headers={"Authorization": "Bearer client-only"},
            )
            self.assertEqual(status, 400)
            error = json.loads(body)["error"]
            self.assertEqual(error["type"], "unsupported_content")
            self.assertTrue(error["not_inspected"])
            self.assertEqual(fixture.forwarded, [])

            status, _headers, body = _post(
                fixture.address,
                {
                    "messages": [{"role": "user", "content": "hello"}],
                    "audio": {"format": "wav"},
                },
                headers={"Authorization": "Bearer client-only"},
            )
            self.assertEqual(status, 400)
            self.assertEqual(json.loads(body)["error"]["type"], "unsupported_content")
            self.assertEqual(fixture.forwarded, [])

            status, _headers, body = _post(
                fixture.address,
                {
                    "messages": [
                        {
                            "role": "user",
                            "content": [
                                {"type": "text", "text": "hello", "audio_url": "opaque-media"}
                            ],
                        }
                    ]
                },
                headers={"Authorization": "Bearer client-only"},
            )
            self.assertEqual(status, 400)
            self.assertEqual(json.loads(body)["error"]["type"], "unsupported_content")
            self.assertEqual(fixture.forwarded, [])

            status, _headers, _body = _post(
                fixture.address,
                {
                    "messages": [{"role": "user", "content": "hello"}],
                    "tools": [{"type": "function", "function": {"name": "lookup"}}],
                    "metadata": {"caller": "test"},
                },
                headers={"Authorization": "Bearer client-only"},
            )
            self.assertEqual(status, 200)
            self.assertEqual(len(fixture.forwarded), 1)
            counters = fixture.metrics.to_dict()["counters"]
            self.assertEqual(counters["gateway_request_rejections_total{reason=client_auth}"], 2)
            self.assertEqual(counters["gateway_request_rejections_total{reason=request_too_large}"], 1)
            self.assertEqual(counters["gateway_request_rejections_total{reason=unsupported_content}"], 3)
        finally:
            fixture.stop()


class GatewayRuntimeLimitTests(unittest.TestCase):
    def test_trickled_client_body_hits_absolute_deadline(self):
        config = GatewayConfig(
            None,
            "default",
            "http://127.0.0.1:1",
            client_timeout_seconds=0.08,
        )
        fixture = _GatewayFixture(config)
        body = b'{"messages":[{"role":"user","content":"hello"}]}'
        raw_response = bytearray()
        client = socket.create_connection(fixture.address, timeout=2)
        try:
            client.sendall(
                (
                    f"POST /v1/chat/completions HTTP/1.1\r\n"
                    f"Host: {fixture.address[0]}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii") + body[:1]
            )
            for byte in body[1:]:
                time.sleep(0.01)
                try:
                    client.sendall(bytes((byte,)))
                except OSError:
                    break
            while True:
                try:
                    chunk = client.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                raw_response.extend(chunk)
        finally:
            client.close()
            fixture.stop()

        self.assertIn(b"400 Bad Request", raw_response)
        self.assertIn(b"invalid_request", raw_response)
        self.assertEqual(fixture.forwarded, [])

    def test_trickled_request_headers_hit_absolute_deadline(self):
        config = GatewayConfig(
            None,
            "default",
            "http://127.0.0.1:1",
            client_timeout_seconds=0.08,
        )
        fixture = _GatewayFixture(config)
        client = socket.create_connection(fixture.address, timeout=2)
        raw_response = bytearray()
        try:
            client.sendall(
                (
                    f"POST /v1/chat/completions HTTP/1.1\r\n"
                    f"Host: {fixture.address[0]}\r\n"
                    "X-Slow: "
                ).encode("ascii")
            )
            for byte in b"header-value\r\n\r\n":
                time.sleep(0.03)
                try:
                    client.sendall(bytes((byte,)))
                except OSError:
                    break
            client.settimeout(2)
            while True:
                try:
                    chunk = client.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                raw_response.extend(chunk)
        finally:
            client.close()
            fixture.stop()

        self.assertIn(b"400 Bad Request", raw_response)
        self.assertIn(b"invalid_request", raw_response)
        self.assertEqual(fixture.forwarded, [])

    def test_recursion_error_in_json_is_static_bad_request(self):
        fixture = _GatewayFixture(GatewayConfig(None, "default", "http://127.0.0.1:1"))
        body = ("[" * 1100) + ("]" * 1100)
        try:
            conn = http.client.HTTPConnection(*fixture.address, timeout=3)
            try:
                conn.request(
                    "POST",
                    "/v1/chat/completions",
                    body,
                    {"content-type": "application/json"},
                )
                response = conn.getresponse()
                response_body = response.read()
            finally:
                conn.close()
            self.assertEqual(response.status, 400)
            self.assertEqual(json.loads(response_body)["error"]["type"], "invalid_request")
            self.assertEqual(fixture.forwarded, [])
        finally:
            fixture.stop()

    def test_invalid_json_encoding_and_integer_limit_are_static_bad_requests(self):
        fixture = _GatewayFixture(GatewayConfig(None, "default", "http://127.0.0.1:1"))
        bodies = (b"\xff", b'{"n":' + (b"9" * 5000) + b"}")
        try:
            for body in bodies:
                conn = http.client.HTTPConnection(*fixture.address, timeout=3)
                try:
                    conn.request(
                        "POST",
                        "/v1/chat/completions",
                        body,
                        {"content-type": "application/json"},
                    )
                    response = conn.getresponse()
                    response_body = response.read()
                finally:
                    conn.close()
                self.assertEqual(response.status, 400)
                self.assertEqual(json.loads(response_body)["error"]["type"], "invalid_request")
            self.assertEqual(fixture.forwarded, [])
        finally:
            fixture.stop()

    def test_malformed_http_request_does_not_echo_parser_input(self):
        fixture = _GatewayFixture(GatewayConfig(None, "default", "http://127.0.0.1:1"))
        secret = b"R3d1s_Pr0d_2024!Secure"
        client = socket.create_connection(fixture.address, timeout=2)
        raw_response = bytearray()
        try:
            client.sendall(
                b"GET /v1/chat/completions HTTP/1.1 " + secret + b"\r\n"
                + f"Host: {fixture.address[0]}\r\n\r\n".encode("ascii")
            )
            client.settimeout(2)
            while True:
                try:
                    chunk = client.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                raw_response.extend(chunk)
        finally:
            client.close()
            fixture.stop()

        self.assertIn(b"400 Bad Request", raw_response)
        self.assertIn(b"invalid_request", raw_response)
        self.assertNotIn(secret, raw_response)
        self.assertEqual(fixture.forwarded, [])

    def test_trickled_upstream_stream_hits_absolute_deadline(self):
        entered = threading.Event()

        class TrickleUpstream(BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
                self.end_headers()
                entered.set()
                event = b'data: {"choices":[{"delta":{"content":"trickle"}}]}\n\n'
                try:
                    for byte in event:
                        self.wfile.write(bytes((byte,)))
                        self.wfile.flush()
                        time.sleep(0.02)
                    self.wfile.write(b"data: [DONE]\n\n")
                    self.wfile.flush()
                except OSError:
                    return

            def log_message(self, format, *args):
                return

        upstream = ThreadingHTTPServer(("127.0.0.1", 0), TrickleUpstream)
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        fixture = _GatewayFixture(
            GatewayConfig(
                None,
                "default",
                f"http://127.0.0.1:{upstream.server_address[1]}",
                upstream_timeout_seconds=1,
                max_stream_seconds=0.15,
                client_timeout_seconds=2,
            ),
            use_default_forward=True,
        )
        try:
            conn = http.client.HTTPConnection(*fixture.address, timeout=3)
            try:
                conn.request(
                    "POST",
                    "/v1/chat/completions",
                    json.dumps({"stream": True, "messages": [{"role": "user", "content": "hello"}]}),
                    {"content-type": "application/json"},
                )
                self.assertTrue(entered.wait(2))
                response = conn.getresponse()
                body = response.read().decode("utf-8")
            finally:
                conn.close()
            self.assertEqual(response.status, 200)
            self.assertIn('"type":"stream_timeout"', body)
            self.assertNotIn("trickle", body)
        finally:
            fixture.stop()
            upstream.shutdown()
            upstream.server_close()
            upstream_thread.join(timeout=3)

    def test_upstream_timeout_is_safe_over_real_http(self):
        entered = threading.Event()
        release = threading.Event()

        class SlowUpstream(BaseHTTPRequestHandler):
            def do_POST(self):
                entered.set()
                release.wait(3)
                try:
                    self.send_response(200)
                    self.send_header("content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"choices":[]}')
                except OSError:
                    return

            def log_message(self, format, *args):
                return

        upstream = ThreadingHTTPServer(("127.0.0.1", 0), SlowUpstream)
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        fixture = _GatewayFixture(
            GatewayConfig(
                None,
                "default",
                f"http://127.0.0.1:{upstream.server_address[1]}",
                upstream_timeout_seconds=0.1,
                client_timeout_seconds=2,
            ),
            use_default_forward=True,
        )
        try:
            conn = http.client.HTTPConnection(*fixture.address, timeout=3)
            try:
                conn.request(
                    "POST",
                    "/v1/chat/completions",
                    json.dumps({"messages": [{"role": "user", "content": "hello"}]}),
                    {"content-type": "application/json"},
                )
                self.assertTrue(entered.wait(2))
                response = conn.getresponse()
                body = response.read()
            finally:
                conn.close()
            self.assertEqual(response.status, 502)
            self.assertEqual(json.loads(body)["error"]["type"], "upstream_transport_error")
            self.assertNotIn("timed out", body.decode("utf-8"))
            self.assertEqual(
                fixture.metrics.to_dict()["counters"][
                    "gateway_upstream_errors_total{error_type=upstream_transport_error}"
                ],
                1,
            )
        finally:
            release.set()
            fixture.stop()
            upstream.shutdown()
            upstream.server_close()
            upstream_thread.join(timeout=3)

    def test_trickled_http_error_bodies_are_deadline_bounded_for_both_paths(self):
        entered = threading.Event()
        error_body = b'{"error":"upstream fixture body ' + (b"x" * 128) + b'"}'

        class SlowErrorUpstream(BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(429)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(error_body)))
                self.end_headers()
                entered.set()
                try:
                    for byte in error_body:
                        self.wfile.write(bytes((byte,)))
                        self.wfile.flush()
                        time.sleep(0.02)
                except OSError:
                    return

            def log_message(self, format, *args):
                return

        upstream = ThreadingHTTPServer(("127.0.0.1", 0), SlowErrorUpstream)
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        fixture = _GatewayFixture(
            GatewayConfig(
                None,
                "default",
                f"http://127.0.0.1:{upstream.server_address[1]}",
                upstream_timeout_seconds=0.1,
                max_stream_seconds=0.1,
                client_timeout_seconds=2,
            ),
            use_default_forward=True,
        )
        try:
            for stream in (False, True):
                entered.clear()
                conn = http.client.HTTPConnection(*fixture.address, timeout=3)
                try:
                    conn.request(
                        "POST",
                        "/v1/chat/completions",
                        json.dumps(
                            {
                                "stream": stream,
                                "messages": [{"role": "user", "content": "hello"}],
                            }
                        ),
                        {"content-type": "application/json"},
                    )
                    self.assertTrue(entered.wait(2))
                    response = conn.getresponse()
                    body = response.read()
                finally:
                    conn.close()
                self.assertEqual(response.status, 502)
                self.assertEqual(json.loads(body)["error"]["type"], "upstream_transport_error")
                self.assertNotIn(b"upstream fixture body", body)
            counters = fixture.metrics.to_dict()["counters"]
            self.assertEqual(
                counters["gateway_upstream_errors_total{error_type=upstream_transport_error}"],
                1,
            )
            self.assertEqual(
                counters["gateway_upstream_errors_total{error_type=upstream_transport_error,stream=True}"],
                1,
            )
        finally:
            fixture.stop()
            upstream.shutdown()
            upstream.server_close()
            upstream_thread.join(timeout=3)

    def test_stalled_stream_http_error_uses_stream_deadline(self):
        entered = threading.Event()
        release = threading.Event()

        class StalledErrorUpstream(BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(429)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", "32")
                self.end_headers()
                entered.set()
                release.wait(5)

            def log_message(self, format, *args):
                return

        upstream = ThreadingHTTPServer(("127.0.0.1", 0), StalledErrorUpstream)
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        fixture = _GatewayFixture(
            GatewayConfig(
                None,
                "default",
                f"http://127.0.0.1:{upstream.server_address[1]}",
                upstream_timeout_seconds=5,
                max_stream_seconds=0.1,
                client_timeout_seconds=2,
            ),
            use_default_forward=True,
        )
        try:
            conn = http.client.HTTPConnection(*fixture.address, timeout=2)
            try:
                conn.request(
                    "POST",
                    "/v1/chat/completions",
                    json.dumps(
                        {
                            "stream": True,
                            "messages": [{"role": "user", "content": "hello"}],
                        }
                    ),
                    {"content-type": "application/json"},
                )
                self.assertTrue(entered.wait(2))
                response = conn.getresponse()
                body = response.read()
            finally:
                conn.close()
            self.assertEqual(response.status, 502)
            self.assertEqual(json.loads(body)["error"]["type"], "upstream_transport_error")
        finally:
            release.set()
            fixture.stop()
            upstream.shutdown()
            upstream.server_close()
            upstream_thread.join(timeout=3)

    def test_immediate_client_disconnect_closes_upstream_iterator(self):
        config = GatewayConfig(
            None,
            "default",
            "http://127.0.0.1:1",
            max_stream_seconds=2,
            client_timeout_seconds=2,
        )
        metrics = MetricsRecorder(enabled=True)
        entered = threading.Event()
        closed = threading.Event()

        class UpstreamBody:
            def __iter__(self):
                entered.set()
                chunk = b'data: {"choices":[{"delta":{"content":"' + (b"x" * 8192) + b'"}}]}\n\n'
                try:
                    for _ in range(1000):
                        yield chunk
                finally:
                    closed.set()

            def close(self):
                closed.set()

        class Handler(LSDFGatewayHandler):
            gateway_config = config
            gateway_firewall = Firewall(load_policy("policies/default.yaml"))
            gateway_metrics = metrics

            def _forward_stream(self, payload):
                return 200, {"content-type": "text/event-stream"}, UpstreamBody()

            def _forward(self, payload):
                return 200, {"content-type": "application/json"}, b'{"choices":[]}'

        server = LSDFGatewayServer(
            ("127.0.0.1", 0),
            Handler,
            max_concurrent_requests=config.max_concurrent_requests,
            metrics=metrics,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        client = socket.create_connection(server.server_address, timeout=2)
        body = json.dumps(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]}
        ).encode("utf-8")
        try:
            client.sendall(
                (
                    f"POST /v1/chat/completions HTTP/1.1\r\n"
                    f"Host: {server.server_address[0]}\r\n"
                    "Content-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii")
                + body
            )
            self.assertTrue(entered.wait(2))
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        finally:
            client.close()
            self.assertTrue(closed.wait(2))
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_stream_duration_returns_terminal_sse_error_and_releases_upstream(self):
        entered = threading.Event()
        release = threading.Event()

        class HangingStream(BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
                self.end_headers()
                self.wfile.write(b'data: {"choices":[{"delta":{"content":"safe"}}]}\n\n')
                self.wfile.flush()
                entered.set()
                release.wait(3)

            def log_message(self, format, *args):
                return

        upstream = ThreadingHTTPServer(("127.0.0.1", 0), HangingStream)
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        fixture = _GatewayFixture(
            GatewayConfig(
                None,
                "default",
                f"http://127.0.0.1:{upstream.server_address[1]}",
                upstream_timeout_seconds=1,
                max_stream_seconds=0.1,
                client_timeout_seconds=2,
            ),
            use_default_forward=True,
        )
        try:
            conn = http.client.HTTPConnection(*fixture.address, timeout=3)
            try:
                conn.request(
                    "POST",
                    "/v1/chat/completions",
                    json.dumps({"stream": True, "messages": [{"role": "user", "content": "hello"}]}),
                    {"content-type": "application/json"},
                )
                self.assertTrue(entered.wait(2))
                response = conn.getresponse()
                body = response.read().decode("utf-8")
            finally:
                conn.close()
            self.assertEqual(response.status, 200)
            self.assertIn('"type":"stream_timeout"', body)
            self.assertNotIn("safe", body)
            self.assertEqual(
                fixture.metrics.to_dict()["counters"]["gateway_stream_timeouts_total{stream=True}"],
                1,
            )
        finally:
            release.set()
            fixture.stop()
            upstream.shutdown()
            upstream.server_close()
            upstream_thread.join(timeout=3)

    def test_client_write_timeout_has_separate_metric_from_disconnect(self):
        metrics = MetricsRecorder(enabled=True)

        class TimeoutWriter:
            def write(self, _chunk):
                raise socket.timeout()

            def flush(self):
                return None

        handler = object.__new__(LSDFGatewayHandler)
        handler.gateway_metrics = metrics
        handler.close_connection = False
        handler.wfile = TimeoutWriter()
        handler.send_response = lambda _status: None
        handler.send_header = lambda _key, _value: None
        handler.end_headers = lambda: None

        handler._send_iter(200, [b"data: {}\n\n"], {}, {})

        counters = metrics.to_dict()["counters"]
        self.assertEqual(
            counters["gateway_client_write_timeouts_total{stream=True}"],
            1,
        )
        self.assertNotIn("gateway_client_disconnects_total{stream=True}", counters)

    def test_concurrency_rejection_happens_before_second_handler_and_permit_releases(self):
        config = GatewayConfig(
            None,
            "default",
            "http://127.0.0.1:1",
            max_concurrent_requests=1,
        )
        fixture = _GatewayFixture(config, block_forward=True)
        first_result: queue.Queue[tuple[int, bytes]] = queue.Queue()
        self.assertLessEqual(fixture.server._overload_socket_timeout, 0.05)

        def first_request():
            status, _headers, body = _post(
                fixture.address,
                {"messages": [{"role": "user", "content": "first"}]},
            )
            first_result.put((status, body))

        first_thread = threading.Thread(target=first_request, daemon=True)
        first_thread.start()
        try:
            self.assertTrue(fixture.forward_entered.wait(2))
            status, _headers, body = _post_empty(fixture.address)
            self.assertEqual(status, 503)
            self.assertEqual(json.loads(body)["error"]["type"], "gateway_overloaded")
            self.assertEqual(len(fixture.forwarded), 1)

            fixture.forward_release.set()
            first_thread.join(timeout=3)
            self.assertEqual(first_result.get(timeout=1)[0], 200)
            self.assertEqual(
                fixture.metrics.to_dict()["counters"]["gateway_concurrency_rejections_total"],
                1,
            )

            status, _headers, _body = _post(
                fixture.address,
                {"messages": [{"role": "user", "content": "third"}]},
            )
            self.assertEqual(status, 200)
        finally:
            fixture.forward_release.set()
            first_thread.join(timeout=3)
            fixture.stop()


if __name__ == "__main__":
    unittest.main()
