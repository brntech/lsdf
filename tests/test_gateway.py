import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from lsdf import Firewall, load_policy
from lsdf.audit import JsonlAuditSink
from lsdf.eval_matrix import ENTITY_SAMPLES
from lsdf.gateway import (
    GatewayConfig,
    LSDFGatewayHandler,
    GatewayConfigError,
    _check_upstream_health,
    _join_upstream_url,
    forward_upstream,
    forward_upstream_stream,
    handle_chat_completion,
    handle_streaming_chat_completion,
    resolve_gateway_config,
)
from lsdf.metrics import MetricsRecorder
from lsdf.streaming import (
    StreamingInspectionState,
    _flush_stream_states,
    format_sse_event,
    iter_sse_events,
)


class SseHelperTests(unittest.TestCase):
    def test_parser_handles_metadata_comments_multiline_data_and_crlf(self):
        raw = (
            b": first comment\r\n"
            b"id: chunk-7\r\n"
            b"retry: 2500\r\n"
            b"event: completion.chunk\r\n"
            b"data: first line\r\n"
            b"data: second line\r\n"
            b"\r\n"
        )

        events = list(iter_sse_events([raw]))

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].comments, ("first comment",))
        self.assertEqual(events[0].id, "chunk-7")
        self.assertEqual(events[0].retry, "2500")
        self.assertEqual(events[0].event, "completion.chunk")
        self.assertEqual(events[0].data, "first line\nsecond line")

    def test_formatter_preserves_sse_metadata_fields(self):
        raw = format_sse_event(
            "first line\nsecond line",
            event="completion.chunk",
            id="chunk-7",
            retry="2500",
            comments=("first comment",),
        ).decode("utf-8")

        self.assertIn(": first comment\n", raw)
        self.assertIn("id: chunk-7\n", raw)
        self.assertIn("retry: 2500\n", raw)
        self.assertIn("event: completion.chunk\n", raw)
        self.assertIn("data: first line\n", raw)
        self.assertIn("data: second line\n", raw)


class GatewayHealthHelperTests(unittest.TestCase):
    class _Response:
        def __init__(self, status):
            self.status = status
            self.closed = False

        def __enter__(self):
            return self

        def __exit__(self, _exc_type, _exc, _traceback):
            self.close()

        def close(self):
            self.closed = True

    def setUp(self):
        marker = ENTITY_SAMPLES["API_KEY"][0]
        self.marker = marker
        self.url = f"https://health-user:{marker}@example.test/v1?api_key={marker}#fixture"

    def test_success_health_result_omits_credentialed_url(self):
        response = self._Response(200)
        with patch("lsdf.gateway.urllib.request.urlopen", return_value=response) as urlopen:
            result = _check_upstream_health(self.url, 100)

        self.assertEqual(result, {"status": "ok", "http_status": 200})
        self.assertEqual(urlopen.call_args.args[0].full_url, self.url)
        self.assertTrue(response.closed)
        serialized = json.dumps(result)
        self.assertNotIn(self.url, serialized)
        self.assertNotIn(self.marker, serialized)

    def test_http_error_closes_body_and_omits_credentialed_url(self):
        response = self._Response(429)
        error = urllib.error.HTTPError(self.url, 429, "synthetic response", {}, response)
        with patch("lsdf.gateway.urllib.request.urlopen", side_effect=error):
            result = _check_upstream_health(self.url, 100)

        self.assertEqual(
            result,
            {
                "status": "warning",
                "http_status": 429,
                "message": "reachable with non-2xx response",
            },
        )
        self.assertTrue(response.closed)
        serialized = json.dumps(result)
        self.assertNotIn(self.url, serialized)
        self.assertNotIn(self.marker, serialized)

    def test_transport_error_is_static_and_omits_credentialed_url(self):
        with patch(
            "lsdf.gateway.urllib.request.urlopen",
            side_effect=urllib.error.URLError("synthetic transport detail"),
        ):
            result = _check_upstream_health(self.url, 100)

        self.assertEqual(
            result,
            {"status": "error", "error_type": "upstream_transport_error"},
        )
        serialized = json.dumps(result)
        self.assertNotIn(self.url, serialized)
        self.assertNotIn(self.marker, serialized)


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.firewall = Firewall(load_policy("policies/default.yaml"))
        self.forward_count = 0

    def test_blocked_request_is_not_forwarded(self):
        payload = {"messages": [{"role": "user", "content": "Use api_LSDF_FIXTURE_TOKEN_000000"}]}

        status, _response_headers, body, headers = handle_chat_completion(
            payload,
            self.firewall,
            self._forward_ok,
        )

        self.assertEqual(status, 403)
        self.assertEqual(headers["x-lsdf-blocked"], "true")
        self.assertGreater(int(headers["x-lsdf-decision-count"]), 0)
        self.assertEqual(self.forward_count, 0)
        self.assertEqual(json.loads(body)["error"]["type"], "sensitive_data_blocked")

    def test_transformed_request_reaches_upstream(self):
        recorder = _ForwardRecorder({"choices": [{"message": {"content": "ok"}}]})

        status, _response_headers, body, headers = handle_chat_completion(
            {"messages": [{"role": "user", "content": "My SSN is 000-00-0000."}]},
            self.firewall,
            recorder,
        )

        sent_content = recorder.payloads[0]["messages"][0]["content"]
        self.assertEqual(status, 200)
        self.assertEqual(headers["x-lsdf-blocked"], "false")
        self.assertIn("<US_SSN:TOKEN>", sent_content)
        self.assertNotIn("000-00-0000", sent_content)
        self.assertEqual(json.loads(body)["choices"][0]["message"]["content"], "ok")

    def test_upstream_response_is_scrubbed(self):
        upstream_payload = {"choices": [{"message": {"content": "Patient MRN: LSDF-FIXTURE-00001 leaked."}}]}

        status, _response_headers, body, headers = handle_chat_completion(
            {"messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_payload(upstream_payload),
        )

        response = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(headers["x-lsdf-blocked"], "false")
        self.assertEqual(headers["x-lsdf-decision-count"], "1")
        self.assertIn("<MRN:REDACTED>", response["choices"][0]["message"]["content"])
        self.assertEqual(self.forward_count, 1)

    def test_blocked_upstream_response_returns_502(self):
        upstream_payload = {
            "choices": [
                {"message": {"reasoning_content": "Use api_LSDF_FIXTURE_TOKEN_000000 next."}}
            ]
        }

        status, _response_headers, body, headers = handle_chat_completion(
            {"messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_payload(upstream_payload),
        )

        self.assertEqual(status, 502)
        self.assertEqual(headers["x-lsdf-blocked"], "true")
        self.assertEqual(json.loads(body)["error"]["type"], "sensitive_data_blocked")

    def test_non_json_upstream_response_passes_through(self):
        status, response_headers, body, headers = handle_chat_completion(
            {"messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: (200, {"content-type": "text/plain"}, b"plain text"),
        )

        self.assertEqual(status, 200)
        self.assertEqual(response_headers["content-type"], "text/plain")
        self.assertEqual(body, b"plain text")
        self.assertEqual(headers["x-lsdf-blocked"], "false")
        self.assertEqual(headers["x-lsdf-decision-count"], "0")

    def test_audit_sink_records_blocked_request_without_raw_values(self):
        raw_secret = "api_LSDF_FIXTURE_TOKEN_000000"
        with TemporaryDirectory() as tmpdir:
            audit_path = Path(tmpdir, "events.jsonl")
            status, _response_headers, _body, _headers = handle_chat_completion(
                {"messages": [{"role": "user", "content": f"Use {raw_secret}"}]},
                self.firewall,
                self._forward_ok,
                audit_sink=JsonlAuditSink(audit_path),
            )
            events = _read_jsonl(audit_path)
            raw_audit = audit_path.read_text(encoding="utf-8")

        self.assertEqual(status, 403)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["stage"], "request_preflight")
        self.assertTrue(events[0]["blocked"])
        self.assertNotIn(raw_secret, raw_audit)

    def test_audit_sink_records_non_streaming_response_redaction(self):
        raw_mrn = "MRN: LSDF-FIXTURE-00001"
        upstream_payload = {"choices": [{"message": {"content": f"Patient {raw_mrn}"}}]}
        with TemporaryDirectory() as tmpdir:
            audit_path = Path(tmpdir, "events.jsonl")
            status, _response_headers, body, _headers = handle_chat_completion(
                {"messages": [{"role": "user", "content": "hello"}]},
                self.firewall,
                lambda _payload: self._forward_payload(upstream_payload),
                audit_sink=JsonlAuditSink(audit_path),
            )
            events = _read_jsonl(audit_path)
            raw_audit = audit_path.read_text(encoding="utf-8")

        self.assertEqual(status, 200)
        self.assertIn("<MRN:REDACTED>", json.loads(body)["choices"][0]["message"]["content"])
        self.assertEqual([event["stage"] for event in events], ["request_preflight", "response_inspection"])
        self.assertFalse(events[1]["blocked"])
        self.assertEqual(events[1]["decision_count"], 1)
        self.assertNotIn(raw_mrn, raw_audit)

    def test_audit_sink_records_non_streaming_response_block(self):
        raw_secret = "api_LSDF_FIXTURE_TOKEN_000000"
        upstream_payload = {
            "choices": [{"message": {"reasoning_content": f"Use {raw_secret}"}}]
        }
        with TemporaryDirectory() as tmpdir:
            audit_path = Path(tmpdir, "events.jsonl")
            status, _response_headers, _body, _headers = handle_chat_completion(
                {"messages": [{"role": "user", "content": "hello"}]},
                self.firewall,
                lambda _payload: self._forward_payload(upstream_payload),
                audit_sink=JsonlAuditSink(audit_path),
            )
            events = _read_jsonl(audit_path)
            raw_audit = audit_path.read_text(encoding="utf-8")

        self.assertEqual(status, 502)
        self.assertEqual(events[-1]["stage"], "response_inspection")
        self.assertTrue(events[-1]["blocked"])
        self.assertNotIn(raw_secret, raw_audit)

    def test_failing_audit_sink_does_not_break_blocked_request(self):
        status, _response_headers, body, _headers = handle_chat_completion(
            {"messages": [{"role": "user", "content": "Use api_LSDF_FIXTURE_TOKEN_000000"}]},
            self.firewall,
            self._forward_ok,
            audit_sink=_FailingAuditSink(),
        )

        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body)["error"]["type"], "sensitive_data_blocked")
        self.assertEqual(self.forward_count, 0)

    def test_failing_audit_sink_does_not_break_response_redaction(self):
        upstream_payload = {"choices": [{"message": {"content": "Patient MRN: LSDF-FIXTURE-00001"}}]}

        status, _response_headers, body, _headers = handle_chat_completion(
            {"messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_payload(upstream_payload),
            audit_sink=_FailingAuditSink(),
        )

        self.assertEqual(status, 200)
        self.assertIn(
            "<MRN:REDACTED>",
            json.loads(body)["choices"][0]["message"]["content"],
        )

    def test_failing_audit_sink_does_not_break_response_block(self):
        upstream_payload = {
            "choices": [
                {"message": {"reasoning_content": "Use api_LSDF_FIXTURE_TOKEN_000000"}}
            ]
        }

        status, _response_headers, body, _headers = handle_chat_completion(
            {"messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_payload(upstream_payload),
            audit_sink=_FailingAuditSink(),
        )

        self.assertEqual(status, 502)
        self.assertEqual(json.loads(body)["error"]["type"], "sensitive_data_blocked")

    def test_request_unknown_fields_keep_input_semantics(self):
        status, _response_headers, body, _headers = handle_chat_completion(
            {
                "messages": [{"role": "user", "content": "hello"}],
                "metadata": {"secret": "api_LSDF_FIXTURE_TOKEN_000000"},
            },
            self.firewall,
            self._forward_ok,
        )

        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body)["error"]["type"], "sensitive_data_blocked")
        self.assertEqual(self.forward_count, 0)

    def test_request_unknown_numeric_fields_keep_input_semantics(self):
        recorder = _ForwardRecorder({"choices": [{"message": {"content": "ok"}}]})

        status, _response_headers, _body, headers = handle_chat_completion(
            {
                "messages": [{"role": "user", "content": "hello"}],
                "metadata": {"card": 4111111111111111},
            },
            self.firewall,
            recorder,
        )

        self.assertEqual(status, 200)
        self.assertEqual(headers["x-lsdf-blocked"], "false")
        self.assertEqual(
            recorder.payloads[0]["metadata"]["card"],
            "<CREDIT_CARD:TOKEN>",
        )

    def test_response_unknown_fields_use_output_semantics(self):
        upstream_payload = {
            "choices": [{"message": {"content": "ok"}}],
            "metadata": {"secret": "api_LSDF_FIXTURE_TOKEN_000000"},
        }

        status, _response_headers, body, headers = handle_chat_completion(
            {"messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_payload(upstream_payload),
        )

        response = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(headers["x-lsdf-blocked"], "false")
        self.assertEqual(response["metadata"]["secret"], "<API_KEY:REDACTED>")

    def test_response_unknown_numeric_fields_use_output_semantics(self):
        upstream_payload = {
            "choices": [{"message": {"content": "ok"}}],
            "metadata": {"card": 4111111111111111},
        }

        status, _response_headers, body, headers = handle_chat_completion(
            {"messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_payload(upstream_payload),
        )

        response = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(headers["x-lsdf-blocked"], "false")
        self.assertEqual(response["metadata"]["card"], "<CREDIT_CARD:REDACTED>")

    def test_non_streaming_upstream_transport_error_returns_502(self):
        def fail(_payload):
            raise urllib.error.URLError("connection refused")

        status, _response_headers, body, headers = handle_chat_completion(
            {"messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            fail,
        )

        self.assertEqual(status, 502)
        self.assertEqual(headers["x-lsdf-blocked"], "false")
        self.assertEqual(json.loads(body)["error"]["type"], "upstream_transport_error")

    def test_forward_upstream_transport_error_records_metric(self):
        config = GatewayConfig(
            policy_path=None,
            policy_profile="default",
            upstream_base_url="http://upstream.example",
        )
        metrics = MetricsRecorder(enabled=True)

        with patch(
            "lsdf.gateway.urllib.request.urlopen",
            side_effect=urllib.error.URLError("connection refused"),
        ):
            status, _response_headers, body, _headers = handle_chat_completion(
                {"messages": [{"role": "user", "content": "hello"}]},
                self.firewall,
                lambda payload: forward_upstream(payload, "/v1/chat/completions", config),
                metrics=metrics,
            )

        self.assertEqual(status, 502)
        self.assertEqual(json.loads(body)["error"]["type"], "upstream_transport_error")
        self.assertEqual(
            metrics.to_dict()["counters"][
                "gateway_upstream_errors_total{error_type=upstream_transport_error}"
            ],
            1,
        )

    def _forward_ok(self, payload):
        return self._forward_payload({"choices": [{"message": {"content": "ok"}}]})

    def _forward_payload(self, payload):
        self.forward_count += 1
        return 200, {"content-type": "application/json"}, json.dumps(payload).encode("utf-8")


class StreamingGatewayTests(unittest.TestCase):
    def setUp(self):
        self.firewall = Firewall(load_policy("policies/default.yaml"))
        self.forward_count = 0

    def test_non_sse_json_stream_response_is_inspected_and_redacted(self):
        upstream_payload = {
            "choices": [{"message": {"content": "Patient MRN: LSDF-FIXTURE-00001 leaked."}}]
        }

        status, response_headers, body, headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_non_sse_json(upstream_payload),
        )

        response = json.loads(b"".join(body))
        self.assertEqual(status, 200)
        self.assertEqual(response_headers["content-type"], "application/json")
        self.assertEqual(headers["x-lsdf-blocked"], "false")
        self.assertEqual(headers["x-lsdf-decision-count"], "1")
        self.assertIn("<MRN:REDACTED>", response["choices"][0]["message"]["content"])
        self.assertNotIn("LSDF-FIXTURE-00001", json.dumps(response))

    def test_non_sse_json_stream_response_can_block(self):
        upstream_payload = {
            "choices": [
                {"message": {"reasoning_content": "Use api_LSDF_FIXTURE_TOKEN_000000 next."}}
            ]
        }

        status, response_headers, body, headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_non_sse_json(upstream_payload),
        )

        response = json.loads(b"".join(body))
        self.assertEqual(status, 502)
        self.assertEqual(response_headers["content-type"], "application/json")
        self.assertEqual(headers["x-lsdf-blocked"], "true")
        self.assertEqual(response["error"]["type"], "sensitive_data_blocked")
        self.assertNotIn("api_LSDF_FIXTURE_TOKEN_000000", json.dumps(response))

    def test_non_sse_non_json_stream_response_still_passes_through(self):
        status, response_headers, body, headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: (200, {"content-type": "text/plain"}, [b"plain text"]),
        )

        self.assertEqual(status, 200)
        self.assertEqual(response_headers["content-type"], "text/plain")
        self.assertEqual(headers["x-lsdf-blocked"], "false")
        self.assertEqual(b"".join(body), b"plain text")

    def test_harmless_stream_preserves_sse_and_done(self):
        status, response_headers, body, headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_stream(
                [
                    _sse({"choices": [{"index": 0, "delta": {"content": "hello "}}]}),
                    _sse({"choices": [{"index": 0, "delta": {"content": "world"}}]}),
                    b"data: [DONE]\n\n",
                ]
            ),
            holdback_chars=3,
        )

        events = _decode_sse_body(body)
        self.assertEqual(status, 200)
        self.assertEqual(response_headers["content-type"], "text/event-stream")
        self.assertEqual(headers["x-lsdf-blocked"], "false")
        self.assertEqual(_joined_stream_field(events, "content"), "hello world")
        self.assertEqual(events[-1], "[DONE]")
        self.assertEqual(self.forward_count, 1)

    def test_stream_preserves_role_metadata_while_content_is_held(self):
        status, _response_headers, body, _headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_stream(
                [
                    _sse({"choices": [{"index": 0, "delta": {"role": "assistant"}}]}),
                    _sse(
                        {
                            "id": "chatcmpl-test",
                            "object": "chat.completion.chunk",
                            "choices": [{"index": 0, "delta": {"content": "held"}}],
                        }
                    ),
                    b"data: [DONE]\n\n",
                ]
            ),
            holdback_chars=64,
        )

        events = _decode_sse_body(body)
        self.assertEqual(status, 200)
        self.assertEqual(events[0]["choices"][0]["delta"]["role"], "assistant")
        self.assertEqual(_joined_stream_field(events, "content"), "held")
        self.assertEqual(events[-1], "[DONE]")

    def test_finish_reason_is_sent_after_held_content_flush(self):
        status, _response_headers, body, _headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_stream(
                [
                    _sse({"choices": [{"index": 0, "delta": {"content": "final text"}}]}),
                    _sse({"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}),
                    b"data: [DONE]\n\n",
                ]
            ),
            holdback_chars=64,
        )

        events = _decode_sse_body(body)
        self.assertEqual(status, 200)
        content_event_index = next(
            idx for idx, event in enumerate(events) if _joined_stream_field([event], "content")
        )
        finish_event_index = next(
            idx
            for idx, event in enumerate(events)
            if isinstance(event, dict)
            and event.get("choices", [{}])[0].get("finish_reason") == "stop"
        )
        self.assertLess(content_event_index, finish_event_index)
        self.assertEqual(_joined_stream_field(events, "content"), "final text")

    def test_utf8_split_across_network_chunks_is_decoded_incrementally(self):
        raw = _sse({"choices": [{"index": 0, "delta": {"content": "cafe\u00e9"}}]})
        split_at = raw.index("é".encode("utf-8")) + 1
        status, _response_headers, body, _headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_stream(
                [raw[:split_at], raw[split_at:], b"data: [DONE]\n\n"]
            ),
            holdback_chars=64,
        )

        events = _decode_sse_body(body)
        self.assertEqual(status, 200)
        self.assertEqual(_joined_stream_field(events, "content"), "cafe\u00e9")
        self.assertEqual(events[-1], "[DONE]")

    def test_secret_split_across_chunks_is_redacted_before_release(self):
        raw_secret = "api_LSDF_FIXTURE_TOKEN_000000"
        status, _response_headers, body, _headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_stream(
                [
                    _sse({"choices": [{"index": 0, "delta": {"content": "token api_abcdef"}}]}),
                    _sse({"choices": [{"index": 0, "delta": {"content": "ghijklmnopqrstuvwxyz"}}]}),
                    b"data: [DONE]\n\n",
                ]
            ),
            holdback_chars=64,
        )

        encoded = b"".join(body).decode("utf-8")
        self.assertEqual(status, 200)
        self.assertNotIn(raw_secret, encoded)
        self.assertIn("<API_KEY:REDACTED>", encoded)

    def test_reasoning_secret_blocks_stream_with_error_event(self):
        status, _response_headers, body, _headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_stream(
                [
                    _sse(
                        {
                            "choices": [
                                {
                                    "index": 0,
                                    "delta": {
                                        "reasoning_content": "Use api_LSDF_FIXTURE_TOKEN_000000"
                                    },
                                }
                            ]
                        }
                    ),
                    b"data: [DONE]\n\n",
                ]
            ),
            holdback_chars=64,
        )

        events = _decode_sse_body(body)
        self.assertEqual(status, 200)
        self.assertEqual(events[0]["error"]["type"], "sensitive_data_blocked")
        self.assertNotIn("[DONE]", events)

    def test_blocked_streaming_request_is_not_forwarded(self):
        status, _response_headers, body, headers = handle_streaming_chat_completion(
            {
                "stream": True,
                "messages": [{"role": "user", "content": "Use api_LSDF_FIXTURE_TOKEN_000000"}],
            },
            self.firewall,
            lambda _payload: self._forward_stream([b"data: [DONE]\n\n"]),
            holdback_chars=64,
        )

        self.assertEqual(status, 403)
        self.assertEqual(headers["x-lsdf-blocked"], "true")
        self.assertEqual(json.loads(b"".join(body))["error"]["type"], "sensitive_data_blocked")
        self.assertEqual(self.forward_count, 0)

    def test_malformed_upstream_sse_returns_error_event(self):
        status, _response_headers, body, _headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_stream([b"data: {not-json}\n\n"]),
            holdback_chars=64,
        )

        events = _decode_sse_body(body)
        self.assertEqual(status, 200)
        self.assertEqual(events[0]["error"]["type"], "upstream_stream_error")

    def test_malformed_sse_flushes_safe_held_tail_before_error(self):
        status, _response_headers, body, _headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_stream(
                [
                    _sse({"choices": [{"index": 0, "delta": {"content": "safe tail"}}]}),
                    b"data: {not-json}\n\n",
                ]
            ),
            holdback_chars=64,
        )

        events = _decode_sse_body(body)
        self.assertEqual(status, 200)
        self.assertEqual(_joined_stream_field(events, "content"), "safe tail")
        self.assertEqual(events[-1]["error"]["type"], "upstream_stream_error")
        self.assertEqual(events[-1]["lsdf"]["stream_state"], "malformed_sse_json")

    def test_malformed_sse_non_object_flushes_safe_held_tail_before_error(self):
        status, _response_headers, body, _headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_stream(
                [
                    _sse({"choices": [{"index": 0, "delta": {"content": "safe tail"}}]}),
                    b"data: []\n\n",
                ]
            ),
            holdback_chars=64,
        )

        events = _decode_sse_body(body)
        self.assertEqual(status, 200)
        self.assertEqual(_joined_stream_field(events, "content"), "safe tail")
        self.assertEqual(events[-1]["error"]["type"], "upstream_stream_error")
        self.assertEqual(events[-1]["lsdf"]["stream_state"], "malformed_sse_payload")

    def test_malformed_sse_with_blocked_tool_arguments_leaks_no_raw_text(self):
        raw_secret = "api_LSDF_FIXTURE_TOKEN_000000"
        status, _response_headers, body, _headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_stream(
                [
                    _sse(
                        {
                            "choices": [
                                {
                                    "index": 0,
                                    "delta": {
                                        "tool_calls": [
                                            {
                                                "index": 0,
                                                "function": {
                                                    "arguments": json.dumps(
                                                        {"token": raw_secret}
                                                    )
                                                },
                                            }
                                        ]
                                    },
                                }
                            ]
                        }
                    ),
                    b"data: {not-json}\n\n",
                ]
            ),
            holdback_chars=64,
        )

        encoded = b"".join(body).decode("utf-8")
        events = _decode_sse_body([encoded.encode("utf-8")])
        self.assertEqual(status, 200)
        self.assertEqual(events[0]["error"]["type"], "sensitive_data_blocked")
        self.assertNotIn(raw_secret, encoded)
        self.assertNotIn("upstream_stream_error", encoded)

    def test_transformed_stream_preserves_sse_metadata(self):
        upstream = (
            b": upstream-note\n"
            b"id: chunk-1\n"
            b"retry: 1000\n"
            b"event: completion.chunk\n"
            + _sse({"choices": [{"index": 0, "delta": {"content": "held text"}}]})
        )
        status, _response_headers, body, _headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_stream([upstream, b"data: [DONE]\n\n"]),
            holdback_chars=64,
        )

        encoded = b"".join(body).decode("utf-8")
        self.assertEqual(status, 200)
        self.assertIn(": upstream-note\n", encoded)
        self.assertIn("id: chunk-1\n", encoded)
        self.assertIn("retry: 1000\n", encoded)
        self.assertIn("event: completion.chunk\n", encoded)
        self.assertEqual(_joined_stream_field(_decode_sse_body([encoded.encode("utf-8")]), "content"), "held text")

    def test_terminal_flush_does_not_release_safe_tail_before_blocked_tail(self):
        safe_state = StreamingInspectionState(
            self.firewall,
            surface_name="output.stream_chunk",
            pointer=("text",),
            holdback_chars=64,
        )
        blocked_state = StreamingInspectionState(
            self.firewall,
            surface_name="output.reasoning",
            pointer=("text",),
            holdback_chars=64,
        )
        safe_state.pending = "safe held text"
        blocked_state.pending = "Use api_LSDF_FIXTURE_TOKEN_000000"
        states = {(0, "content"): safe_state, (0, "reasoning_content"): blocked_state}

        result = _flush_stream_states(states, {})

        self.assertEqual(result.chunks, [])
        self.assertIsNotNone(result.blocked_event)
        events = _decode_sse_body([result.blocked_event])
        self.assertEqual(events[0]["error"]["type"], "sensitive_data_blocked")

    def test_premature_eof_flushes_safe_tail_and_emits_error_event(self):
        status, _response_headers, body, _headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_stream(
                [_sse({"choices": [{"index": 0, "delta": {"content": "safe tail"}}]})]
            ),
            holdback_chars=64,
        )

        events = _decode_sse_body(body)
        self.assertEqual(status, 200)
        self.assertEqual(_joined_stream_field(events, "content"), "safe tail")
        self.assertEqual(events[-1]["error"]["type"], "upstream_stream_error")
        self.assertEqual(events[-1]["lsdf"]["stream_state"], "upstream_eof")
        self.assertNotIn("[DONE]", events)

    def test_premature_eof_with_blocked_tail_emits_block_only(self):
        status, _response_headers, body, _headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_stream(
                [
                    _sse(
                        {
                            "choices": [
                                {
                                    "index": 0,
                                    "delta": {
                                        "reasoning_content": "Use api_LSDF_FIXTURE_TOKEN_000000"
                                    },
                                }
                            ]
                        }
                    )
                ]
            ),
            holdback_chars=64,
        )

        events = _decode_sse_body(body)
        self.assertEqual(status, 200)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["error"]["type"], "sensitive_data_blocked")
        self.assertEqual(events[0]["lsdf"]["stream_state"], "blocked")

    def test_audit_sink_records_safe_stream_terminal_summary(self):
        with TemporaryDirectory() as tmpdir:
            audit_path = Path(tmpdir, "events.jsonl")
            status, _response_headers, body, _headers = handle_streaming_chat_completion(
                {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
                self.firewall,
                lambda _payload: self._forward_stream(
                    [
                        _sse({"choices": [{"index": 0, "delta": {"content": "hello"}}]}),
                        b"data: [DONE]\n\n",
                    ]
                ),
                holdback_chars=64,
                audit_sink=JsonlAuditSink(audit_path),
            )
            events = _decode_sse_body(body)
            audit_events = _read_jsonl(audit_path)

        self.assertEqual(status, 200)
        self.assertEqual(events[-1], "[DONE]")
        self.assertEqual(audit_events[-1]["stage"], "stream_terminal")
        self.assertEqual(audit_events[-1]["stream_state"], "done")
        self.assertFalse(audit_events[-1]["blocked"])
        self.assertEqual(audit_events[-1]["surfaces_inspected"], ["output.stream_chunk"])

    def test_audit_sink_records_stream_terminal_block_without_raw_values(self):
        raw_secret = "api_LSDF_FIXTURE_TOKEN_000000"
        with TemporaryDirectory() as tmpdir:
            audit_path = Path(tmpdir, "events.jsonl")
            status, _response_headers, body, _headers = handle_streaming_chat_completion(
                {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
                self.firewall,
                lambda _payload: self._forward_stream(
                    [
                        _sse(
                            {
                                "choices": [
                                    {
                                        "index": 0,
                                        "delta": {"reasoning_content": f"Use {raw_secret}"},
                                    }
                                ]
                            }
                        ),
                        b"data: [DONE]\n\n",
                    ]
                ),
                holdback_chars=64,
                audit_sink=JsonlAuditSink(audit_path),
            )
            events = _decode_sse_body(body)
            audit_events = _read_jsonl(audit_path)
            raw_audit = audit_path.read_text(encoding="utf-8")

        self.assertEqual(status, 200)
        self.assertEqual(events[0]["error"]["type"], "sensitive_data_blocked")
        self.assertEqual(audit_events[-1]["stream_state"], "blocked")
        self.assertTrue(audit_events[-1]["blocked"])
        self.assertEqual(audit_events[-1]["error_type"], "sensitive_data_blocked")
        self.assertIn("audit_event", audit_events[-1])
        self.assertNotIn(raw_secret, raw_audit)

    def test_audit_sink_records_malformed_stream_error(self):
        with TemporaryDirectory() as tmpdir:
            audit_path = Path(tmpdir, "events.jsonl")
            status, _response_headers, body, _headers = handle_streaming_chat_completion(
                {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
                self.firewall,
                lambda _payload: self._forward_stream([b"data: {not-json}\n\n"]),
                holdback_chars=64,
                audit_sink=JsonlAuditSink(audit_path),
            )
            events = _decode_sse_body(body)
            audit_events = _read_jsonl(audit_path)

        self.assertEqual(status, 200)
        self.assertEqual(events[0]["error"]["type"], "upstream_stream_error")
        self.assertEqual(audit_events[-1]["stream_state"], "malformed_sse_json")
        self.assertEqual(audit_events[-1]["error_type"], "upstream_stream_error")

    def test_audit_sink_records_premature_eof_error(self):
        with TemporaryDirectory() as tmpdir:
            audit_path = Path(tmpdir, "events.jsonl")
            status, _response_headers, body, _headers = handle_streaming_chat_completion(
                {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
                self.firewall,
                lambda _payload: self._forward_stream(
                    [_sse({"choices": [{"index": 0, "delta": {"content": "safe"}}]})]
                ),
                holdback_chars=64,
                audit_sink=JsonlAuditSink(audit_path),
            )
            events = _decode_sse_body(body)
            audit_events = _read_jsonl(audit_path)

        self.assertEqual(status, 200)
        self.assertEqual(events[-1]["lsdf"]["stream_state"], "upstream_eof")
        self.assertEqual(audit_events[-1]["stream_state"], "upstream_eof")
        self.assertEqual(audit_events[-1]["error_type"], "upstream_stream_error")

    def test_streamed_tool_call_arguments_are_assembled_before_done(self):
        status, _response_headers, body, _headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_stream(
                [
                    _sse(
                        {
                            "choices": [
                                {
                                    "index": 0,
                                    "delta": {
                                        "tool_calls": [
                                            {
                                                "index": 0,
                                                "id": "call_1",
                                                "type": "function",
                                                "function": {
                                                    "name": "lookup",
                                                    "arguments": "{\"query\":\"hel",
                                                },
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
                                                "function": {"arguments": "lo\"}"},
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
            ),
            holdback_chars=64,
        )

        events = _decode_sse_body(body)
        argument_events = _tool_argument_events(events)
        finish_event_index = next(
            idx
            for idx, event in enumerate(events)
            if isinstance(event, dict)
            and event.get("choices", [{}])[0].get("finish_reason") == "tool_calls"
        )
        argument_event_index = events.index(argument_events[0])
        self.assertEqual(status, 200)
        self.assertLess(argument_event_index, finish_event_index)
        self.assertEqual(_joined_tool_arguments(events, 0), '{"query":"hello"}')
        self.assertEqual(json.loads(_joined_tool_arguments(events, 0)), {"query": "hello"})
        self.assertEqual(events[-1], "[DONE]")

    def test_streamed_tool_call_metadata_passes_while_arguments_are_held(self):
        status, _response_headers, body, _headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_stream(
                [
                    _sse(
                        {
                            "choices": [
                                {
                                    "index": 0,
                                    "delta": {
                                        "tool_calls": [
                                            {
                                                "index": 0,
                                                "id": "call_1",
                                                "type": "function",
                                                "function": {
                                                    "name": "lookup",
                                                    "arguments": "{\"query\":\"safe\"}",
                                                },
                                            }
                                        ]
                                    },
                                }
                            ]
                        }
                    ),
                    b"data: [DONE]\n\n",
                ]
            ),
            holdback_chars=64,
        )

        events = _decode_sse_body(body)
        metadata_delta = events[0]["choices"][0]["delta"]["tool_calls"][0]
        self.assertEqual(status, 200)
        self.assertEqual(metadata_delta["id"], "call_1")
        self.assertEqual(metadata_delta["type"], "function")
        self.assertEqual(metadata_delta["function"]["name"], "lookup")
        self.assertNotIn("arguments", metadata_delta["function"])
        self.assertEqual(_joined_tool_arguments(events, 0), '{"query":"safe"}')
        self.assertEqual(events[-1], "[DONE]")

    def test_streamed_tool_call_secret_blocks_without_raw_fragments(self):
        raw_secret = "api_LSDF_FIXTURE_TOKEN_000000"
        status, _response_headers, body, _headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_stream(
                [
                    _sse(
                        {
                            "choices": [
                                {
                                    "index": 0,
                                    "delta": {
                                        "tool_calls": [
                                            {
                                                "index": 0,
                                                "function": {
                                                    "arguments": "{\"token\":\"api_abcdef",
                                                },
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
                                                "function": {
                                                    "arguments": "ghijklmnopqrstuvwxyz\"}",
                                                },
                                            }
                                        ]
                                    },
                                }
                            ]
                        }
                    ),
                    b"data: [DONE]\n\n",
                ]
            ),
            holdback_chars=64,
        )

        raw_body = b"".join(body)
        encoded = raw_body.decode("utf-8")
        events = _decode_sse_body([raw_body])
        self.assertEqual(status, 200)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["error"]["type"], "sensitive_data_blocked")
        self.assertNotIn(raw_secret, encoded)
        self.assertNotIn("api_abcdef", encoded)
        self.assertNotIn("ghijklmnopqrstuvwxyz", encoded)
        self.assertNotIn("[DONE]", events)

    def test_streamed_tool_call_redaction_preserves_json_shapes(self):
        firewall = Firewall(load_policy("policies/dev.yaml"))
        cases = [
            (
                "{\"card\":4111111111111111,\"note\":\"safe\"}",
                lambda arguments: self.assertEqual(
                    json.loads(arguments),
                    {"card": "<CREDIT_CARD:REDACTED>", "note": "safe"},
                ),
            ),
            (
                "\"api_LSDF_FIXTURE_TOKEN_000000\"",
                lambda arguments: self.assertEqual(
                    json.loads(arguments),
                    "<API_KEY:REDACTED>",
                ),
            ),
            (
                "{\"token\":\"api_LSDF_FIXTURE_TOKEN_000000\"}",
                lambda arguments: self.assertEqual(
                    json.loads(arguments),
                    {"token": "<API_KEY:REDACTED>"},
                ),
            ),
        ]
        for raw_arguments, assertion in cases:
            with self.subTest(raw_arguments=raw_arguments):
                status, _response_headers, body, _headers = handle_streaming_chat_completion(
                    {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
                    firewall,
                    lambda _payload, value=raw_arguments: self._forward_stream(
                        [
                            _sse(
                                {
                                    "choices": [
                                        {
                                            "index": 0,
                                            "delta": {
                                                "tool_calls": [
                                                    {
                                                        "index": 0,
                                                        "function": {
                                                            "arguments": value,
                                                        },
                                                    }
                                                ]
                                            },
                                        }
                                    ]
                                }
                            ),
                            b"data: [DONE]\n\n",
                        ]
                    ),
                    holdback_chars=64,
                )

                events = _decode_sse_body(body)
                arguments = _joined_tool_arguments(events, 0)
                self.assertEqual(status, 200)
                assertion(arguments)
                self.assertEqual(events[-1], "[DONE]")

    def test_interleaved_streamed_tool_calls_keep_separate_argument_state(self):
        status, _response_headers, body, _headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_stream(
                [
                    _sse(
                        {
                            "choices": [
                                {
                                    "index": 0,
                                    "delta": {
                                        "tool_calls": [
                                            {
                                                "index": 0,
                                                "function": {"arguments": "{\"a\":\""},
                                            },
                                            {
                                                "index": 1,
                                                "function": {"arguments": "{\"b\":\""},
                                            },
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
                                    "index": 1,
                                    "delta": {
                                        "tool_calls": [
                                            {
                                                "index": 0,
                                                "function": {"arguments": "{\"c\":\""},
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
                                            {"index": 0, "function": {"arguments": "one\"}"}},
                                            {"index": 1, "function": {"arguments": "two\"}"}},
                                        ]
                                    },
                                },
                                {
                                    "index": 1,
                                    "delta": {
                                        "tool_calls": [
                                            {
                                                "index": 0,
                                                "function": {"arguments": "three\"}"},
                                            }
                                        ]
                                    },
                                },
                            ]
                        }
                    ),
                    b"data: [DONE]\n\n",
                ]
            ),
            holdback_chars=64,
        )

        events = _decode_sse_body(body)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(_joined_tool_arguments(events, 0, choice_index=0)), {"a": "one"})
        self.assertEqual(json.loads(_joined_tool_arguments(events, 1, choice_index=0)), {"b": "two"})
        self.assertEqual(json.loads(_joined_tool_arguments(events, 0, choice_index=1)), {"c": "three"})
        self.assertEqual(events[-1], "[DONE]")

    def test_premature_eof_flushes_safe_tool_arguments_before_error(self):
        status, _response_headers, body, _headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_stream(
                [
                    _sse(
                        {
                            "choices": [
                                {
                                    "index": 0,
                                    "delta": {
                                        "tool_calls": [
                                            {
                                                "index": 0,
                                                "function": {
                                                    "arguments": "{\"query\":\"safe\"}",
                                                },
                                            }
                                        ]
                                    },
                                }
                            ]
                        }
                    )
                ]
            ),
            holdback_chars=64,
        )

        events = _decode_sse_body(body)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(_joined_tool_arguments(events, 0)), {"query": "safe"})
        self.assertEqual(events[-1]["error"]["type"], "upstream_stream_error")
        self.assertEqual(events[-1]["lsdf"]["stream_state"], "upstream_eof")

    def test_malformed_streamed_tool_arguments_emit_error_without_raw_release(self):
        status, _response_headers, body, _headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_stream(
                [
                    _sse(
                        {
                            "choices": [
                                {
                                    "index": 0,
                                    "delta": {
                                        "tool_calls": [
                                            {
                                                "index": 0,
                                                "function": {"arguments": "{\"query\":\"safe"},
                                            }
                                        ]
                                    },
                                }
                            ]
                        }
                    ),
                    b"data: [DONE]\n\n",
                ]
            ),
            holdback_chars=64,
        )

        encoded = b"".join(body).decode("utf-8")
        events = _decode_sse_body([encoded.encode("utf-8")])
        self.assertEqual(status, 200)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["error"]["type"], "upstream_stream_error")
        self.assertEqual(events[0]["lsdf"]["stream_state"], "malformed_tool_call_arguments")
        self.assertNotIn("safe", encoded)
        self.assertNotIn("[DONE]", events)

    def test_failing_audit_sink_does_not_break_safe_stream_done(self):
        status, _response_headers, body, _headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_stream(
                [
                    _sse({"choices": [{"index": 0, "delta": {"content": "safe"}}]}),
                    b"data: [DONE]\n\n",
                ]
            ),
            audit_sink=_FailingAuditSink(),
        )

        events = _decode_sse_body(body)
        self.assertEqual(status, 200)
        self.assertEqual(_joined_stream_field(events, "content"), "safe")
        self.assertEqual(events[-1], "[DONE]")

    def test_failing_audit_sink_does_not_break_stream_terminal_block(self):
        status, _response_headers, body, _headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_stream(
                [
                    _sse(
                        {
                            "choices": [
                                {
                                    "index": 0,
                                    "delta": {
                                        "reasoning_content": "Use api_LSDF_FIXTURE_TOKEN_000000"
                                    },
                                }
                            ]
                        }
                    ),
                    b"data: [DONE]\n\n",
                ]
            ),
            audit_sink=_FailingAuditSink(),
        )

        events = _decode_sse_body(body)
        self.assertEqual(status, 200)
        self.assertEqual(events[0]["error"]["type"], "sensitive_data_blocked")

    def test_streaming_upstream_open_transport_error_returns_502(self):
        def fail(_payload):
            raise urllib.error.URLError("connection refused")

        status, response_headers, body, headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            fail,
        )

        self.assertEqual(status, 502)
        self.assertEqual(response_headers["content-type"], "application/json")
        self.assertEqual(headers["x-lsdf-blocked"], "false")
        self.assertEqual(
            json.loads(b"".join(body))["error"]["type"],
            "upstream_transport_error",
        )

    def test_forward_upstream_stream_transport_error_records_metric(self):
        config = GatewayConfig(
            policy_path=None,
            policy_profile="default",
            upstream_base_url="http://upstream.example",
        )
        metrics = MetricsRecorder(enabled=True)

        with patch(
            "lsdf.gateway.urllib.request.urlopen",
            side_effect=urllib.error.URLError("connection refused"),
        ):
            status, _response_headers, body, _headers = handle_streaming_chat_completion(
                {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
                self.firewall,
                lambda payload: forward_upstream_stream(payload, "/v1/chat/completions", config),
                metrics=metrics,
            )

        self.assertEqual(status, 502)
        self.assertEqual(json.loads(b"".join(body))["error"]["type"], "upstream_transport_error")
        self.assertEqual(
            metrics.to_dict()["counters"][
                "gateway_upstream_errors_total{error_type=upstream_transport_error,stream=True}"
            ],
            1,
        )

    def test_mid_stream_transport_error_flushes_safe_tail_then_errors(self):
        def failing_chunks():
            yield _sse({"choices": [{"index": 0, "delta": {"content": "safe tail"}}]})
            raise OSError("connection reset")

        status, _response_headers, body, _headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_stream(failing_chunks()),
            holdback_chars=64,
            audit_sink=_FailingAuditSink(),
        )

        events = _decode_sse_body(body)
        self.assertEqual(status, 200)
        self.assertEqual(_joined_stream_field(events, "content"), "safe tail")
        self.assertEqual(events[-1]["error"]["type"], "upstream_transport_error")
        self.assertEqual(events[-1]["lsdf"]["stream_state"], "upstream_transport_error")

    def test_mid_stream_transport_error_with_blocked_tail_leaks_no_raw_text(self):
        def failing_chunks():
            yield _sse(
                {
                    "choices": [
                        {
                            "index": 0,
                            "delta": {
                                "reasoning_content": "Use api_LSDF_FIXTURE_TOKEN_000000"
                            },
                        }
                    ]
                }
            )
            raise OSError("connection reset")

        status, _response_headers, body, _headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_stream(failing_chunks()),
            holdback_chars=64,
        )

        encoded = b"".join(body).decode("utf-8")
        events = _decode_sse_body([encoded.encode("utf-8")])
        self.assertEqual(status, 200)
        self.assertEqual(events[0]["error"]["type"], "sensitive_data_blocked")
        self.assertNotIn("api_LSDF_FIXTURE_TOKEN_000000", encoded)
        self.assertNotIn("upstream_transport_error", encoded)

    def _forward_stream(self, chunks):
        self.forward_count += 1
        return 200, {"content-type": "text/event-stream"}, chunks

    def _forward_non_sse_json(self, payload):
        self.forward_count += 1
        return 200, {"content-type": "application/json"}, [json.dumps(payload).encode("utf-8")]


class StreamingGatewayHttpTests(unittest.TestCase):
    def test_http_streaming_gateway_redacts_and_preserves_done(self):
        raw_secret = "api_LSDF_FIXTURE_TOKEN_000000"
        status, headers, body = self._run_gateway_stream(
            [
                _sse({"choices": [{"index": 0, "delta": {"content": "token api_abcdef"}}]}),
                _sse({"choices": [{"index": 0, "delta": {"content": "ghijklmnopqrstuvwxyz"}}]}),
                b"data: [DONE]\n\n",
            ],
            holdback_chars=64,
        )

        events = _decode_sse_body([body])
        encoded = body.decode("utf-8")
        self.assertEqual(status, 200)
        self.assertIn("text/event-stream", headers.get("content-type", ""))
        self.assertNotIn("content-length", {key.lower(): value for key, value in headers.items()})
        self.assertNotIn(raw_secret, encoded)
        self.assertIn("<API_KEY:REDACTED>", encoded)
        self.assertEqual(events[-1], "[DONE]")

    def test_http_streaming_gateway_terminal_block_closes_without_done(self):
        status, _headers, body = self._run_gateway_stream(
            [
                _sse({"choices": [{"index": 0, "delta": {"content": "safe held text"}}]}),
                _sse(
                    {
                        "choices": [
                            {
                                "index": 0,
                                "delta": {
                                    "reasoning_content": "Use api_LSDF_FIXTURE_TOKEN_000000"
                                },
                            }
                        ]
                    }
                ),
                b"data: [DONE]\n\n",
            ],
            holdback_chars=64,
        )

        events = _decode_sse_body([body])
        self.assertEqual(status, 200)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["error"]["type"], "sensitive_data_blocked")
        self.assertNotIn("safe held text", body.decode("utf-8"))
        self.assertNotIn("[DONE]", events)

    def _run_gateway_stream(self, upstream_chunks, *, holdback_chars):
        upstream_server = _start_test_server(_upstream_handler(upstream_chunks))
        upstream_url = _server_url(upstream_server)
        firewall = Firewall(load_policy("policies/default.yaml"))

        class Handler(LSDFGatewayHandler):
            gateway_config = GatewayConfig(
                policy_path=None,
                policy_profile="default",
                upstream_base_url=upstream_url,
                stream_holdback_chars=holdback_chars,
            )
            gateway_firewall = firewall

        gateway_server = _start_test_server(Handler)
        gateway_url = _server_url(gateway_server)
        try:
            request = urllib.request.Request(
                f"{gateway_url}/v1/chat/completions",
                data=json.dumps(
                    {"stream": True, "messages": [{"role": "user", "content": "hello"}]}
                ).encode("utf-8"),
                headers={"content-type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, dict(response.headers.items()), response.read()
        finally:
            gateway_server.shutdown()
            gateway_server.server_close()
            upstream_server.shutdown()
            upstream_server.server_close()


class GatewayConfigTests(unittest.TestCase):
    def test_cli_policy_overrides_env_policy_and_profile(self):
        config = resolve_gateway_config(
            policy_path="policies/dev.yaml",
            policy_profile="strict",
            upstream_base_url="http://cli.example",
            environ={
                "LSDF_POLICY": "policies/strict.yaml",
                "LSDF_PROFILE": "healthcare",
                "LSDF_UPSTREAM_BASE_URL": "http://env.example",
            },
        )

        self.assertEqual(config.policy_path, "policies/dev.yaml")
        self.assertEqual(config.policy_profile, "default")

    def test_env_policy_overrides_cli_and_env_profile(self):
        config = resolve_gateway_config(
            policy_profile="dev",
            upstream_base_url="http://cli.example",
            environ={
                "LSDF_POLICY": "policies/strict.yaml",
                "LSDF_PROFILE": "healthcare",
            },
        )

        self.assertEqual(config.policy_path, "policies/strict.yaml")
        self.assertEqual(config.policy_profile, "default")

    def test_cli_profile_overrides_env_profile(self):
        config = resolve_gateway_config(
            policy_profile="strict",
            upstream_base_url="http://cli.example",
            environ={"LSDF_PROFILE": "dev"},
        )

        self.assertIsNone(config.policy_path)
        self.assertEqual(config.policy_profile, "strict")

    def test_env_profile_used_without_explicit_policy_or_profile(self):
        config = resolve_gateway_config(
            upstream_base_url="http://cli.example",
            environ={"LSDF_PROFILE": "monitor"},
        )

        self.assertIsNone(config.policy_path)
        self.assertEqual(config.policy_profile, "monitor")

    def test_cli_upstream_values_override_env(self):
        config = resolve_gateway_config(
            upstream_base_url="http://cli.example/",
            upstream_api_key="cli-key",
            environ={
                "LSDF_UPSTREAM_BASE_URL": "http://env.example",
                "LSDF_UPSTREAM_API_KEY": "env-key",
            },
        )

        self.assertEqual(config.upstream_base_url, "http://cli.example")
        self.assertEqual(config.upstream_api_key, "cli-key")

    def test_missing_upstream_base_url_fails_cleanly(self):
        with self.assertRaisesRegex(
            GatewayConfigError,
            "Missing --upstream-base-url or LSDF_UPSTREAM_BASE_URL",
        ):
            resolve_gateway_config(environ={})

    def test_stream_holdback_can_be_configured_from_env(self):
        config = resolve_gateway_config(
            upstream_base_url="http://cli.example",
            environ={"LSDF_STREAM_HOLDBACK_CHARS": "64"},
        )

        self.assertEqual(config.stream_holdback_chars, 64)

    def test_audit_jsonl_path_can_be_configured_from_env(self):
        config = resolve_gateway_config(
            upstream_base_url="http://cli.example",
            environ={"LSDF_AUDIT_JSONL_PATH": "audit/events.jsonl"},
        )

        self.assertEqual(config.audit_jsonl_path, "audit/events.jsonl")

    def test_stream_holdback_must_be_non_negative(self):
        with self.assertRaisesRegex(
            GatewayConfigError,
            "LSDF_STREAM_HOLDBACK_CHARS must be non-negative",
        ):
            resolve_gateway_config(
                upstream_base_url="http://cli.example",
                environ={"LSDF_STREAM_HOLDBACK_CHARS": "-1"},
            )



class UpstreamForwardingTests(unittest.TestCase):
    def test_authorization_header_is_forwarded_to_upstream(self):
        config = GatewayConfig(
            policy_path=None,
            policy_profile="default",
            upstream_base_url="http://upstream.example",
            upstream_api_key="secret-key",
        )
        captured = {}

        def fake_urlopen(request, timeout):
            captured["url"] = request.full_url
            captured["method"] = request.get_method()
            captured["body"] = json.loads(request.data)
            captured["authorization"] = request.get_header("Authorization")
            captured["timeout"] = timeout
            return _FakeUrlopenResponse(
                200,
                {"content-type": "application/json"},
                b'{"choices":[{"message":{"content":"ok"}}]}',
            )

        with patch("lsdf.gateway.urllib.request.urlopen", fake_urlopen):
            status, headers, body = forward_upstream(
                {"messages": [{"role": "user", "content": "hi"}]},
                "/v1/chat/completions",
                config,
            )

        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/json")
        self.assertIn(b'"ok"', body)
        self.assertEqual(captured["url"], "http://upstream.example/v1/chat/completions")
        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["body"]["messages"][0]["content"], "hi")
        self.assertEqual(captured["authorization"], "Bearer secret-key")
        self.assertEqual(captured["timeout"], 120)

    def test_openai_style_base_url_does_not_duplicate_v1_path(self):
        config = GatewayConfig(
            policy_path=None,
            policy_profile="default",
            upstream_base_url="https://openrouter.ai/api/v1",
        )
        captured = {}

        def fake_urlopen(request, timeout):
            captured["url"] = request.full_url
            return _FakeUrlopenResponse(
                200,
                {"content-type": "application/json"},
                b'{"choices":[{"message":{"content":"ok"}}]}',
            )

        with patch("lsdf.gateway.urllib.request.urlopen", fake_urlopen):
            status, _headers, _body = forward_upstream(
                {"messages": [{"role": "user", "content": "hi"}]},
                "/v1/chat/completions",
                config,
            )

        self.assertEqual(status, 200)
        self.assertEqual(captured["url"], "https://openrouter.ai/api/v1/chat/completions")

    def test_versioned_provider_prefix_with_openai_suffix_does_not_duplicate_v1(self):
        config = GatewayConfig(
            policy_path=None,
            policy_profile="default",
            upstream_base_url="https://api.deepinfra.com/v1/openai",
        )
        captured = {}

        def fake_urlopen(request, timeout):
            captured["url"] = request.full_url
            return _FakeUrlopenResponse(
                200,
                {"content-type": "application/json"},
                b'{"choices":[{"message":{"content":"ok"}}]}',
            )

        with patch("lsdf.gateway.urllib.request.urlopen", fake_urlopen):
            status, _headers, _body = forward_upstream(
                {"messages": [{"role": "user", "content": "hi"}]},
                "/v1/chat/completions",
                config,
            )

        self.assertEqual(status, 200)
        self.assertEqual(captured["url"], "https://api.deepinfra.com/v1/openai/chat/completions")

    def test_v1_in_hostname_is_not_treated_as_a_versioned_base_path(self):
        self.assertEqual(
            _join_upstream_url("https://v1.example", "/v1/chat/completions"),
            "https://v1.example/v1/chat/completions",
        )

    def test_openai_style_base_url_join_applies_to_stream_forwarding(self):
        config = GatewayConfig(
            policy_path=None,
            policy_profile="default",
            upstream_base_url="https://openrouter.ai/api/v1",
        )
        captured = {}

        def fake_urlopen(request, timeout):
            captured["url"] = request.full_url
            return _FakeUrlopenResponse(
                200,
                {"content-type": "text/event-stream"},
                b"data: [DONE]\n\n",
            )

        with patch("lsdf.gateway.urllib.request.urlopen", fake_urlopen):
            status, _headers, body = forward_upstream_stream(
                {"stream": True, "messages": [{"role": "user", "content": "hi"}]},
                "/v1/chat/completions",
                config,
            )

        self.assertEqual(status, 200)
        self.assertEqual(captured["url"], "https://openrouter.ai/api/v1/chat/completions")
        self.assertEqual(b"".join(body), b"data: [DONE]\n\n")


class _ForwardRecorder:
    def __init__(self, response_payload):
        self.response_payload = response_payload
        self.payloads = []

    def __call__(self, payload):
        self.payloads.append(payload)
        return (
            200,
            {"content-type": "application/json"},
            json.dumps(self.response_payload).encode("utf-8"),
        )


class _FakeUrlopenResponse:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, size=None):
        if size is None or size < 0:
            chunk = self.body
            self.body = b""
            return chunk
        chunk = self.body[:size]
        self.body = self.body[size:]
        return chunk

    def close(self):
        return None


class _FailingAuditSink:
    def write(self, event):
        raise OSError("audit unavailable")


def _sse(payload):
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n".encode("utf-8")


def _decode_sse_body(body):
    raw = b"".join(body).decode("utf-8")
    events = []
    for block in raw.strip().split("\n\n"):
        data_lines = []
        for line in block.splitlines():
            if line.startswith("data:"):
                data = line[5:]
                if data.startswith(" "):
                    data = data[1:]
                data_lines.append(data)
        data = "\n".join(data_lines)
        if data == "[DONE]":
            events.append(data)
        elif data:
            events.append(json.loads(data))
    return events


def _joined_stream_field(events, field):
    text = ""
    for event in events:
        if not isinstance(event, dict):
            continue
        for choice in event.get("choices", []):
            text += choice.get("delta", {}).get(field, "")
    return text


def _tool_argument_events(events):
    return [
        event
        for event in events
        if isinstance(event, dict)
        for choice in event.get("choices", [])
        for tool_call in choice.get("delta", {}).get("tool_calls", [])
        if isinstance(tool_call, dict)
        and isinstance(tool_call.get("function"), dict)
        and "arguments" in tool_call["function"]
    ]


def _joined_tool_arguments(events, tool_call_index, *, choice_index=0):
    text = ""
    for event in events:
        if not isinstance(event, dict):
            continue
        for choice in event.get("choices", []):
            if choice.get("index", 0) != choice_index:
                continue
            for tool_call in choice.get("delta", {}).get("tool_calls", []):
                if not isinstance(tool_call, dict):
                    continue
                if tool_call.get("index", 0) != tool_call_index:
                    continue
                function = tool_call.get("function", {})
                if isinstance(function, dict):
                    text += function.get("arguments", "")
    return text


def _start_test_server(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _server_url(server):
    host, port = server.server_address
    return f"http://{host}:{port}"


def _read_jsonl(path):
    return [
        json.loads(line)
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _upstream_handler(chunks):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("content-length", "0"))
            self.rfile.read(length)
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.end_headers()
            for chunk in chunks:
                self.wfile.write(chunk)
                self.wfile.flush()

        def log_message(self, format, *args):
            return

    return Handler


class StreamChunkInspectionMetricsTests(unittest.TestCase):
    """Per-chunk SSE inspection timing.

    True SSE chunk inspection in `streaming.py` was previously untimed, while
    `response_inspection_ms` only fired on the non-SSE fallback path. Two
    metrics — `stream_chunk_inspection_ms` for content holdback and
    `stream_tool_call_inspection_ms` for tool-call argument reassembly —
    fire from inside the streaming state classes when a metrics recorder is
    plumbed from the gateway.
    """

    def setUp(self):
        self.firewall = Firewall(load_policy("policies/default.yaml"))
        self.forward_count = 0

    def _forward_stream(self, chunks):
        self.forward_count += 1
        return 200, {"content-type": "text/event-stream"}, chunks

    def _stream_chunk_inspection_count(self, snapshot):
        durations = snapshot.get("durations", {})
        return sum(
            entry.get("count", 0)
            for key, entry in durations.items()
            if key.startswith("stream_chunk_inspection_ms")
        )

    def _stream_tool_call_inspection_count(self, snapshot):
        durations = snapshot.get("durations", {})
        return sum(
            entry.get("count", 0)
            for key, entry in durations.items()
            if key.startswith("stream_tool_call_inspection_ms")
        )

    def test_sse_content_stream_emits_chunk_inspection_observations(self):
        metrics = MetricsRecorder(enabled=True)

        status, _response_headers, body, _headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_stream(
                [
                    _sse({"choices": [{"index": 0, "delta": {"content": "hello "}}]}),
                    _sse({"choices": [{"index": 0, "delta": {"content": "world"}}]}),
                    b"data: [DONE]\n\n",
                ]
            ),
            holdback_chars=4,
            metrics=metrics,
        )

        list(body)  # exhaust the generator so all timer context-managers exit
        self.assertEqual(status, 200)
        snapshot = metrics.to_dict()
        self.assertGreaterEqual(
            self._stream_chunk_inspection_count(snapshot),
            2,
            "expected at least one stream_chunk_inspection_ms observation per "
            "content delta; got "
            f"{snapshot.get('durations', {})}",
        )

    def test_sse_chunk_inspection_carries_surface_label(self):
        metrics = MetricsRecorder(enabled=True)

        status, _response_headers, body, _headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_stream(
                [
                    _sse({"choices": [{"index": 0, "delta": {"content": "harmless"}}]}),
                    b"data: [DONE]\n\n",
                ]
            ),
            holdback_chars=4,
            metrics=metrics,
        )

        list(body)
        self.assertEqual(status, 200)
        snapshot = metrics.to_dict()
        durations = snapshot.get("durations", {})
        keys_with_surface = [
            key
            for key in durations
            if key.startswith("stream_chunk_inspection_ms") and "surface=" in key
        ]
        self.assertTrue(
            keys_with_surface,
            f"expected at least one stream_chunk_inspection_ms entry with a "
            f"surface label; got {durations}",
        )

    def test_tool_call_inspection_metric_not_double_counted_at_flush(self):
        """Regression: the tool-call flush path used to re-run _inspect_pending
        and emit a second timer observation per state at [DONE], inflating
        stream_tool_call_inspection_ms counts by 2x. flush_with_preflight
        now reuses the preflight result directly — no second scan, no
        second timer observation."""
        metrics = MetricsRecorder(enabled=True)

        status, _response_headers, body, _headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_stream(
                [
                    _sse(
                        {
                            "choices": [
                                {
                                    "index": 0,
                                    "delta": {
                                        "tool_calls": [
                                            {
                                                "index": 0,
                                                "function": {
                                                    "arguments": '{"city":"Paris"}'
                                                },
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
                                    "delta": {},
                                    "finish_reason": "tool_calls",
                                }
                            ]
                        }
                    ),
                    b"data: [DONE]\n\n",
                ]
            ),
            holdback_chars=4,
            metrics=metrics,
        )

        list(body)
        self.assertEqual(status, 200)
        snapshot = metrics.to_dict()
        # One logical tool-call inspection happened across the two SSE events;
        # the timer observation count must equal logical inspections, not
        # logical-inspections × redundant-internal-passes.
        self.assertEqual(
            self._stream_tool_call_inspection_count(snapshot),
            1,
            f"expected exactly 1 stream_tool_call_inspection_ms observation; "
            f"got {snapshot.get('durations', {})}",
        )

    def test_no_metrics_when_recorder_disabled(self):
        # Disabled recorder should not emit observations even when the
        # streaming path runs end-to-end. Regression guard against accidentally
        # bypassing the enabled-flag in a future refactor.
        metrics = MetricsRecorder(enabled=False)

        status, _response_headers, body, _headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: self._forward_stream(
                [
                    _sse({"choices": [{"index": 0, "delta": {"content": "harmless"}}]}),
                    b"data: [DONE]\n\n",
                ]
            ),
            holdback_chars=4,
            metrics=metrics,
        )

        list(body)
        self.assertEqual(status, 200)
        snapshot = metrics.to_dict()
        self.assertEqual(self._stream_chunk_inspection_count(snapshot), 0)



class _EnforcementScanner:
    def scan(self, surface):
        from lsdf.types import Finding
        if "detector-failure" in surface.value:
            raise OSError("synthetic diagnostic detail must remain private")
        if "tripwire" not in surface.value:
            return []
        start = surface.value.index("tripwire")
        return [Finding("US_SSN", surface.name, surface.pointer, start, start + 8, "tripwire", 1.0, surface.json_pointer)]


class _CapturedAudit:
    def __init__(self):
        self.events = []

    def write(self, event):
        self.events.append(event)


def _enforcement_firewall(on_fail="exception"):
    from lsdf.policy import AuditConfig, Policy, Rule
    return Firewall(Policy(
        version="0.2", name="gateway-enforcement", mode="monitor",
        entities={"US_SSN"}, surfaces={"input.messages", "output.content", "output.stream_chunk", "output.reasoning", "output.tool_calls.arguments"},
        rules=[Rule("enforcement", {"entity": "US_SSN"}, "redact", on_fail=on_fail)],
        audit=AuditConfig(),
    ), scanner=_EnforcementScanner())


class GatewayInspectionFailureTests(unittest.TestCase):
    def test_real_http_policy_exceptions_have_safe_status_and_audit(self):
        import http.client
        import io
        from contextlib import redirect_stderr

        sink = _CapturedAudit()
        forwarded = []

        class Handler(LSDFGatewayHandler):
            gateway_config = GatewayConfig(None, "default", "http://127.0.0.1:1")
            gateway_firewall = _enforcement_firewall()
            gateway_audit_sink = sink

            def _forward(self, payload):
                forwarded.append(payload)
                return 200, {"content-type": "application/json"}, b"{}"

            def _forward_stream(self, payload):
                forwarded.append(payload)
                return 200, {"content-type": "text/event-stream"}, [b"data: [DONE]\n\n"]

        with redirect_stderr(io.StringIO()) as stderr:
            server = _start_test_server(Handler)
            try:
                for streaming in (False, True):
                    with self.subTest(stream=streaming):
                        conn = http.client.HTTPConnection(*server.server_address, timeout=3)
                        try:
                            conn.request("POST", "/v1/chat/completions", json.dumps({"stream": streaming, "messages": [{"role": "user", "content": "tripwire"}]}), {"content-type": "application/json"})
                            response = conn.getresponse()
                            body = response.read().decode()
                            self.assertEqual(response.status, 403)
                            self.assertEqual(json.loads(body)["error"]["type"], "policy_enforcement_error")
                            self.assertNotIn("tripwire", body)
                        finally:
                            conn.close()
            finally:
                server.shutdown()
                server.server_close()
        self.assertEqual(forwarded, [])
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(len(sink.events), 2)
        self.assertTrue(all(event["outcome"] == "inspection_failed" and event["blocked"] for event in sink.events))
        self.assertNotIn("tripwire", json.dumps(sink.events))

    def test_response_failures_are_safe_for_json_and_stream_fallback(self):
        for streaming in (False, True):
            for text, expected_status, error_type in (("tripwire", 502, "policy_enforcement_error"), ("detector-failure", 500, "inspection_error")):
                with self.subTest(stream=streaming, error_type=error_type):
                    sink = _CapturedAudit()
                    response = json.dumps({"choices": [{"message": {"content": text}}]}).encode()
                    handle = handle_streaming_chat_completion if streaming else handle_chat_completion
                    result = handle(
                        {"messages": [{"role": "user", "content": "hello"}]},
                        _enforcement_firewall(),
                        lambda payload: (200, {"content-type": "application/json"}, [response] if streaming else response),
                        audit_sink=sink,
                    )
                    status, _, body, headers = result
                    body = b"".join(body) if streaming else body
                    self.assertEqual(status, expected_status)
                    self.assertEqual(json.loads(body)["error"]["type"], error_type)
                    self.assertEqual(headers["x-lsdf-blocked"], "true")
                    self.assertEqual(sink.events[-1]["outcome"], "inspection_failed")
                    self.assertNotIn(text, body.decode())
                    self.assertNotIn("synthetic diagnostic detail", body.decode() + json.dumps(sink.events))

    def test_request_detector_failure_and_audit_failure_remain_safe(self):
        import io
        from contextlib import redirect_stderr
        from unittest.mock import Mock

        for streaming in (False, True):
            with self.subTest(stream=streaming), redirect_stderr(io.StringIO()) as stderr:
                forward = Mock()
                handle = handle_streaming_chat_completion if streaming else handle_chat_completion
                status, _, body, _ = handle(
                    {"messages": [{"role": "user", "content": "detector-failure"}]},
                    _enforcement_firewall(), forward, audit_sink=_FailingAuditSink(),
                )
                body = b"".join(body) if streaming else body
                self.assertEqual(status, 500)
                self.assertEqual(json.loads(body)["error"]["type"], "inspection_error")
                forward.assert_not_called()
                self.assertIn("audit sink write failed", stderr.getvalue())
                self.assertNotIn("synthetic diagnostic detail", stderr.getvalue() + body.decode())

    def test_sse_detector_oserror_is_not_an_upstream_transport_error(self):
        sink = _CapturedAudit()
        _, _, body, _ = handle_streaming_chat_completion(
            {"messages": [{"role": "user", "content": "hello"}]},
            _enforcement_firewall(),
            lambda payload: (200, {"content-type": "text/event-stream"}, [_sse({"choices": [{"index": 0, "delta": {"content": "detector-failure"}}]}), b"data: [DONE]\n\n"]),
            audit_sink=sink,
        )
        events = _decode_sse_body(body)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["error"]["type"], "inspection_error")
        self.assertEqual(sink.events[-1]["outcome"], "inspection_failed")
        self.assertTrue(sink.events[-1]["blocked"])
        self.assertNotIn("synthetic diagnostic detail", json.dumps(events) + json.dumps(sink.events))

    def test_all_terminal_paths_withhold_pending_text_when_tool_inspection_raises(self):
        for ending in ("done", "finish", "eof", "malformed", "transport"):
            with self.subTest(ending=ending):
                sink = _CapturedAudit()
                def chunks():
                    yield _sse({"choices": [{"index": 0, "delta": {"content": "safe pending text"}}]})
                    yield _sse({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": '{"value":"tripwire"}'}}]}}]})
                    if ending == "done":
                        yield b"data: [DONE]\n\n"
                    elif ending == "finish":
                        yield _sse({"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]})
                    elif ending == "malformed":
                        yield b"data: {broken}\n\n"
                    elif ending == "transport":
                        raise OSError("upstream private detail")
                _, _, body, _ = handle_streaming_chat_completion(
                    {"messages": [{"role": "user", "content": "hello"}]},
                    _enforcement_firewall(),
                    lambda payload: (200, {"content-type": "text/event-stream"}, chunks()),
                    holdback_chars=128, audit_sink=sink,
                )
                events = _decode_sse_body(body)
                self.assertEqual(_joined_stream_field(events, "content"), "")
                self.assertEqual(events[-1]["error"]["type"], "policy_enforcement_error")
                self.assertNotIn("[DONE]", events)
                self.assertNotIn("tripwire", json.dumps(events) + json.dumps(sink.events))
                self.assertEqual(sink.events[-1]["stream_state"], "inspection_failed")


class TerminalStreamOrderingTests(unittest.TestCase):
    def test_terminal_text_preserves_order_for_every_text_field(self):
        for field in ("content", "reasoning", "reasoning_content", "reasoning_details"):
            with self.subTest(field=field):
                expected = "a" * 16 + "b" * 10
                chunks = [
                    _sse({"choices": [{"index": 0, "delta": {field: expected[:16]}}]}),
                    _sse({"choices": [{"index": 0, "delta": {field: expected[16:]}, "finish_reason": "stop"}]}),
                    b"data: [DONE]\n\n",
                ]
                _, _, body, _ = handle_streaming_chat_completion(
                    {"messages": [{"role": "user", "content": "hello"}]},
                    _enforcement_firewall(),
                    lambda payload: (200, {"content-type": "text/event-stream"}, chunks),
                    holdback_chars=8,
                )
                events = _decode_sse_body(body)
                self.assertEqual(_joined_stream_field(events, field), expected)
                self.assertEqual(events[-1], "[DONE]")
                finish = next(i for i, event in enumerate(events) if isinstance(event, dict) and any(choice.get("finish_reason") for choice in event.get("choices", [])))
                self.assertTrue(all(not _joined_stream_field([event], field) for event in events[finish:]))

    def test_all_terminal_choices_are_inspected_before_any_text_is_released(self):
        terminal = {"choices": [
            {"index": 0, "delta": {"content": "safe earlier choice"}, "finish_reason": "stop"},
            {"index": 1, "delta": {"content": "tripwire"}, "finish_reason": "stop"},
        ]}
        _, _, body, _ = handle_streaming_chat_completion(
            {"messages": [{"role": "user", "content": "hello"}]},
            _enforcement_firewall(on_fail="block"),
            lambda payload: (200, {"content-type": "text/event-stream"}, [_sse(terminal), b"data: [DONE]\n\n"]),
            holdback_chars=0,
        )
        events = _decode_sse_body(body)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["error"]["type"], "sensitive_data_blocked")
        self.assertEqual(_joined_stream_field(events, "content"), "")


class ManagementCredentialEncodingTests(unittest.TestCase):
    def test_non_ascii_headers_reject_with_401_and_server_remains_usable(self):
        import http.client
        class Handler(LSDFGatewayHandler):
            gateway_config = GatewayConfig(None, "default", "http://127.0.0.1:1", management_token="management-test")
        server = _start_test_server(Handler)
        try:
            cases = [
                ({"Authorization": "Bearer \u00e9"}, 401),
                ({"X-LSDF-Management-Token": "\u00e9"}, 401),
                ({"Authorization": "Bearer wrong"}, 401),
                ({"Authorization": "Bearer management-test"}, 200),
                ({"X-LSDF-Management-Token": "management-test"}, 200),
            ]
            for headers, expected in cases:
                with self.subTest(expected=expected):
                    conn = http.client.HTTPConnection(*server.server_address, timeout=3)
                    try:
                        conn.request("GET", "/lsdf/metrics?format=json", headers=headers)
                        response = conn.getresponse()
                        response.read()
                        self.assertEqual(response.status, expected)
                    finally:
                        conn.close()
        finally:
            server.shutdown()
            server.server_close()



if __name__ == "__main__":
    unittest.main()
