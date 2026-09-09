import json
from dataclasses import replace
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from lsdf import Firewall, load_policy
from lsdf.audit import JsonlAuditSink
from lsdf.gateway import handle_chat_completion, handle_streaming_chat_completion
from lsdf.metrics import MetricsRecorder


class ResponseFramingTests(unittest.TestCase):
    def test_unsupported_bodies_are_withheld_in_both_response_paths(self):
        secret = "api_LSDF_FIXTURE_TOKEN_000000"
        bodies = [
            secret.encode(),
            json.dumps([{"credential": secret}]).encode(),
            json.dumps(secret).encode(),
            b"null",
            b"123",
            b"",
            b"{" + secret.encode(),
            b"\xff",
        ]
        for stream in (False, True):
            for raw_body in bodies:
                with self.subTest(stream=stream, body_length=len(raw_body)), TemporaryDirectory() as directory:
                    audit_path = Path(directory, "audit.jsonl")
                    metrics = MetricsRecorder(enabled=True)
                    firewall = Firewall(load_policy("policies/default.yaml"))
                    handler = handle_streaming_chat_completion if stream else handle_chat_completion
                    upstream_body = [raw_body] if stream else raw_body
                    status, response_headers, body, headers = handler(
                        {"stream": stream, "messages": [{"role": "user", "content": "hello"}]},
                        firewall,
                        lambda _payload: (200, {"content-type": "application/json", "x-unsafe": secret}, upstream_body),
                        audit_sink=JsonlAuditSink(audit_path),
                        metrics=metrics,
                    )
                    if stream:
                        body = b"".join(body)
                    self.assertEqual(status, 502)
                    self.assertEqual(response_headers, {"content-type": "application/json"})
                    self.assertEqual(json.loads(body)["error"]["type"], "invalid_upstream_response")
                    self.assertEqual(headers["x-lsdf-blocked"], "true")
                    self.assertEqual(headers["x-lsdf-decision-count"], "0")
                    self.assertNotIn(secret, body.decode())
                    audit_text = audit_path.read_text()
                    self.assertNotIn(secret, audit_text)
                    event = json.loads(audit_text.splitlines()[-1])
                    self.assertEqual(event["stage"], "response_validation")
                    self.assertTrue(event["blocked"])
                    self.assertEqual(event["error_type"], "invalid_upstream_response")
                    self.assertEqual(metrics.to_dict()["counters"][
                        f"gateway_upstream_errors_total{{error_type=invalid_upstream_response,stream={stream}}}"
                    ], 1)


    def test_monitor_mode_still_rejects_invalid_protocol_body(self):
        firewall = Firewall(replace(load_policy("policies/default.yaml"), mode="monitor"))
        status, _response_headers, body, headers = handle_chat_completion(
            {"messages": [{"role": "user", "content": "hello"}]},
            firewall,
            lambda _payload: (200, {"content-type": "text/plain"}, b"uninspected"),
        )
        self.assertEqual(status, 502)
        self.assertEqual(headers["x-lsdf-blocked"], "true")
        self.assertEqual(json.loads(body)["error"]["type"], "invalid_upstream_response")


if __name__ == "__main__":
    unittest.main()
