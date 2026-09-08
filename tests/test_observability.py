import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from lsdf import Firewall, load_policy, sanitize_observability
from lsdf.audit import JsonlAuditSink
from lsdf.policy import AuditConfig, Policy, Rule


class ObservabilitySanitizerTests(unittest.TestCase):
    def setUp(self):
        self.firewall = Firewall(load_policy("policies/default.yaml"))

    def test_sanitizes_nested_trace_log_and_scalar_leaves(self):
        payload = {
            "trace_id": "trace-1",
            "spans": [
                {
                    "name": "charge",
                    "attributes": {
                        "ssn": "000-00-0000",
                        "card": 4111111111111111,
                        "sampled": True,
                    },
                }
            ],
        }

        result = sanitize_observability(payload, self.firewall)

        attributes = result.transformed_payload["spans"][0]["attributes"]
        self.assertFalse(result.blocked)
        self.assertEqual(result.transformed_payload["trace_id"], "trace-1")
        self.assertEqual(attributes["sampled"], True)
        self.assertEqual(attributes["ssn"], "<US_SSN:REDACTED>")
        self.assertEqual(attributes["card"], "<CREDIT_CARD:REDACTED>")
        self.assertNotIn("000-00-0000", str(result.to_dict()))
        self.assertTrue({finding.surface for finding in result.findings} <= {"logs.traces"})

    def test_secret_observability_payload_blocks_without_raw_audit_values(self):
        raw_secret = "api_LSDF_FIXTURE_TOKEN_000000"

        result = sanitize_observability(
            {"event": "tool.dispatch", "token": raw_secret},
            self.firewall,
        )

        self.assertTrue(result.blocked)
        self.assertEqual(result.transformed_payload["token"], "<API_KEY:REDACTED>")
        self.assertNotIn(raw_secret, str(result.audit_event))

    def test_root_scalar_payload_can_be_sanitized(self):
        result = sanitize_observability("SSN 000-00-0000", self.firewall)

        self.assertEqual(result.transformed_payload, "SSN <US_SSN:REDACTED>")
        self.assertFalse(result.blocked)


class JsonlAuditSinkTests(unittest.TestCase):
    def test_jsonl_sink_appends_valid_raw_value_safe_events(self):
        raw_ssn = "000-00-0000"
        firewall = Firewall(load_policy("policies/default.yaml"))
        result = firewall.inspect({"messages": [{"role": "user", "content": f"SSN {raw_ssn}"}]})

        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir, "audit", "events.jsonl")
            sink = JsonlAuditSink(path)
            sink.write({"source": "test", "stage": "first", "audit_event": result.audit_event})
            sink.write({"source": "test", "stage": "second", "blocked": False})

            lines = path.read_text(encoding="utf-8").splitlines()

        self.assertEqual(len(lines), 2)
        events = [json.loads(line) for line in lines]
        self.assertEqual(events[0]["stage"], "first")
        self.assertEqual(events[1]["stage"], "second")
        self.assertNotIn(raw_ssn, "\n".join(lines))

    def test_jsonl_sink_preserves_policy_decision_omission(self):
        policy = Policy(
            version="test",
            name="audit-minimal",
            mode="redact",
            entities={"US_SSN"},
            surfaces={"input.messages"},
            rules=[
                Rule(
                    id="redact-ssn",
                    match={"entity": "US_SSN", "surface": "input.messages"},
                    action="tokenize",
                )
            ],
            audit=AuditConfig(include_policy_decision=False),
        )
        result = Firewall(policy).inspect(
            {"messages": [{"role": "user", "content": "SSN 000-00-0000"}]}
        )

        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir, "events.jsonl")
            JsonlAuditSink(path).write({"audit_event": result.audit_event})
            event_text = path.read_text(encoding="utf-8")

        self.assertNotIn('"action"', event_text)
        self.assertNotIn('"rule_id"', event_text)
        self.assertNotIn('"severity"', event_text)


if __name__ == "__main__":
    unittest.main()
