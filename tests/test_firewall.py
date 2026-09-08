import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from lsdf import Firewall, load_policy
from lsdf.policy import AuditConfig, Policy, Rule
from lsdf.surfaces import extract_surfaces


class FirewallTests(unittest.TestCase):
    def setUp(self):
        self.firewall = Firewall(load_policy("policies/default.yaml"))

    def test_tokenizes_ssn_in_input_message(self):
        result = self.firewall.inspect(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": "Please remember SSN 000-00-0000 for later.",
                    }
                ]
            }
        )

        content = result.transformed_payload["messages"][0]["content"]
        self.assertFalse(result.blocked)
        self.assertIn("<US_SSN:TOKEN>", content)
        self.assertNotIn("000-00-0000", content)

    def test_blocks_secret_in_tool_call_arguments(self):
        result = self.firewall.inspect(
            {
                "choices": [
                    {
                        "message": {
                            "tool_calls": [
                                {
                                    "function": {
                                        "name": "post_ticket",
                                        "arguments": "{\"token\":\"api_LSDF_FIXTURE_TOKEN_000000\"}",
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        )

        arguments = result.transformed_payload["choices"][0]["message"]["tool_calls"][0][
            "function"
        ]["arguments"]
        self.assertTrue(result.blocked)
        self.assertIn("<API_KEY:REDACTED>", arguments)
        self.assertNotIn("api_LSDF_FIXTURE_TOKEN_000000", arguments)
        json.loads(arguments)

    def test_tool_call_argument_json_leaf_transform_preserves_structure(self):
        result = self.firewall.inspect(
            {
                "choices": [
                    {
                        "message": {
                            "tool_calls": [
                                {
                                    "function": {
                                        "name": "update_patient",
                                        "arguments": "{\"patient\":{\"mrn\":\"MRN: LSDF-FIXTURE-00001\",\"note\":\"safe\"}}",
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        )

        arguments = result.transformed_payload["choices"][0]["message"]["tool_calls"][0][
            "function"
        ]["arguments"]
        parsed = json.loads(arguments)
        self.assertTrue(result.blocked)
        self.assertEqual(parsed["patient"]["note"], "safe")
        self.assertEqual(parsed["patient"]["mrn"], "<MRN:REDACTED>")

    def test_mixed_known_payload_scans_and_transforms_extra_fields(self):
        result = self.firewall.inspect(
            {
                "messages": [{"role": "user", "content": "hello"}],
                "metadata": {"note": "SSN 000-00-0000"},
            }
        )

        self.assertFalse(result.blocked)
        self.assertIn("<US_SSN:TOKEN>", result.transformed_payload["metadata"]["note"])
        self.assertNotIn("000-00-0000", result.transformed_payload["metadata"]["note"])

    def test_unknown_surface_can_be_overridden_for_response_payloads(self):
        result = self.firewall.inspect(
            {
                "choices": [{"message": {"content": "ok"}}],
                "metadata": {"secret": "api_LSDF_FIXTURE_TOKEN_000000"},
            },
            unknown_surface="output.content",
        )

        self.assertFalse(result.blocked)
        self.assertEqual(
            result.transformed_payload["metadata"]["secret"],
            "<API_KEY:REDACTED>",
        )

    def test_root_string_payload_can_be_inspected_and_redacted(self):
        result = self.firewall.inspect(
            "SSN 000-00-0000",
            unknown_surface="output.content",
        )

        self.assertFalse(result.blocked)
        self.assertEqual(result.transformed_payload, "SSN <US_SSN:REDACTED>")

    def test_root_numeric_payload_can_be_inspected_without_crashing(self):
        result = self.firewall.inspect(
            4111111111111111,
            unknown_surface="output.content",
        )

        self.assertFalse(result.blocked)
        self.assertEqual(result.transformed_payload, "<CREDIT_CARD:REDACTED>")

    def test_root_boolean_payload_can_be_inspected_without_crashing(self):
        result = self.firewall.inspect(True, unknown_surface="output.content")

        self.assertFalse(result.blocked)
        self.assertEqual(result.transformed_payload, True)
        self.assertEqual(result.findings, [])

    def test_unknown_scalar_extras_include_numbers_and_booleans(self):
        surfaces = extract_surfaces(
            {
                "messages": [{"role": "user", "content": "hello"}],
                "metadata": {"count": 42, "enabled": True},
            }
        )

        by_pointer = {surface.pointer: surface for surface in surfaces}
        self.assertEqual(by_pointer[("metadata", "count")].value, "42")
        self.assertEqual(by_pointer[("metadata", "count")].name, "input.messages")
        self.assertEqual(by_pointer[("metadata", "enabled")].value, "True")
        self.assertEqual(by_pointer[("metadata", "enabled")].name, "input.messages")

    def test_unknown_numeric_request_extra_uses_input_policy_semantics(self):
        result = self.firewall.inspect(
            {
                "messages": [{"role": "user", "content": "hello"}],
                "metadata": {"card": 4111111111111111},
            }
        )

        self.assertFalse(result.blocked)
        self.assertEqual(
            result.transformed_payload["metadata"]["card"],
            "<CREDIT_CARD:TOKEN>",
        )

    def test_unknown_numeric_response_extra_uses_output_policy_semantics(self):
        result = self.firewall.inspect(
            {
                "choices": [{"message": {"content": "ok"}}],
                "metadata": {"card": 4111111111111111},
            },
            unknown_surface="output.content",
        )

        self.assertFalse(result.blocked)
        self.assertEqual(
            result.transformed_payload["metadata"]["card"],
            "<CREDIT_CARD:REDACTED>",
        )

    def test_structured_message_content_is_transformed_at_leaf_pointer(self):
        result = self.firewall.inspect(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": "Please store SSN 000-00-0000."},
                            {"type": "image_url", "image_url": {"url": "https://example.com/a.png"}},
                        ],
                    }
                ]
            }
        )

        text = result.transformed_payload["messages"][0]["content"][0]["text"]
        self.assertFalse(result.blocked)
        self.assertIn("<US_SSN:TOKEN>", text)
        self.assertNotIn("000-00-0000", text)

    def test_request_side_assistant_tool_call_arguments_are_inspected(self):
        result = self.firewall.inspect(
            {
                "messages": [
                    {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "function": {
                                    "name": "send_webhook",
                                    "arguments": "{\"token\":\"api_LSDF_FIXTURE_TOKEN_000000\"}",
                                }
                            }
                        ],
                    }
                ]
            }
        )

        arguments = result.transformed_payload["messages"][0]["tool_calls"][0]["function"][
            "arguments"
        ]
        self.assertTrue(result.blocked)
        self.assertIn("<API_KEY:REDACTED>", arguments)
        self.assertNotIn("api_LSDF_FIXTURE_TOKEN_000000", arguments)
        json.loads(arguments)

    def test_numeric_json_tool_argument_leaf_is_scanned_and_transformed(self):
        result = self.firewall.inspect(
            {
                "choices": [
                    {
                        "message": {
                            "tool_calls": [
                                {
                                    "function": {
                                        "name": "charge_card",
                                        "arguments": "{\"card\":4111111111111111,\"note\":\"safe\"}",
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        )

        arguments = result.transformed_payload["choices"][0]["message"]["tool_calls"][0][
            "function"
        ]["arguments"]
        parsed = json.loads(arguments)
        self.assertTrue(result.blocked)
        self.assertEqual(parsed["card"], "<CREDIT_CARD:REDACTED>")
        self.assertEqual(parsed["note"], "safe")

    def test_root_json_string_tool_argument_is_transformed(self):
        result = self.firewall.inspect(
            {
                "choices": [
                    {
                        "message": {
                            "tool_calls": [
                                {
                                    "function": {
                                        "name": "send_token",
                                        "arguments": "\"api_LSDF_FIXTURE_TOKEN_000000\"",
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        )

        arguments = result.transformed_payload["choices"][0]["message"]["tool_calls"][0][
            "function"
        ]["arguments"]
        self.assertTrue(result.blocked)
        self.assertEqual(json.loads(arguments), "<API_KEY:REDACTED>")

    def test_audit_event_omits_raw_values(self):
        result = self.firewall.inspect(
            {"messages": [{"role": "user", "content": "SSN 000-00-0000"}]}
        )

        event = str(result.audit_event)
        self.assertNotIn("000-00-0000", event)
        self.assertNotIn("12...[REDACTED]...89", event)
        self.assertIn("evidence", event)

    def test_audit_can_omit_policy_decision_fields(self):
        policy = Policy(
            version="test",
            name="audit-minimal",
            mode="redact",
            entities={"US_SSN"},
            surfaces={"input.messages"},
            rules=[
                Rule(
                    id="tokenize-ssn",
                    match={"entity": "US_SSN", "surface": "input.messages"},
                    action="tokenize",
                )
            ],
            audit=AuditConfig(include_policy_decision=False),
        )
        result = Firewall(policy).inspect(
            {"messages": [{"role": "user", "content": "SSN 000-00-0000"}]}
        )

        decision = result.audit_event["decisions"][0]
        self.assertIn("finding", decision)
        self.assertNotIn("action", decision)
        self.assertNotIn("rule_id", decision)
        self.assertNotIn("severity", decision)

    def test_policy_rejects_store_raw_values_true(self):
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir, "policy.yaml")
            path.write_text(
                """
version: 0.2
name: unsafe-audit
detection: {entities: [US_SSN]}
action:
  mode: redact
  rules:
    - id: tokenize-ssn
      match: {entity: US_SSN, surface: input.messages}
      action: tokenize
audit:
  store_raw_values: true
""".strip(),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "store_raw_values=true is not supported"):
                load_policy(path)

    def test_policy_rejects_require_approval_action_until_workflow_exists(self):
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir, "policy.yaml")
            path.write_text(
                """
version: 0.2
name: unsupported-approval
detection: {entities: [SECRET]}
action:
  mode: redact
  rules:
    - id: manual-review
      match: {entity_in_category: SECRET, surface: input.messages}
      action: require_approval
""".strip(),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "no executable approval workflow"):
                load_policy(path)

    def test_credit_card_detector_requires_luhn_valid_number(self):
        invalid_result = self.firewall.inspect(
            {"messages": [{"role": "user", "content": "Order number 4111 1111 1111 1112"}]}
        )
        valid_result = self.firewall.inspect(
            {"messages": [{"role": "user", "content": "Card number 4111 1111 1111 1111"}]}
        )

        self.assertNotIn("CREDIT_CARD", {finding.entity for finding in invalid_result.findings})
        self.assertIn("CREDIT_CARD", {finding.entity for finding in valid_result.findings})
        self.assertIn("<CREDIT_CARD:TOKEN>", valid_result.transformed_payload["messages"][0]["content"])

    def test_entropy_scanner_redacts_redis_style_password_in_final_content(self):
        result = self.firewall.inspect(
            {
                "choices": [
                    {
                        "message": {
                            "content": "The leaked Redis password is R3d1s_Pr0d_2024!Secure."
                        }
                    }
                ]
            }
        )

        self.assertFalse(result.blocked)
        content = result.transformed_payload["choices"][0]["message"]["content"]
        self.assertIn("<OTHER_SECRET:REDACTED>", content)
        self.assertNotIn("R3d1s_Pr0d_2024!Secure", content)

    def test_entropy_scanner_skips_url_like_tokens(self):
        result = self.firewall.inspect(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": "Fetch from //api.example.com/v1 and parse config/settings.yml.",
                    }
                ]
            }
        )

        self.assertFalse(result.findings)

    def test_scans_reasoning_surface(self):
        result = self.firewall.inspect(
            {
                "choices": [
                    {
                        "message": {
                            "reasoning_content": "The password was R3d1s_Pr0d_2024!Secure."
                        }
                    }
                ]
            }
        )

        self.assertTrue(result.blocked)
        self.assertEqual(result.findings[0].surface, "output.reasoning")

    def test_scrubs_trace_surface(self):
        result = self.firewall.inspect(
            {
                "trace": {
                    "model_output": "Patient MRN: LSDF-FIXTURE-00001 should not reach Langfuse."
                }
            }
        )

        self.assertFalse(result.blocked)
        self.assertIn("<MRN:REDACTED>", str(result.transformed_payload))

    def test_medical_phi_supplement_redacts_lab_and_medication(self):
        result = self.firewall.inspect(
            {
                "choices": [
                    {
                        "message": {
                            "content": "Patient takes metformin 500mg and HbA1c 8.2% was noted."
                        }
                    }
                ]
            }
        )

        content = result.transformed_payload["choices"][0]["message"]["content"]
        self.assertFalse(result.blocked)
        self.assertIn("<MEDICATION:REDACTED>", content)
        self.assertIn("<LAB_VALUE:REDACTED>", content)
        self.assertNotIn("metformin 500mg", content)
        self.assertNotIn("HbA1c 8.2%", content)

    def test_monitor_mode_records_without_transforming_or_blocking(self):
        policy = Policy(
            version="test",
            name="monitor",
            mode="monitor",
            entities={"OTHER_SECRET"},
            surfaces={"output.content"},
            rules=[
                Rule(
                    id="monitor-secrets",
                    match={"entity": "OTHER_SECRET", "surface": "output.content"},
                    action="block",
                )
            ],
            audit=AuditConfig(),
        )
        result = Firewall(policy).inspect(
            {"choices": [{"message": {"content": "Password R3d1s_Pr0d_2024!Secure leaked."}}]}
        )

        self.assertFalse(result.blocked)
        self.assertIn("R3d1s_Pr0d_2024!Secure", str(result.transformed_payload))
        self.assertEqual(result.decisions[0].action, "block")

    def test_min_confidence_can_suppress_entropy_only_findings(self):
        policy = Policy(
            version="test",
            name="strict",
            mode="redact",
            entities={"OTHER_SECRET"},
            surfaces={"output.content"},
            rules=[
                Rule(
                    id="high-confidence-secret-only",
                    match={
                        "entity": "OTHER_SECRET",
                        "surface": "output.content",
                        "min_confidence": 0.90,
                    },
                    action="block",
                )
            ],
            audit=AuditConfig(),
        )
        result = Firewall(policy).inspect(
            {"choices": [{"message": {"content": "Password R3d1s_Pr0d_2024!Secure leaked."}}]}
        )

        self.assertFalse(result.blocked)
        self.assertFalse(result.decisions)


if __name__ == "__main__":
    unittest.main()
