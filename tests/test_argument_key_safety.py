import json
import unittest
from tempfile import TemporaryDirectory

from lsdf import Firewall, load_policy
from lsdf.gateway import handle_chat_completion, handle_streaming_chat_completion
from lsdf.policy import AuditConfig, Policy, Rule
from lsdf.streaming import StreamingToolCallArgumentState, format_sse_event, iter_sse_events
from lsdf.surfaces import extract_surfaces
from lsdf.vault import EncryptedSqliteTokenVault, generate_vault_key


RAW_SECRET = "api_LSDF_FIXTURE_TOKEN_000000"


def _tool_argument_payload(arguments: str) -> dict:
    return {
        "messages": [
            {
                "role": "assistant",
                "tool_calls": [
                    {
                        "type": "function",
                        "function": {"name": "dispatch", "arguments": arguments},
                    }
                ],
            }
        ]
    }


def _policy(*, mode: str = "redact", action: str = "redact", on_fail: str | None = None) -> Policy:
    return Policy(
        version="0.2",
        name="argument-key-safety",
        mode=mode,
        entities={"API_KEY", "OTHER_SECRET"},
        surfaces={"output.tool_calls.arguments"},
        rules=[
            Rule(
                id="protect-argument-secrets",
                match={
                    "entity_any_of": ["API_KEY", "OTHER_SECRET"],
                    "surface": "output.tool_calls.arguments",
                },
                action=action,
                on_fail=on_fail,
            )
        ],
        audit=AuditConfig(),
    )


def _json_response(payload: dict) -> tuple[int, dict[str, str], bytes]:
    return 200, {"content-type": "application/json"}, json.dumps(payload).encode("utf-8")


def _sse(payload: dict) -> bytes:
    return format_sse_event(payload)


class ArgumentKeySurfaceTests(unittest.TestCase):
    def test_key_only_secret_is_detected_and_withheld(self):
        firewall = Firewall(load_policy("policies/default.yaml"))
        result = firewall.inspect(_tool_argument_payload(json.dumps({RAW_SECRET: "safe"})))

        self.assertTrue(result.blocked)
        self.assertIsNone(result.transformed_payload)
        self.assertTrue(any(finding.value == RAW_SECRET for finding in result.findings))

    def test_key_and_value_are_raw_safe_and_do_not_write_vault(self):
        with TemporaryDirectory() as tmpdir:
            vault = EncryptedSqliteTokenVault(f"{tmpdir}/tokens.sqlite", generate_vault_key())
            firewall = Firewall(_policy(action="tokenize"), token_vault=vault)
            result = firewall.inspect(
                _tool_argument_payload(json.dumps({RAW_SECRET: RAW_SECRET}))
            )

            serialized = json.dumps(result.to_dict())
            self.assertTrue(result.blocked)
            self.assertIsNone(result.transformed_payload)
            self.assertNotIn(RAW_SECRET, serialized)
            self.assertEqual(vault.status()["token_count"], 0)
            self.assertTrue(
                any(finding.argument_key_metadata for finding in result.findings)
            )
            self.assertTrue(
                all(
                    "api_LSDF_FIXTURE_TOKEN_000000" not in str(finding.safe_dict())
                    for finding in result.findings
                )
            )

    def test_benign_key_value_still_transforms_value_and_pointer_is_safe(self):
        firewall = Firewall(load_policy("policies/default.yaml"))
        raw_arguments = json.dumps({"query": "SSN 000-00-0000"})
        result = firewall.inspect(_tool_argument_payload(raw_arguments))

        arguments = result.transformed_payload["messages"][0]["tool_calls"][0]["function"][
            "arguments"
        ]
        self.assertIn("<US_SSN:REDACTED>", json.loads(arguments)["query"])
        value_findings = [finding for finding in result.findings if not finding.argument_key_metadata]
        self.assertTrue(value_findings)
        argument_surfaces = [
            surface
            for surface in extract_surfaces(_tool_argument_payload(raw_arguments))
            if surface.argument_key_metadata
        ]
        self.assertEqual([surface.value for surface in argument_surfaces], ["query"])
        self.assertEqual(argument_surfaces[0].safe_json_pointer, ("argument", "key", 0))
        self.assertEqual(value_findings[0].json_pointer, ("query",))
        self.assertEqual(value_findings[0].safe_dict()["json_pointer"], ["argument", "value", 0])

    def test_nested_key_and_value_safe_pointers_are_unique(self):
        surfaces = extract_surfaces(
            _tool_argument_payload(
                json.dumps({"outer": [{RAW_SECRET: "safe"}, {"other": "value"}]})
            )
        )
        argument_surfaces = [
            surface
            for surface in surfaces
            if surface.name == "output.tool_calls.arguments"
            and surface.safe_json_pointer is not None
        ]
        pointers = [surface.safe_json_pointer for surface in argument_surfaces]
        self.assertEqual(len(pointers), len(set(pointers)))
        self.assertIn(("argument", "key", 0), pointers)
        self.assertIn(("argument", "key", 0, 0, 0), pointers)
        self.assertIn(("argument", "key", 0, 1, 0), pointers)
        self.assertNotIn(RAW_SECRET, json.dumps(pointers))

    def test_json_gateway_withholds_argument_key_without_vault_write(self):
        with TemporaryDirectory() as tmpdir:
            vault = EncryptedSqliteTokenVault(f"{tmpdir}/tokens.sqlite", generate_vault_key())
            firewall = Firewall(_policy(action="tokenize"), token_vault=vault)
            response_payload = {
                "object": "chat.completion",
                "choices": [
                    {
                        "message": {
                            "content": "safe",
                            "tool_calls": [
                                {
                                    "type": "function",
                                    "function": {
                                        "name": "dispatch",
                                        "arguments": json.dumps({RAW_SECRET: RAW_SECRET}),
                                    },
                                }
                            ],
                        }
                    }
                ],
            }
            status, _headers, body, response_headers = handle_chat_completion(
                {"messages": [{"role": "user", "content": "hello"}]},
                firewall,
                lambda _payload: _json_response(response_payload),
            )

            self.assertEqual(status, 502)
            self.assertEqual(response_headers["x-lsdf-blocked"], "true")
            self.assertNotIn(RAW_SECRET, body.decode("utf-8"))
            self.assertEqual(vault.status()["token_count"], 0)

    def test_sse_streamed_argument_key_is_blocked_at_terminal_flush(self):
        firewall = Firewall(load_policy("policies/default.yaml"))
        chunks = [
            _sse(
                {
                    "choices": [
                        {
                            "index": 0,
                            "delta": {
                                "tool_calls": [
                                    {
                                        "index": 0,
                                        "function": {"arguments": f'{{"{RAW_SECRET}":"sa'},
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
                                        "function": {"arguments": 'fe"}'},
                                    }
                                ]
                            },
                        }
                    ]
                }
            ),
            b"data: [DONE]\n\n",
        ]
        _status, _headers, body, _response_headers = handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            firewall,
            lambda _payload: (200, {"content-type": "text/event-stream"}, chunks),
            holdback_chars=64,
        )
        events = [
            event.data if event.data == "[DONE]" else json.loads(event.data)
            for event in iter_sse_events(body)
        ]

        self.assertTrue(events)
        self.assertEqual(events[-1]["error"]["type"], "sensitive_data_blocked")
        self.assertNotIn("[DONE]", events)
        self.assertNotIn(RAW_SECRET, json.dumps(events))


class ArgumentKeyPolicyTests(unittest.TestCase):
    def test_monitor_and_observe_leave_key_payload_unchanged(self):
        payload = _tool_argument_payload(json.dumps({RAW_SECRET: "safe"}))
        for policy in (
            _policy(mode="monitor"),
            _policy(mode="redact", on_fail="observe"),
        ):
            with self.subTest(mode=policy.mode, on_fail=policy.rules[0].on_fail):
                result = Firewall(policy).inspect(payload)
                self.assertFalse(result.blocked)
                self.assertEqual(result.transformed_payload, payload)

    def test_explicit_enforcing_overrides_withhold_without_transforming(self):
        payload = _tool_argument_payload(json.dumps({RAW_SECRET: "safe"}))
        for on_fail in ("mask", "block", "reask"):
            with self.subTest(on_fail=on_fail):
                result = Firewall(_policy(mode="monitor", on_fail=on_fail)).inspect(payload)
                self.assertTrue(result.blocked)
                self.assertIsNone(result.transformed_payload)

    def test_streamed_arguments_are_reassembled_before_key_enforcement(self):
        firewall = Firewall(load_policy("policies/default.yaml"))
        state = StreamingToolCallArgumentState(
            firewall,
            choice_index=0,
            tool_call_index=0,
        )
        pieces = [f'{{"{RAW_SECRET}":"sa', 'fe"}']
        self.assertEqual([state.append(piece).released for piece in pieces], ["", ""])
        result = state.check_pending()

        self.assertTrue(result.blocked)
        self.assertEqual(result.released, "")
        self.assertNotIn(RAW_SECRET, json.dumps(result.audit_event))


if __name__ == "__main__":
    unittest.main()
