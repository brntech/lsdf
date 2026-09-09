import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from lsdf import Firewall, load_policy
from lsdf.audit import JsonlAuditSink
from lsdf.gateway import _inspect_response_payload, handle_chat_completion, handle_streaming_chat_completion
from lsdf.policy import AuditConfig, DetectorConfig, Policy, Rule
from lsdf.streaming import format_sse_event, iter_sse_events
from lsdf.surfaces import extract_response_metadata_surfaces, extract_surfaces
from lsdf.vault import EncryptedSqliteTokenVault, generate_vault_key


RAW_SECRET = "api_LSDF_FIXTURE_TOKEN_000000"
RESPONSE_ID = "chatcmpl-0123abcdEFGH5678"
TOOL_ID = "chatcmpl-tool-0123456789abcdef"


def _json_response(payload):
    return 200, {"content-type": "application/json"}, json.dumps(payload).encode("utf-8")


def _sse(payload, **kwargs):
    return format_sse_event(payload, **kwargs)


def _events(body):
    return [event.data if event.data == "[DONE]" else json.loads(event.data) for event in iter_sse_events(body)]


def _policy(rule: Rule, *, mode: str = "redact") -> Policy:
    return Policy(
        version="0.2",
        name="response-metadata-test",
        mode=mode,
        entities={"API_KEY", "OTHER_SECRET"},
        surfaces={"output.content"},
        rules=[rule],
        audit=AuditConfig(),
        detectors=DetectorConfig(),
    )


class ResponseSurfaceTests(unittest.TestCase):
    def setUp(self):
        self.firewall = Firewall(load_policy("policies/default.yaml"))

    def test_response_id_marker_requires_real_root_envelope(self):
        valid = extract_surfaces(
            {"object": "chat.completion", "choices": [], "id": RESPONSE_ID},
            unknown_surface="output.content",
        )
        marked = [surface for surface in valid if surface.pointer == ("id",)]
        self.assertEqual(len(marked), 1)
        self.assertTrue(marked[0].response_id_metadata)
        self.assertFalse(
            self.firewall.inspect(
                {"object": "chat.completion", "choices": [], "id": RESPONSE_ID},
                unknown_surface="output.content",
            ).findings
        )

        invalid_payloads = (
            {"object": "not-a-response", "choices": [], "id": RESPONSE_ID},
            {"choices": [], "id": RESPONSE_ID},
            {"object": "chat.completion", "choices": [], "id": RESPONSE_ID, "messages": []},
            {"messages": [{"role": "user", "content": RESPONSE_ID}]},
            {"choices": [{"message": {"content": {"id": RESPONSE_ID}}}]},
        )
        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                surfaces = extract_surfaces(payload, unknown_surface="output.content")
                self.assertFalse(
                    [surface for surface in surfaces if surface.value == RESPONSE_ID and surface.response_id_metadata]
                )

    def test_same_response_id_in_user_text_is_not_marked(self):
        surfaces = extract_surfaces(
            {"messages": [{"role": "user", "content": RESPONSE_ID}]}
        )
        self.assertTrue(any(surface.value == RESPONSE_ID for surface in surfaces))
        self.assertFalse(any(surface.response_id_metadata for surface in surfaces))

    def test_metadata_finding_uses_static_pointer_and_audit_is_raw_safe(self):
        hostile_key = RAW_SECRET
        payload = {
            "object": "chat.completion",
            "id": RESPONSE_ID,
            "choices": [{"message": {"content": "safe"}}],
            "metadata": {hostile_key: RAW_SECRET},
        }
        result = _inspect_response_payload(payload, self.firewall)
        self.assertTrue(result.blocked)
        self.assertIsNone(result.transformed_payload)
        self.assertNotIn(RAW_SECRET, json.dumps(result.to_dict()))
        self.assertTrue(
            all(finding.pointer[0] == "response_metadata" for finding in result.findings)
        )
        self.assertTrue(all(finding.json_pointer is None for finding in result.findings))


    def test_cache_write_usage_label_is_structural_but_its_value_is_inspected(self):
        payload = {
            "object": "chat.completion",
            "id": RESPONSE_ID,
            "choices": [{"message": {"content": "safe"}}],
            "usage": {"prompt_tokens_details": {"cache_write_tokens": 0}},
        }
        result = _inspect_response_payload(payload, self.firewall)
        self.assertFalse(result.blocked)
        self.assertEqual(result.transformed_payload, payload)
        payload["usage"]["prompt_tokens_details"]["cache_write_tokens"] = RAW_SECRET
        result = _inspect_response_payload(payload, self.firewall)
        self.assertTrue(result.blocked)
        self.assertNotIn(RAW_SECRET, json.dumps(result.to_dict()))


    def test_prompt_token_ids_json_label_preserves_null_and_numeric_values(self):
        for value in (None, [11, 22, 33], [100_000 + index for index in range(1024)]):
            with self.subTest(value=value):
                payload = {
                    "object": "chat.completion",
                    "id": RESPONSE_ID,
                    "choices": [{"message": {"content": "safe"}}],
                    "prompt_token_ids": value,
                }
                status, _headers, body, response_headers = handle_chat_completion(
                    {"messages": [{"role": "user", "content": "hello"}]},
                    self.firewall,
                    lambda _payload: _json_response(payload),
                )
                self.assertEqual(status, 200)
                self.assertEqual(response_headers["x-lsdf-blocked"], "false")
                self.assertEqual(json.loads(body), payload)

    def test_prompt_token_ids_label_exception_requires_response_root(self):
        root = {"object": "chat.completion", "choices": [], "prompt_token_ids": [11, 22, 33]}
        values = {surface.value for surface in extract_response_metadata_surfaces(root)}
        self.assertTrue({"11", "22", "33"}.issubset(values))
        self.assertNotIn("prompt_token_ids", values)
        payloads = (
            {"object": "chat.completion", "choices": [], "metadata": {"prompt_token_ids": None}},
            {"object": "chat.completion", "choices": [], "messages": [], "prompt_token_ids": None},
            {"object": "not-a-response", "choices": [], "prompt_token_ids": None},
            {"object": "chat.completion", "prompt_token_ids": None},
        )
        for index, payload in enumerate(payloads):
            with self.subTest(case=index):
                surfaces = extract_response_metadata_surfaces(payload)
                self.assertIn("prompt_token_ids", [surface.value for surface in surfaces])

    def test_prompt_token_ids_json_values_and_unknown_keys_remain_inspected(self):
        extensions = [
            {"prompt_token_ids": value}
            for value in (
                RAW_SECRET,
                [RAW_SECRET],
                {"value": RAW_SECRET},
                [{"value": RAW_SECRET}],
                {RAW_SECRET: "safe"},
            )
        ] + [{"prompt_token_ids": None, RAW_SECRET: "safe"}]
        for index, extension in enumerate(extensions):
            with self.subTest(case=index):
                payload = {
                    "object": "chat.completion",
                    "id": RESPONSE_ID,
                    "choices": [{"message": {"content": "held"}}],
                    **extension,
                }
                result = _inspect_response_payload(payload, self.firewall)
                self.assertTrue(result.blocked)
                self.assertIsNone(result.transformed_payload)
                self.assertNotIn(RAW_SECRET, json.dumps(result.to_dict()))
                status, _headers, body, response_headers = handle_chat_completion(
                    {"messages": [{"role": "user", "content": "hello"}]},
                    self.firewall,
                    lambda _payload: _json_response(payload),
                )
                self.assertEqual(status, 502)
                self.assertEqual(response_headers["x-lsdf-blocked"], "true")
                self.assertEqual(json.loads(body)["error"]["type"], "sensitive_data_blocked")
                self.assertNotIn(RAW_SECRET, body.decode("utf-8"))
                self.assertNotIn("held", body.decode("utf-8"))

    def test_gateway_blocks_metadata_without_rewriting_identity(self):
        payload = {
            "object": "chat.completion",
            "id": RESPONSE_ID,
            "choices": [{"message": {"content": "safe"}}],
            "metadata": {"credential": RAW_SECRET},
        }
        status, _headers, body, response_headers = handle_chat_completion(
            {"messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: _json_response(payload),
        )
        self.assertEqual(status, 502)
        self.assertEqual(response_headers["x-lsdf-blocked"], "true")
        self.assertEqual(json.loads(body)["error"]["type"], "sensitive_data_blocked")
        self.assertNotIn(RAW_SECRET, body.decode("utf-8"))

    def test_gateway_preserves_valid_id_and_transforms_content(self):
        payload = {
            "object": "chat.completion",
            "id": RESPONSE_ID,
            "choices": [{"message": {"content": "MRN: LSDF-FIXTURE-00001"}}],
        }
        status, _headers, body, response_headers = handle_chat_completion(
            {"messages": [{"role": "user", "content": "hello"}]},
            self.firewall,
            lambda _payload: _json_response(payload),
        )
        response = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(response_headers["x-lsdf-blocked"], "false")
        self.assertEqual(response["id"], RESPONSE_ID)
        self.assertIn("<MRN:REDACTED>", response["choices"][0]["message"]["content"])

    def test_metadata_rejection_does_not_write_vault(self):
        payload = {
            "object": "chat.completion",
            "choices": [{"message": {"content": "safe"}}],
            "metadata": {"card": 4111111111111111},
        }
        with TemporaryDirectory() as tmpdir:
            vault = EncryptedSqliteTokenVault(Path(tmpdir, "vault.sqlite"), generate_vault_key())
            firewall = Firewall(load_policy("policies/default.yaml"), token_vault=vault)
            status, _headers, _body, _response_headers = handle_chat_completion(
                {"messages": [{"role": "user", "content": "hello"}]},
                firewall,
                lambda _payload: _json_response(payload),
            )
            self.assertEqual(status, 502)
            self.assertEqual(vault.status()["token_count"], 0)

    def test_monitor_and_observe_metadata_findings_remain_unmodified(self):
        rule = Rule(
            id="observe-key",
            match={"entity": "API_KEY", "surface": "output.content"},
            action="redact",
            on_fail="observe",
        )
        for mode in ("redact", "monitor"):
            with self.subTest(mode=mode):
                firewall = Firewall(_policy(rule, mode=mode))
                payload = {
                    "object": "chat.completion",
                    "choices": [{"message": {"content": "safe"}}],
                    "metadata": {"credential": RAW_SECRET},
                }
                status, _headers, body, _response_headers = handle_chat_completion(
                    {"messages": [{"role": "user", "content": "hello"}]},
                    firewall,
                    lambda _payload: _json_response(payload),
                )
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(body)["metadata"]["credential"], RAW_SECRET)

    def test_valid_tool_id_is_narrow_and_extension_sibling_is_scanned(self):
        tool = {
            "id": TOOL_ID,
            "type": "function",
            "function": {"name": "lookup", "arguments": "{}"},
        }
        response = {
            "object": "chat.completion",
            "choices": [{"message": {"role": "assistant", "tool_calls": [tool]}}],
        }
        self.assertFalse(self.firewall.inspect(response, unknown_surface="output.content").findings)
        sibling = {
            "object": "chat.completion",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "other": [{"id": TOOL_ID}],
                        "tool_calls": [tool],
                    }
                }
            ],
        }
        metadata = extract_response_metadata_surfaces(sibling, unknown_surface="output.content")
        self.assertTrue(any(surface.value == TOOL_ID for surface in metadata))
        self.assertTrue(self.firewall.inspect(sibling, unknown_surface="output.content").findings)

    def test_malformed_content_and_arguments_stay_in_metadata_projection(self):
        for field, value in (
            ("content", {RAW_SECRET: "safe"}),
            ("arguments", {RAW_SECRET: "safe"}),
        ):
            with self.subTest(field=field):
                if field == "content":
                    choice = {"message": {"content": value}}
                else:
                    choice = {
                        "message": {
                            "tool_calls": [
                                {
                                    "type": "function",
                                    "function": {"name": "lookup", "arguments": value},
                                }
                            ]
                        }
                    }
                payload = {
                    "object": "chat.completion",
                    "id": RESPONSE_ID,
                    "choices": [choice],
                }
                result = _inspect_response_payload(payload, self.firewall)
                self.assertTrue(result.blocked)
                self.assertIsNone(result.transformed_payload)
                self.assertNotIn(RAW_SECRET, json.dumps(result.to_dict()))
                self.assertTrue(all(finding.json_pointer is None for finding in result.findings))


class ResponseStreamingMetadataTests(unittest.TestCase):
    def setUp(self):
        self.firewall = Firewall(load_policy("policies/default.yaml"))
        self.request = {"stream": True, "messages": [{"role": "user", "content": "hello"}]}

    def _stream(self, chunks, *, holdback=64):
        return handle_streaming_chat_completion(
            self.request,
            self.firewall,
            lambda _payload: (200, {"content-type": "text/event-stream"}, chunks),
            holdback_chars=holdback,
        )

    def test_prompt_token_ids_sse_label_preserves_null_and_numeric_values(self):
        for value in (None, [11, 22, 33], [100_000 + index for index in range(1024)]):
            with self.subTest(value=value):
                payload = {
                    "object": "chat.completion.chunk",
                    "id": RESPONSE_ID,
                    "choices": [{"index": 0, "delta": {"content": "safe"}}],
                    "prompt_token_ids": value,
                }
                status, _headers, body, _response_headers = self._stream(
                    [_sse(payload), b"data: [DONE]\n\n"], holdback=0,
                )
                events = _events(body)
                self.assertEqual(status, 200)
                self.assertEqual(events[-1], "[DONE]")
                self.assertFalse(any(isinstance(event, dict) and "error" in event for event in events))
                values = [event["prompt_token_ids"] for event in events
                          if isinstance(event, dict) and "prompt_token_ids" in event]
                self.assertEqual(values, [value])
                content = "".join(choice.get("delta", {}).get("content", "")
                                  for event in events if isinstance(event, dict)
                                  for choice in event.get("choices", []))
                self.assertEqual(content, "safe")

    def test_prompt_token_ids_sse_values_and_unknown_keys_remain_inspected(self):
        extensions = [
            {"prompt_token_ids": value}
            for value in (
                RAW_SECRET,
                [RAW_SECRET],
                {"value": RAW_SECRET},
                [{"value": RAW_SECRET}],
                {RAW_SECRET: "safe"},
            )
        ] + [{"prompt_token_ids": None, RAW_SECRET: "safe"}]
        for index, extension in enumerate(extensions):
            with self.subTest(case=index):
                payload = {
                    "object": "chat.completion.chunk",
                    "id": RESPONSE_ID,
                    "choices": [{"index": 0, "delta": {"content": "held"}}],
                    **extension,
                }
                status, _headers, body, _response_headers = self._stream(
                    [_sse(payload), b"data: [DONE]\n\n"], holdback=0,
                )
                events = _events(body)
                self.assertEqual(status, 200)
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0]["error"]["type"], "sensitive_data_blocked")
                self.assertNotIn(RAW_SECRET, json.dumps(events))
                self.assertNotIn("held", json.dumps(events))

    def test_metadata_block_precedes_emission_and_drops_held_content(self):
        chunks = [
            _sse({"choices": [{"index": 0, "delta": {"content": "held"}}]}),
            _sse({"choices": [{"index": 0, "delta": {"metadata": {"credential": RAW_SECRET}}}]}),
            b"data: [DONE]\n\n",
        ]
        status, _headers, body, response_headers = self._stream(chunks)
        events = _events(body)
        self.assertEqual(status, 200)
        self.assertEqual(response_headers["x-lsdf-blocked"], "false")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["error"]["type"], "sensitive_data_blocked")
        self.assertNotIn(RAW_SECRET, json.dumps(events))
        self.assertNotIn("held", json.dumps(events))

    def test_all_sse_envelope_fields_are_preflighted(self):
        for envelope in (
            {"id": RAW_SECRET},
            {"event": RAW_SECRET},
            {"retry": RAW_SECRET},
            {"comments": (RAW_SECRET,)},
        ):
            for payload in (
                {"choices": [{"index": 0, "delta": {"content": "held"}}]},
                "",
                "{malformed",
            ):
                with self.subTest(envelope_field=next(iter(envelope)), payload_type=type(payload).__name__):
                    chunks = [_sse(payload, **envelope), b"data: [DONE]\n\n"]
                    _status, _headers, body, _response_headers = self._stream(chunks)
                    events = _events(body)
                    self.assertEqual(events[0]["error"]["type"], "sensitive_data_blocked")
                    self.assertNotIn(RAW_SECRET, json.dumps(events))
                    self.assertNotIn("held", json.dumps(events))

    def test_done_envelope_is_checked_before_flushing(self):
        chunks = [
            _sse({"choices": [{"index": 0, "delta": {"content": "held"}}]}),
            _sse("[DONE]", id=RAW_SECRET),
        ]
        _status, _headers, body, _response_headers = self._stream(chunks)
        events = _events(body)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["error"]["type"], "sensitive_data_blocked")
        self.assertNotIn("held", json.dumps(events))

    def test_unknown_no_choice_payload_is_inspected(self):
        chunks = [_sse({"metadata": {"credential": RAW_SECRET}}), b"data: [DONE]\n\n"]
        _status, _headers, body, _response_headers = self._stream(chunks)
        events = _events(body)
        self.assertEqual(events[0]["error"]["type"], "sensitive_data_blocked")

    def test_unknown_nested_content_and_argument_extensions_are_inspected(self):
        chunks = [
            _sse(
                {
                    "choices": [
                        {
                            "index": 0,
                            "delta": {
                                "extensions": {"content": RAW_SECRET},
                                "tool_calls": [
                                    {
                                        "index": 0,
                                        "extensions": {"arguments": RAW_SECRET},
                                    }
                                ],
                            },
                        }
                    ]
                }
            )
        ]
        _status, _headers, body, _response_headers = self._stream(chunks)
        events = _events(body)
        self.assertEqual(events[0]["error"]["type"], "sensitive_data_blocked")

    def test_nonstring_delta_content_is_not_excluded(self):
        chunks = [
            _sse({"choices": [{"delta": {"content": {RAW_SECRET: "safe"}}}]}),
            b"data: [DONE]\n\n",
        ]
        _status, _headers, body, _response_headers = self._stream(chunks)
        self.assertEqual(_events(body)[0]["error"]["type"], "sensitive_data_blocked")

    def test_response_id_is_stable_while_sse_envelope_id_can_vary(self):
        chunks = [
            _sse(
                {"object": "chat.completion.chunk", "id": RESPONSE_ID, "choices": [{"index": 0, "delta": {"content": "a"}}]},
                id="event-1",
            ),
            _sse(
                {"object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"content": "b"}}]},
                id="event-2",
            ),
            b"data: [DONE]\n\n",
        ]
        _status, _headers, body, _response_headers = self._stream(chunks, holdback=0)
        events = _events(body)
        self.assertEqual(events[-1], "[DONE]")
        self.assertEqual("".join(event["choices"][0]["delta"].get("content", "") for event in events if isinstance(event, dict)), "ab")

    def test_streaming_request_json_fallback_preflights_metadata(self):
        payload = {
            "object": "chat.completion",
            "id": RESPONSE_ID,
            "choices": [{"message": {"content": "safe"}}],
            "metadata": {"credential": RAW_SECRET},
        }
        status, _headers, body, response_headers = handle_streaming_chat_completion(
            self.request,
            self.firewall,
            lambda _payload: (
                200,
                {"content-type": "application/json"},
                [json.dumps(payload).encode("utf-8")],
            ),
        )
        response = json.loads(b"".join(body))
        self.assertEqual(status, 502)
        self.assertEqual(response_headers["x-lsdf-blocked"], "true")
        self.assertEqual(response["error"]["type"], "sensitive_data_blocked")
        self.assertNotIn(RAW_SECRET, json.dumps(response))

    def test_conflicting_or_nonstring_response_ids_are_rejected_before_frame(self):
        conflict = [
            _sse({"object": "chat.completion.chunk", "id": RESPONSE_ID, "choices": [{"delta": {"content": "a"}}]}),
            _sse({"object": "chat.completion.chunk", "id": "chatcmpl-SECOND1234", "choices": [{"delta": {"content": "b"}}]}),
        ]
        _status, _headers, body, _response_headers = self._stream(conflict, holdback=0)
        events = _events(body)
        self.assertEqual(events[-1]["error"]["type"], "upstream_stream_error")
        self.assertEqual(events[-1]["lsdf"]["stream_state"], "response_id_mismatch")
        self.assertFalse(any(event.get("choices", [{}])[0].get("delta", {}).get("content") == "b" for event in events if isinstance(event, dict)))

        nonstring = [_sse({"object": "chat.completion.chunk", "id": 7, "choices": []})]
        _status, _headers, body, _response_headers = self._stream(nonstring)
        self.assertEqual(_events(body)[0]["lsdf"]["stream_state"], "invalid_response_id")

    def test_tool_identity_fragments_are_rejected_but_argument_continuations_are_buffered(self):
        fragmented = [
            _sse({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": "api_"}]}}]}),
            _sse({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": "fixture0000000001"}]}}]}),
        ]
        _status, _headers, body, _response_headers = self._stream(fragmented, holdback=0)
        self.assertEqual(_events(body)[-1]["lsdf"]["stream_state"], "fragmented_tool_identity")

        args = [
            _sse({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": "{\"q\":\"hel"}}]}}]}),
            _sse({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": "lo\"}"}}]}}]}),
            b"data: [DONE]\n\n",
        ]
        _status, _headers, body, _response_headers = self._stream(args)
        events = _events(body)
        self.assertEqual(events[-1], "[DONE]")
        argument_events = [
            event["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"]
            for event in events
            if isinstance(event, dict)
            and event.get("choices")
            and event["choices"][0].get("delta", {}).get("tool_calls")
        ]
        self.assertIn('{"q":"hello"}', argument_events)

    def test_duplicate_tool_identity_occurrences_are_rejected(self):
        duplicate = [
            _sse(
                {
                    "choices": [
                        {
                            "index": 0,
                            "delta": {
                                "tool_calls": [
                                    {
                                        "index": 0,
                                        "type": "function",
                                        "id": TOOL_ID,
                                        "function": {"name": "lookup", "arguments": "{}"},
                                    },
                                    {
                                        "index": 0,
                                        "type": "function",
                                        "id": TOOL_ID,
                                        "function": {"name": "lookup", "arguments": "{}"},
                                    },
                                ]
                            },
                        }
                    ]
                }
            )
        ]
        _status, _headers, body, _response_headers = self._stream(duplicate, holdback=0)
        events = _events(body)
        self.assertEqual(events[-1]["lsdf"]["stream_state"], "fragmented_tool_identity")

    def test_contradictory_stream_shape_cannot_inherit_tool_id_exemption(self):
        validated = {(0, 0)}
        for contradictory in (
            {
                "object": "chat.completion",
                "choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": TOOL_ID}]}}],
            },
            {
                "object": "chat.completion.chunk",
                "messages": [],
                "choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": TOOL_ID}]}}],
            },
            {
                "object": "chat.completion.chunk",
                "choices": [
                    {
                        "index": 0,
                        "delta": {
                            "role": "user",
                            "tool_calls": [{"index": 0, "id": TOOL_ID}],
                        },
                    }
                ],
            },
        ):
            with self.subTest(contradictory=contradictory):
                metadata = extract_response_metadata_surfaces(
                    contradictory,
                    unknown_surface="output.content",
                    validated_tool_context=validated,
                )
                matching = [surface for surface in metadata if surface.value == TOOL_ID]
                self.assertTrue(matching)
                self.assertFalse(any(surface.correlation_metadata for surface in matching))



    def test_envelope_is_scanned_once_and_metadata_appears_in_summary(self):
        from types import SimpleNamespace
        from unittest.mock import Mock, patch

        chunks = [
            _sse({"choices": []}, event="completion.chunk"),
            b"data: [DONE]\n\n",
        ]
        scan = Mock(side_effect=self.firewall.scanner.scan)
        with patch.object(self.firewall, "scanner", SimpleNamespace(scan=scan)):
            _status, _headers, body, _response_headers = self._stream(chunks)
            self.assertEqual(_events(body)[-1], "[DONE]")
            event_scans = [call.args[0] for call in scan.call_args_list if call.args[0].value == "completion.chunk"]
            self.assertEqual(len(event_scans), 1)

        unsafe = [_sse({"metadata": {RAW_SECRET: "safe"}})]
        _status, _headers, body, _response_headers = self._stream(unsafe)
        self.assertIn("output.content", _events(body)[0]["lsdf"]["surfaces_inspected"])


    def test_null_tool_identity_continuations_are_treated_as_omitted(self):
        first = {
            "object": "chat.completion.chunk",
            "choices": [{"index": 0, "delta": {"tool_calls": [{
                "index": 0, "id": TOOL_ID, "type": "function",
                "function": {"name": "lookup", "arguments": '{"q":'},
            }]}}],
        }
        continuation = {
            "choices": [{"index": 0, "delta": {"tool_calls": [{
                "index": 0, "id": None,
                "function": {"name": None, "arguments": '"hello"}'},
            }]}}],
        }
        _status, _headers, body, _response_headers = self._stream(
            [_sse(first), _sse(continuation), b"data: [DONE]\n\n"]
        )
        events = _events(body)
        self.assertEqual(events[-1], "[DONE]")
        self.assertFalse(any(isinstance(event, dict) and "error" in event for event in events))
        arguments = "".join(
            call.get("function", {}).get("arguments", "")
            for event in events if isinstance(event, dict)
            for choice in event.get("choices", [])
            for call in choice.get("delta", {}).get("tool_calls", [])
        )
        self.assertEqual(json.loads(arguments), {"q": "hello"})

        invalid = {"choices": [{"delta": {"tool_calls": [{"id": 7}]}}]}
        _status, _headers, body, _response_headers = self._stream([_sse(invalid)])
        self.assertEqual(_events(body)[-1]["lsdf"]["stream_state"], "invalid_tool_identity")


if __name__ == "__main__":
    unittest.main()


class VllmFingerprintTests(unittest.TestCase):
    fingerprint = "vllm-0.12.0rc1.dev42+gabcdef123456-0123abcd"

    def setUp(self):
        self.firewall = Firewall(load_policy("policies/default.yaml"))

    @staticmethod
    def _payload(value, *, stream=False):
        return {
            "object": "chat.completion.chunk" if stream else "chat.completion",
            "id": RESPONSE_ID,
            "choices": [{"index": 0, "delta" if stream else "message": {"content": "held"}}],
            "system_fingerprint": value,
        }

    def _json(self, payload, firewall=None):
        return handle_chat_completion(
            {"messages": [{"role": "user", "content": "hello"}]},
            firewall or self.firewall,
            lambda _payload: _json_response(payload),
        )

    def _stream(self, payload, firewall=None):
        return handle_streaming_chat_completion(
            {"stream": True, "messages": [{"role": "user", "content": "hello"}]},
            firewall or self.firewall,
            lambda _payload: (200, {"content-type": "text/event-stream"},
                             [_sse(payload), b"data: [DONE]\n\n"]),
            holdback_chars=0,
        )

    def test_generated_fingerprints_are_preserved_in_json_and_sse(self):
        from lsdf.scanners.entropy import EntropySecretScanner
        from lsdf.surfaces import Surface

        fingerprints = (
            "vllm-0.12.0-0123abcd",
            self.fingerprint,
            "vllm-0.12.0a1-0123abcd",
            "vllm-0.12.0b2-0123abcd",
            "vllm-0.12.0.post1+cu128-nohash",
            "vllm-0.12.0.dev42+gabcdef123456.d20260909.cu128-tp2-pp4-dp8-ep-0123abcd",
            "vllm-0.12.0-tp2-0123abcd",
            "vllm-0.12.0-pp2-0123abcd",
            "vllm-0.12.0-dp2-0123abcd",
            "vllm-0.12.0-ep-0123abcd",
            "vllm-dev-nohash",
            None,
        )
        for index, value in enumerate(fingerprints):
            with self.subTest(case=index):
                if value in (fingerprints[4], fingerprints[5]):
                    scanner = EntropySecretScanner()
                    ordinary = Surface("output.content", ("response_metadata", 0), value)
                    marked = Surface("output.content", ("response_metadata", 0), value,
                                     provider_version_metadata=True)
                    self.assertTrue(scanner.scan(ordinary))
                    self.assertFalse(scanner.scan(marked))
                payload = self._payload(value)
                status, _headers, body, response_headers = self._json(payload)
                self.assertEqual(status, 200)
                self.assertEqual(response_headers["x-lsdf-blocked"], "false")
                self.assertEqual(json.loads(body), payload)
                status, _headers, body, _response_headers = self._stream(self._payload(value, stream=True))
                events = _events(body)
                self.assertEqual(status, 200)
                self.assertEqual(events[-1], "[DONE]")
                self.assertFalse(any(isinstance(event, dict) and "error" in event for event in events))
                self.assertEqual([event["system_fingerprint"] for event in events
                                  if isinstance(event, dict) and "system_fingerprint" in event], [value])
                content = "".join(choice.get("delta", {}).get("content", "")
                                  for event in events if isinstance(event, dict)
                                  for choice in event.get("choices", []))
                self.assertEqual(content, "held")

    def test_fingerprint_marker_is_limited_to_a_valid_response_root(self):
        from lsdf.scanners.entropy import EntropySecretScanner

        scanner = EntropySecretScanner()
        for extractor in (extract_surfaces, extract_response_metadata_surfaces):
            root = self._payload(self.fingerprint)
            values = [surface for surface in extractor(root) if surface.value == self.fingerprint]
            self.assertEqual(len(values), 1)
            self.assertTrue(values[0].provider_version_metadata)
            self.assertFalse(scanner.scan(values[0]))
            invalid = (
                {"object": "chat.completion", "choices": [], "metadata": {"system_fingerprint": self.fingerprint}},
                {"messages": [], "system_fingerprint": self.fingerprint},
                {"object": "chat.completion", "choices": [], "messages": [], "system_fingerprint": self.fingerprint},
                {"object": "invalid", "choices": [], "system_fingerprint": self.fingerprint},
                {"object": "chat.completion", "system_fingerprint": self.fingerprint},
            )
            for index, payload in enumerate(invalid):
                with self.subTest(extractor=extractor.__name__, case=index):
                    values = [surface for surface in extractor(payload) if surface.value == self.fingerprint]
                    self.assertEqual(len(values), 1)
                    self.assertFalse(values[0].provider_version_metadata)
                    self.assertTrue(scanner.scan(values[0]))

    def test_noncanonical_fingerprints_get_normal_entropy_inspection(self):
        from lsdf.scanners.entropy import EntropySecretScanner
        from lsdf.surfaces import Surface

        values = (
            self.fingerprint + "!",
            " " + self.fingerprint,
            self.fingerprint + " ",
            self.fingerprint.replace("-0123abcd", "-tp1-0123abcd"),
            self.fingerprint.replace("-0123abcd", "-tp0-0123abcd"),
            self.fingerprint.replace("-0123abcd", "-tp02-0123abcd"),
            self.fingerprint.replace("-0123abcd", "-pp2-tp4-0123abcd"),
            self.fingerprint.replace("-0123abcd", "-ep-dp2-0123abcd"),
            self.fingerprint.replace("-0123abcd", "-ABCD1234"),
            self.fingerprint.replace("+gabcdef123456", "+customabcdef123456"),
            self.fingerprint.replace("0.12.0", "０.12.0"),
            "opaque-" + self.fingerprint,
            self.fingerprint + "x" * 193,
        )
        scanner = EntropySecretScanner()
        for index, value in enumerate(values):
            with self.subTest(case=index):
                ordinary = Surface("output.content", ("response_metadata", 0), value)
                marked = Surface("output.content", ("response_metadata", 0), value,
                                 provider_version_metadata=True)
                expected = scanner.scan(ordinary)
                self.assertTrue(expected)
                self.assertEqual(scanner.scan(marked), expected)

    def test_secret_and_nonstring_fingerprints_remain_blocked(self):
        for index, value in enumerate((RAW_SECRET, [RAW_SECRET], {"value": RAW_SECRET}, {RAW_SECRET: "safe"})):
            with self.subTest(case=index):
                payload = self._payload(value)
                result = _inspect_response_payload(payload, self.firewall)
                self.assertTrue(result.blocked)
                self.assertNotIn(RAW_SECRET, json.dumps(result.to_dict()))
                status, _headers, body, response_headers = self._json(payload)
                self.assertEqual(status, 502)
                self.assertEqual(response_headers["x-lsdf-blocked"], "true")
                self.assertEqual(json.loads(body)["error"]["type"], "sensitive_data_blocked")
                self.assertNotIn(RAW_SECRET, body.decode("utf-8"))
                self.assertNotIn("held", body.decode("utf-8"))
                _status, _headers, body, _response_headers = self._stream(self._payload(value, stream=True))
                events = _events(body)
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0]["error"]["type"], "sensitive_data_blocked")
                self.assertNotIn(RAW_SECRET, json.dumps(events))
                self.assertNotIn("held", json.dumps(events))

    def test_another_detector_still_inspects_generated_fingerprints(self):
        import re
        from lsdf.scanners.entropy import EntropySecretScanner
        from lsdf.scanners.regex import PatternRecognizer, RegexScanner

        scanner = RegexScanner([PatternRecognizer("API_KEY", re.compile(re.escape(self.fingerprint)), 1.0)])
        firewall = Firewall(load_policy("policies/default.yaml"), scanner=scanner)
        payload = self._payload(self.fingerprint)
        surface = next(surface for surface in extract_response_metadata_surfaces(payload)
                       if surface.value == self.fingerprint)
        self.assertTrue(surface.provider_version_metadata)
        self.assertFalse(EntropySecretScanner().scan(surface))
        self.assertTrue(scanner.scan(surface))
        result = _inspect_response_payload(payload, firewall)
        self.assertTrue(result.blocked)
        self.assertNotIn(self.fingerprint, json.dumps(result.to_dict()))
        status, _headers, body, _response_headers = self._json(payload, firewall)
        self.assertEqual(status, 502)
        self.assertNotIn(self.fingerprint, body.decode("utf-8"))
        _status, _headers, body, _response_headers = self._stream(self._payload(self.fingerprint, stream=True), firewall)
        events = _events(body)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["error"]["type"], "sensitive_data_blocked")
        self.assertNotIn(self.fingerprint, json.dumps(events))

    def test_fingerprint_exception_does_not_skip_other_metadata(self):
        for stream in (False, True):
            with self.subTest(stream=stream):
                payload = self._payload(self.fingerprint, stream=stream)
                payload["metadata"] = {RAW_SECRET: "safe"}
                if stream:
                    _status, _headers, body, _response_headers = self._stream(payload)
                    events = _events(body)
                    self.assertEqual(events[0]["error"]["type"], "sensitive_data_blocked")
                else:
                    status, _headers, body, _response_headers = self._json(payload)
                    self.assertEqual(status, 502)
                self.assertNotIn(RAW_SECRET, body.decode("utf-8") if isinstance(body, bytes) else json.dumps(events))
                self.assertNotIn("held", body.decode("utf-8") if isinstance(body, bytes) else json.dumps(events))
