# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import base64
import json
import unittest
from unittest.mock import patch

from lsdf import Firewall, load_policy
from lsdf.engine import InspectionResult
from lsdf.eval_matrix import ENTITY_SAMPLES, build_coding_matrix
from lsdf.reporting import format_eval_report_markdown
from lsdf.surfaces import extract_surfaces


class CodingMatrixTests(unittest.TestCase):
    def setUp(self):
        self.firewall = Firewall(load_policy("policies/default.yaml"))

    def test_battery_has_compact_curated_shape_and_explicit_gaps(self):
        dataset = build_coding_matrix()
        cases = dataset["cases"]

        self.assertEqual(len(cases), 25)
        self.assertEqual(len({case["id"] for case in cases}), len(cases))
        categories = {case["category"] for case in cases}
        self.assertIn("coding-threat-assignment", categories)
        self.assertIn("coding-threat-diff", categories)
        self.assertIn("coding-threat-hard-id", categories)
        self.assertIn("coding-threat-escaped-json", categories)
        self.assertIn("coding-encoding-containment", categories)
        self.assertIn("coding-benign-name", categories)
        self.assertIn("coding-characterization-gap-base64", categories)
        self.assertIn("coding-characterization-gap-url", categories)
        gaps = [case for case in cases if case.get("characterization_gap")]
        self.assertEqual(
            {case["characterization_gap"] for case in gaps},
            {"base64_decoding_not_supported", "url_target_not_decoded"},
        )
        self.assertTrue(all(case.get("known_gap") for case in gaps))
        base64_gap = next(
            case for case in gaps if case["characterization_gap"] == "base64_decoding_not_supported"
        )
        encoded_with_spaces = base64_gap["sensitive_values"][0]
        self.assertEqual(
            base64.b64decode("".join(encoded_with_spaces.split())).decode(),
            ENTITY_SAMPLES["API_KEY"][0],
        )
        self.assertEqual(
            base64_gap["payload"]["messages"][0]["content"].split(": ", 1)[0],
            "Base64 text",
        )
        person_case = next(case for case in cases if case["id"].startswith("coding-observe-person"))
        self.assertEqual(person_case["category"], "coding-benign-name")

    def test_default_profile_passes_coding_battery_and_reports_separate_metrics(self):
        report = self.firewall.evaluate(build_coding_matrix()["cases"])

        self.assertEqual(report["failed"], 0)
        self.assertEqual(report["evaluation_errors"], 0)
        self.assertGreaterEqual(report["blocked"], 10)
        self.assertEqual(report["misses"], 0)
        self.assertEqual(report["unwanted_mutations"], 0)
        self.assertGreaterEqual(report["json_text_mutations"], 1)
        self.assertEqual(report["known_gap_cases"], 2)
        self.assertEqual(report["known_gap_misses"], 2)
        self.assertEqual(report["known_gap_leaked_after"], 2)
        self.assertEqual(report["known_gap_would_fail"], 2)
        self.assertEqual(report["audit_raw_value_violations"], 0)
        base64_containment = next(
            result
            for result in report["results"]
            if result["id"].startswith("coding-base64-containment")
        )
        self.assertFalse(base64_containment.get("known_gap", False))
        self.assertTrue(base64_containment["blocked"])
        self.assertIn("OTHER_SECRET", base64_containment["finding_entities"])
        self.assertTrue(
            all(
                result["known_gap_miss"]
                for result in report["results"]
                if result.get("known_gap")
            )
        )
        serialized = json.dumps(report)
        for case in build_coding_matrix()["cases"]:
            for value in case.get("sensitive_values", []):
                self.assertNotIn(value, serialized)

    def test_transformed_tool_json_preserves_unrelated_keys(self):
        cases = [
            case
            for case in build_coding_matrix()["cases"]
            if case["category"] == "coding-transformed-tool-json"
        ]
        report = self.firewall.evaluate(cases)

        self.assertEqual(report["failed"], 0)
        self.assertEqual(report["unwanted_mutations"], 0)
        self.assertGreaterEqual(report["json_text_mutations"], 1)
        for result in report["results"]:
            self.assertTrue(result["mutated"])
            self.assertTrue(result["json_text_mutation"])

    def test_evaluation_errors_are_static_and_counted_even_when_revealing(self):
        class ExplodingScanner:
            def scan(self, _surface):
                raise RuntimeError("raw-secret-value-must-not-escape")

        firewall = Firewall(load_policy("policies/default.yaml"), scanner=ExplodingScanner())
        report = firewall.evaluate(
            [
                {
                    "id": "coding-error",
                    "category": "coding-error-isolation",
                    "surface": "input.messages",
                    "known_gap": True,
                    "payload": {"messages": [{"role": "user", "content": "fixture"}]},
                    "sensitive_values": ["raw-secret-value-must-not-escape"],
                }
            ],
            reveal_sensitive_values=True,
        )

        self.assertEqual(report["failed"], 1)
        self.assertEqual(report["passed"], 0)
        self.assertEqual(report["evaluation_errors"], 1)
        self.assertEqual(report["evaluation_error_categories"], {"inspection_runtime": 1})
        result = report["results"][0]
        self.assertFalse(result["passed"])
        self.assertEqual(result["category"], "coding-error-isolation")
        self.assertEqual(result["surface"], "input.messages")
        self.assertTrue(result["known_gap"])
        self.assertEqual(result["error_category"], "inspection_runtime")
        self.assertEqual(result["failures"], ["inspection_error: inspection_runtime"])
        self.assertFalse(result["known_gap_miss"])
        self.assertFalse(result["unwanted_block"])
        self.assertNotIn("raw-secret-value-must-not-escape", json.dumps(report))
        bucket = report["summary"]["by_category"]["coding-error-isolation"]
        self.assertEqual(bucket["failed"], 1)

    def test_mixed_error_and_success_report_renders_markdown(self):
        class FirstCallExplodingScanner:
            def __init__(self):
                self.calls = 0

            def scan(self, _surface):
                self.calls += 1
                if self.calls == 1:
                    raise RuntimeError("diagnostic detail must remain private")
                return []

        firewall = Firewall(
            load_policy("policies/default.yaml"),
            scanner=FirstCallExplodingScanner(),
        )
        report = firewall.evaluate(
            [
                {
                    "id": "coding-error-mixed",
                    "category": "coding-error-isolation",
                    "surface": "input.messages",
                    "payload": {"messages": [{"role": "user", "content": "first"}]},
                },
                {
                    "id": "coding-success-mixed",
                    "category": "coding-benign-name",
                    "surface": "input.messages",
                    "payload": {"messages": [{"role": "user", "content": "second"}]},
                    "expected_blocked": False,
                    "expected_unchanged": True,
                },
            ]
        )

        markdown = format_eval_report_markdown(report)
        self.assertEqual(report["failed"], 1)
        self.assertEqual(report["passed"], 1)
        self.assertEqual(report["audit_raw_value_violations"], 0)
        self.assertIn("inspection_error: inspection_runtime", markdown)
        self.assertIn("coding-benign-name", markdown)

    def test_model_routing_metadata_is_narrow_and_credential_safe(self):
        harmless = {"model": "qwen2.5-coder:0.5b", "messages": [{"role": "user", "content": "hello"}]}
        surfaces = extract_surfaces(harmless)
        model_surface = next(surface for surface in surfaces if surface.pointer == ("model",))
        self.assertTrue(model_surface.routing_metadata)
        self.assertFalse(self.firewall.inspect(harmless).findings)

        credential = {"model": "api_fixture0000000001", "messages": [{"role": "user", "content": "hello"}]}
        result = self.firewall.inspect(credential)
        self.assertTrue(result.blocked)
        self.assertIn("API_KEY", {finding.entity for finding in result.findings})
        self.assertEqual({finding.surface for finding in result.findings}, {"input.messages"})

        segmented_secret = {
            "model": "mVxQpLrTaN:2026b",
            "messages": [{"role": "user", "content": "hello"}],
        }
        segmented_result = self.firewall.inspect(segmented_secret)
        self.assertTrue(segmented_result.blocked)
        self.assertIn("OTHER_SECRET", {finding.entity for finding in segmented_result.findings})

    def test_model_identifier_in_user_or_nested_tool_text_stays_scanned(self):
        text = "qwen2.5-coder:0.5b"
        user_result = self.firewall.inspect({"messages": [{"role": "user", "content": text}]})
        self.assertTrue(user_result.blocked)
        self.assertIn("OTHER_SECRET", {finding.entity for finding in user_result.findings})

        tool_result = self.firewall.inspect(
            {
                "choices": [
                    {
                        "message": {
                            "tool_calls": [
                                {
                                    "function": {
                                        "name": "route",
                                        "arguments": json.dumps({"model": text}),
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        )
        self.assertTrue(tool_result.blocked)
        self.assertIn("OTHER_SECRET", {finding.entity for finding in tool_result.findings})

    def test_model_id_prose_context_is_narrow_and_credential_safe(self):
        contexts = (
            "The exact model ID is {value}.",
            "You are powered by the model named {value}.",
        )
        for context in contexts:
            with self.subTest(context=context):
                safe = self.firewall.inspect(
                    {"messages": [{"role": "system", "content": context.format(value="qwen2.5-coder:0.5b")}]}
                )
                self.assertFalse(safe.blocked)
                self.assertFalse(safe.findings)
                for value, entity in (
                    ("api_fixture0000000001", "API_KEY"),
                    ("mVxQpLrTaUiOpAsDfGhJkL:2026b", "OTHER_SECRET"),
                ):
                    result = self.firewall.inspect(
                        {"messages": [{"role": "system", "content": context.format(value=value)}]}
                    )
                    self.assertTrue(result.blocked)
                    self.assertIn(entity, {finding.entity for finding in result.findings})

        # Reproduce the complete pinned client's public model declaration.
        declared = (
            "You are powered by the model named qwen2.5-coder:0.5b. "
            "The exact model ID is lsdf/qwen2.5-coder:0.5b"
        )
        result = self.firewall.inspect({"messages": [{"role": "system", "content": declared}]})
        self.assertFalse(result.findings)

    def test_code_reference_lexemes_are_narrowly_exempt_but_secrets_remain_scanned(self):
        public_code = (
            "Use `file_path:line_number`, `src/components/**/*.tsx`, "
            "and `getCurrentWorkingDirectory` when rendering the example; "
            "call(getCurrentWorkingDirectory) for the current path. "
            "Rename getCwd -> getCurrentWorkingDirectory across the repo."
        )
        benign_result = self.firewall.inspect(
            {"messages": [{"role": "system", "content": public_code}]}
        )
        self.assertFalse(benign_result.findings)

        secret = "api_fixture0000000001"
        system_result = self.firewall.inspect(
            {
                "messages": [
                    {
                        "role": "system",
                        "content": f"{public_code} use {secret} as the credential",
                    }
                ]
            }
        )
        self.assertTrue(system_result.blocked)
        self.assertIn("API_KEY", {finding.entity for finding in system_result.findings})

        tool_result = self.firewall.inspect(
            {
                "messages": [
                    {
                        "role": "tool",
                        "content": f"`getCurrentWorkingDirectory` returned {secret}",
                    }
                ]
            }
        )
        self.assertTrue(tool_result.blocked)
        self.assertIn("API_KEY", {finding.entity for finding in tool_result.findings})

        heuristic_secret = "zQmNwErTyUiOpAsDfGhJkL"
        adversarial_result = self.firewall.inspect(
            {
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            f"`{heuristic_secret}` `username:password123!` "
                            "`R3d1s_Pr0d_2024!Secure/**/*.tsx`"
                        ),
                    }
                ]
            }
        )
        self.assertTrue(adversarial_result.blocked)
        self.assertIn("OTHER_SECRET", {finding.entity for finding in adversarial_result.findings})

        for text in (
            heuristic_secret,
            f"`{heuristic_secret}`",
            f"call({heuristic_secret})",
            "`username:password123!`",
            "`R3d1s_Pr0d_2024!Secure/**/*.tsx`",
        ):
            with self.subTest(text=text):
                result = self.firewall.inspect(
                    {"messages": [{"role": "system", "content": text}]}
                )
                self.assertIn("OTHER_SECRET", {finding.entity for finding in result.findings})

    def test_json_validation_errors_are_static_for_both_pointer_forms(self):
        class FixedResultFirewall(Firewall):
            def inspect(self, _payload):
                return InspectionResult(
                    blocked=False,
                    transformed_payload={"argument": "fixture"},
                    findings=[],
                    decisions=[],
                    audit_event={},
                )

        case = {
            "id": "coding-json-validation-errors",
            "category": "coding-structured-validation",
            "surface": "output.tool_calls.arguments",
            "payload": {"argument": "fixture"},
            "expected_valid_json_pointers": [["argument"]],
            "expected_json_semantics": [
                {"pointer": ["argument"], "values": {"safe": "value"}}
            ],
        }
        for decoder_error in (
            ValueError("decoder detail"),
            RecursionError("decoder detail"),
            UnicodeDecodeError("utf-8", b"\xff", 0, 1, "decoder detail"),
        ):
            with self.subTest(error=type(decoder_error).__name__):
                firewall = FixedResultFirewall(load_policy("policies/default.yaml"))
                with patch("lsdf.engine.json.loads", side_effect=decoder_error):
                    report = firewall.evaluate([case])
                result = report["results"][0]
                self.assertEqual(report["failed"], 1)
                self.assertEqual(
                    result["failures"],
                    [
                        "Pointer ['argument'] is not valid JSON",
                        "Pointer ['argument'] is not valid JSON",
                    ],
                )
                self.assertNotIn("decoder detail", json.dumps(report))

    def test_known_gap_inspection_error_is_counted_in_markdown_would_failures(self):
        class ExplodingScanner:
            def scan(self, _surface):
                raise RuntimeError("untrusted diagnostic detail")

        firewall = Firewall(load_policy("policies/default.yaml"), scanner=ExplodingScanner())
        report = firewall.evaluate(
            [
                {
                    "id": "coding-known-gap-error",
                    "category": "coding-error-isolation",
                    "surface": "input.messages",
                    "known_gap": True,
                    "payload": {"messages": [{"role": "user", "content": "fixture"}]},
                }
            ]
        )

        result = report["results"][0]
        self.assertEqual(report["failed"], 1)
        self.assertEqual(report["known_gap_would_fail"], 1)
        self.assertEqual(result["would_failures"], ["inspection_error: inspection_runtime"])
        markdown = format_eval_report_markdown(report)
        self.assertIn("- Known-gap would-fail cases: 1", markdown)
        self.assertIn("coding-known-gap-error", markdown)
        self.assertIn("inspection_error: inspection_runtime", markdown)
        self.assertNotIn("No known-gap misses.", markdown)


if __name__ == "__main__":
    unittest.main()
