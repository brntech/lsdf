import json
import unittest
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory

from lsdf import Firewall, load_policy
from lsdf.eval_matrix import (
    BATTERY_FILENAMES,
    build_eval_batteries,
    build_safety_matrix,
    build_observability_matrix,
    build_utility_matrix,
)
from lsdf.surfaces import Surface
from lsdf.types import Finding


class DetectorProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.firewall = Firewall(load_policy("policies/default.yaml"))

    def test_regex_findings_include_safe_provenance(self):
        result = self.firewall.inspect(
            {"messages": [{"role": "user", "content": "SSN 000-00-0000"}]}
        )

        finding = next(finding for finding in result.findings if finding.entity == "US_SSN")
        safe = finding.safe_dict()
        self.assertEqual(finding.detector_id, "regex.ssn")
        self.assertEqual(finding.detector_family, "regex")
        self.assertEqual(safe["detector_id"], "regex.ssn")
        self.assertEqual(safe["detector_family"], "regex")
        self.assertNotIn("000-00-0000", str(safe))

    def test_entropy_and_medical_findings_include_provenance(self):
        secret_result = self.firewall.inspect(
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
        phi_result = self.firewall.inspect(
            {
                "choices": [
                    {
                        "message": {
                            "content": "Patient takes metformin 500mg."
                        }
                    }
                ]
            }
        )

        self.assertIn("entropy.secret", {finding.detector_id for finding in secret_result.findings})
        self.assertIn("entropy", {finding.detector_family for finding in secret_result.findings})
        self.assertIn("medical-regex.phi_pattern", {finding.detector_id for finding in phi_result.findings})
        self.assertIn("medical-regex", {finding.detector_family for finding in phi_result.findings})

    def test_audit_includes_provenance_without_raw_value(self):
        result = self.firewall.inspect(
            {"messages": [{"role": "user", "content": "SSN 000-00-0000"}]}
        )
        audit_text = str(result.audit_event)

        self.assertIn("regex.ssn", audit_text)
        self.assertIn("regex", audit_text)
        self.assertNotIn("000-00-0000", audit_text)


class EvalHarnessSemanticsTests(unittest.TestCase):
    def setUp(self):
        self.firewall = Firewall(load_policy("policies/default.yaml"))

    def test_sensitive_values_add_before_after_leakage_counts(self):
        report = self.firewall.evaluate(
            [
                {
                    "id": "secret",
                    "category": "credentials",
                    "surface": "output.content",
                    "payload": {
                        "choices": [
                            {
                                "message": {
                                    "content": "Password R3d1s_Pr0d_2024!Secure leaked."
                                }
                            }
                        ]
                    },
                    "sensitive_values": ["R3d1s_Pr0d_2024!Secure"],
                    "expected_absent": ["R3d1s_Pr0d_2024!Secure"],
                    "expected_detector_families": ["entropy"],
                }
            ]
        )

        self.assertEqual(report["failed"], 0)
        self.assertEqual(report["sensitive_values_leaked_before"], 1)
        self.assertEqual(report["sensitive_values_leaked_after"], 0)
        self.assertEqual(report["summary"]["by_category"]["credentials"]["cases"], 1)
        self.assertEqual(report["summary"]["by_detector_family"]["entropy"], 1)
        self.assertNotIn("R3d1s_Pr0d_2024!Secure", json.dumps(report))

    def test_reveal_sensitive_values_restores_raw_synthetic_values(self):
        report = self.firewall.evaluate(
            [
                {
                    "id": "secret",
                    "payload": {
                        "choices": [
                            {
                                "message": {
                                    "content": "Password R3d1s_Pr0d_2024!Secure leaked."
                                }
                            }
                        ]
                    },
                    "sensitive_values": ["R3d1s_Pr0d_2024!Secure"],
                }
            ],
            reveal_sensitive_values=True,
        )

        self.assertIn("R3d1s_Pr0d_2024!Secure", json.dumps(report))

    def test_expected_unchanged_fails_when_payload_is_transformed(self):
        report = self.firewall.evaluate(
            [
                {
                    "id": "unexpected-transform",
                    "payload": {
                        "choices": [
                            {
                                "message": {
                                    "content": "Password R3d1s_Pr0d_2024!Secure leaked."
                                }
                            }
                        ]
                    },
                    "expected_unchanged": True,
                }
            ]
        )

        self.assertEqual(report["failed"], 1)
        self.assertIn("Expected transformed payload", " ".join(report["results"][0]["failures"]))

    def test_expected_detector_ids_and_families_fail_when_missing(self):
        report = self.firewall.evaluate(
            [
                {
                    "id": "bad-detector-expectation",
                    "payload": {
                        "messages": [{"role": "user", "content": "SSN 000-00-0000"}]
                    },
                    "expected_detector_ids": ["missing.detector"],
                    "expected_detector_families": ["missing-family"],
                }
            ]
        )

        self.assertEqual(report["failed"], 1)
        failures = " ".join(report["results"][0]["failures"])
        self.assertIn("detector ids", failures)
        self.assertIn("detector families", failures)

    def test_known_gap_reports_would_failures_without_failing(self):
        report = self.firewall.evaluate(
            [
                {
                    "id": "person-gap",
                    "category": "known-gap-person",
                    "surface": "output.content",
                    "known_gap": True,
                    "payload": {
                        "choices": [
                            {"message": {"content": "Lisa Nakamura approved the memo."}}
                        ]
                    },
                    "sensitive_values": ["Lisa Nakamura"],
                    "expected_absent": ["Lisa Nakamura"],
                    "expected_blocked": False,
                    "expected_no_findings": True,
                }
            ]
        )

        self.assertEqual(report["failed"], 0)
        self.assertEqual(report["known_gap_cases"], 1)
        self.assertEqual(report["known_gap_leaked_after"], 1)
        self.assertEqual(report["known_gap_would_fail"], 1)
        self.assertEqual(report["leaked_after"], 1)
        self.assertEqual(report["sensitive_values_leaked_after"], 1)
        self.assertTrue(report["results"][0]["known_gap"])
        self.assertTrue(report["results"][0]["would_failures"])
        self.assertNotIn("Lisa Nakamura", json.dumps(report))

    def test_sensitive_values_are_automatically_sanitized_from_audit_metadata(self):
        firewall = Firewall(load_policy("policies/default.yaml"), scanner=RawMetadataScanner())
        report = firewall.evaluate(
            [
                {
                    "id": "audit-raw-value-violation",
                    "payload": {
                        "messages": [
                            {"role": "user", "content": "SSN 000-00-0000"}
                        ]
                    },
                    "sensitive_values": ["000-00-0000"],
                }
            ]
        )

        self.assertEqual(report["failed"], 0)
        self.assertEqual(report["audit_raw_value_violations"], 0)
        self.assertNotIn("000-00-0000", json.dumps(report))


class RawMetadataScanner:
    def scan(self, surface: Surface) -> list[Finding]:
        if "000-00-0000" not in surface.value:
            return []
        start = surface.value.index("000-00-0000")
        return [
            Finding(
                entity="US_SSN",
                surface=surface.name,
                pointer=surface.pointer,
                start=start,
                end=start + len("000-00-0000"),
                value="000-00-0000",
                confidence=1.0,
                json_pointer=surface.json_pointer,
                detector_id="test.raw_metadata",
                detector_family="test",
                metadata={"unsafe_raw_value": "000-00-0000"},
            )
        ]


class ObservabilityFakeSinkTests(unittest.TestCase):
    def setUp(self):
        self.firewall = Firewall(load_policy("policies/default.yaml"))

    def test_blocked_secret_trace_is_not_forwarded(self):
        sink = FakeSink()
        payload = {"trace": {"span": "api_fixture0000000001 reached tracing"}}
        result = forward_if_allowed(self.firewall, sink, payload)

        self.assertTrue(result.blocked)
        self.assertEqual(sink.forwarded, [])

    def test_redacted_trace_reaches_sink_without_raw_values(self):
        sink = FakeSink()
        payload = {"trace": {"span": "Patient MRN: LSDF-FIXTURE-00001 reached tracing"}}
        result = forward_if_allowed(self.firewall, sink, payload)

        self.assertFalse(result.blocked)
        self.assertEqual(len(sink.forwarded), 1)
        self.assertNotIn("MRN: LSDF-FIXTURE-00001", str(sink.forwarded[0]))
        self.assertIn("<MRN:REDACTED>", str(sink.forwarded[0]))

    def test_blocked_tool_arguments_do_not_reach_executor(self):
        executor = FakeSink()
        payload = {
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {
                                "function": {
                                    "name": "send_webhook",
                                    "arguments": json.dumps(
                                        {"api_key": "api_fixture0000000001"}
                                    ),
                                }
                            }
                        ]
                    }
                }
            ]
        }
        result = forward_if_allowed(self.firewall, executor, payload)

        self.assertTrue(result.blocked)
        self.assertEqual(executor.forwarded, [])

    def test_benign_observability_payload_passes_unchanged(self):
        sink = FakeSink()
        payload = {"trace": {"span": "route completed in 42 ms with zero retries"}}
        result = forward_if_allowed(self.firewall, sink, payload)

        self.assertFalse(result.blocked)
        self.assertFalse(result.decisions)
        self.assertEqual(sink.forwarded, [payload])


class FakeSink:
    def __init__(self):
        self.forwarded = []

    def send(self, payload):
        self.forwarded.append(deepcopy(payload))


def forward_if_allowed(firewall: Firewall, sink: FakeSink, payload):
    result = firewall.inspect(payload)
    if not result.blocked:
        sink.send(result.transformed_payload)
    return result


class EvalMatrixGeneratorTests(unittest.TestCase):
    def test_build_eval_batteries_are_deterministic(self):
        self.assertEqual(build_eval_batteries(), build_eval_batteries())
        self.assertEqual(build_safety_matrix(), build_safety_matrix())
        self.assertEqual(build_utility_matrix(), build_utility_matrix())
        self.assertEqual(build_observability_matrix(), build_observability_matrix())

    def test_committed_eval_files_match_generator(self):
        expected = build_eval_batteries()
        for battery, dataset in expected.items():
            actual = json.loads(
                Path("evals", BATTERY_FILENAMES[battery]).read_text(encoding="utf-8")
            )
            self.assertEqual(actual, dataset)

    def test_generated_case_ids_are_unique_and_metadata_complete(self):
        datasets = build_eval_batteries()
        cases = [case for dataset in datasets.values() for case in dataset["cases"]]
        ids = [case["id"] for case in cases]

        self.assertGreaterEqual(len(cases), 150)
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all("category" in case for case in cases))
        self.assertTrue(all("surface" in case for case in cases))
        self.assertTrue(
            all(
                any(
                    key in case
                    for key in (
                        "expected_blocked",
                        "expected_no_findings",
                        "expected_actions",
                    )
                )
                for case in cases
            )
        )

    def test_generated_batteries_include_broader_provider_token_shapes(self):
        cases = build_safety_matrix()["cases"]
        rendered = json.dumps(cases)

        self.assertIn("api_LSDF_FIXTURE_EVAL_000003", rendered)
        self.assertIn("token-fixture0000000004", rendered)
        self.assertIn("Pgr_Bkup_77#Rotate_2026", rendered)

    def test_generator_writes_all_batteries_to_output_dir(self):
        from lsdf.eval_matrix import main

        with TemporaryDirectory() as tmpdir:
            status = main(["--battery", "all", "--output-dir", tmpdir])
            self.assertEqual(status, 0)
            for filename in BATTERY_FILENAMES.values():
                self.assertTrue(Path(tmpdir, filename).exists())


if __name__ == "__main__":
    unittest.main()
