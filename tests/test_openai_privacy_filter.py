import json
import os
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from lsdf import Firewall
from lsdf.cli import main
from lsdf.comparison import compare_detector_sets, parse_detector_set
from lsdf.detectors import build_detector_registry
from lsdf.policy import AuditConfig, DetectorConfig, Policy, load_policy
from lsdf.scanners.openai_privacy_filter import (
    OpenAIPrivacyFilterDetector,
    TransformersPrivacyFilterProvider,
    build_installed_openai_privacy_filter_detector,
)
from lsdf.surfaces import Surface


class OpenAIPrivacyFilterRegistryTests(unittest.TestCase):
    def test_registry_builds_privacy_filter_when_provider_is_registered(self):
        detector = OpenAIPrivacyFilterDetector(
            FakePrivacyFilterProvider(
                [{"category": "secret", "start": 1, "end": 4, "score": 0.94}]
            )
        )
        registry = build_detector_registry(
            ("openai_privacy_filter",),
            detector_providers={"openai_privacy_filter": detector},
        )

        findings = registry.scan(Surface("output.content", ("content",), "abcdef"))

        self.assertEqual(
            registry.summary()["detector_families"], ["openai_privacy_filter"]
        )
        self.assertEqual(findings[0].entity, "OTHER_SECRET")
        self.assertEqual(findings[0].detector_id, "openai_privacy_filter.secret")

    def test_policy_privacy_filter_family_uses_registered_mock_provider(self):
        policy = Policy(
            version="test",
            name="privacy-filter-mock",
            mode="redact",
            entities={"SECRET"},
            surfaces={"output.content"},
            rules=[],
            audit=AuditConfig(),
            detectors=DetectorConfig(enabled_families=("openai_privacy_filter",)),
        )
        detector = OpenAIPrivacyFilterDetector(
            FakePrivacyFilterProvider(
                [{"category": "secret", "start": 9, "end": 31, "score": 0.89}]
            )
        )
        firewall = Firewall(policy, detector_providers={"openai_privacy_filter": detector})

        result = firewall.inspect(
            {
                "choices": [
                    {"message": {"content": "Password R3d1s_Pr0d_2024!Secure leaked."}}
                ]
            }
        )

        self.assertEqual(
            firewall.detector_summary()["detector_families"], ["openai_privacy_filter"]
        )
        self.assertEqual(result.findings[0].value, "R3d1s_Pr0d_2024!Secure")
        self.assertEqual(result.findings[0].confidence, 0.89)


class OpenAIPrivacyFilterAdapterTests(unittest.TestCase):
    def test_privacy_filter_adapter_maps_result_to_normalized_finding(self):
        surface = Surface(
            name="output.reasoning",
            pointer=("choices", 0, "message", "reasoning_content"),
            json_pointer=("trace",),
            value="Call Alice Smith at +1 202 555 0172.",
        )
        detector = OpenAIPrivacyFilterDetector(
            FakePrivacyFilterProvider(
                [
                    {
                        "entity_group": "private_person",
                        "start": 5,
                        "end": 16,
                        "score": 0.98,
                    }
                ]
            )
        )

        findings = detector.scan(surface)

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.entity, "PERSON")
        self.assertEqual(finding.surface, surface.name)
        self.assertEqual(finding.pointer, surface.pointer)
        self.assertEqual(finding.json_pointer, ("trace",))
        self.assertEqual((finding.start, finding.end), (5, 16))
        self.assertEqual(finding.value, "Alice Smith")
        self.assertEqual(finding.confidence, 0.98)
        self.assertEqual(finding.detector_id, "openai_privacy_filter.private_person")
        self.assertEqual(finding.detector_family, "openai_privacy_filter")
        self.assertEqual(finding.metadata["privacy_filter_category"], "private_person")
        self.assertEqual(finding.metadata["source_span_count"], 1)
        self.assertNotIn("Alice Smith", json.dumps(finding.safe_dict()))

    def test_privacy_filter_adapter_merges_adjacent_same_category_spans(self):
        surface = Surface(
            name="output.content",
            pointer=("content",),
            value="SSN 478-33-9182 is visible.",
        )
        detector = OpenAIPrivacyFilterDetector(
            FakePrivacyFilterProvider(
                [
                    {"entity": "account_number", "start": 4, "end": 14, "score": 0.82},
                    {"entity": "account_number", "start": 14, "end": 15, "score": 0.96},
                ]
            )
        )

        findings = detector.scan(surface)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].entity, "BANK_ACCOUNT")
        self.assertEqual(findings[0].value, "478-33-9182")
        self.assertEqual(findings[0].confidence, 0.96)
        self.assertEqual(findings[0].metadata["source_span_count"], 2)
        self.assertEqual(findings[0].metadata["source_scores"], [0.82, 0.96])

    def test_privacy_filter_adapter_filters_low_scores_and_bio_prefixes(self):
        detector = OpenAIPrivacyFilterDetector(
            FakePrivacyFilterProvider(
                [
                    {"label": "B-private_email", "start": 0, "end": 16, "score": 0.93},
                    {"label": "S-private_phone", "start": 17, "end": 29, "score": 0.40},
                ]
            ),
            score_threshold=0.50,
        )
        surface = Surface(
            name="output.content",
            pointer=("content",),
            value="dev@example.test +1 2025550101",
        )

        findings = detector.scan(surface)

        self.assertEqual([finding.entity for finding in findings], ["EMAIL"])
        self.assertEqual(findings[0].detector_id, "openai_privacy_filter.private_email")

    def test_privacy_filter_adapter_defaults_to_threshold_and_known_categories(self):
        detector = OpenAIPrivacyFilterDetector(
            FakePrivacyFilterProvider(
                [
                    {"label": "private_email", "start": 0, "end": 16, "score": 0.49},
                    {"label": "new_private_label", "start": 17, "end": 28, "score": 0.99},
                    {"label": "private_person", "start": 29, "end": 40, "score": 0.98},
                ]
            )
        )
        surface = Surface(
            name="output.content",
            pointer=("content",),
            value="dev@example.test hiddenfield Alice Smith",
        )

        findings = detector.scan(surface)

        self.assertEqual([finding.entity for finding in findings], ["PERSON"])
        self.assertEqual(findings[0].value, "Alice Smith")

    def test_privacy_filter_adapter_scans_stream_chunks(self):
        provider = FakePrivacyFilterProvider(
            [{"label": "private_person", "start": 0, "end": 11, "score": 0.99}]
        )
        detector = OpenAIPrivacyFilterDetector(provider)
        surface = Surface(
            name="output.stream_chunk",
            pointer=("choices", 0, "delta", "content"),
            value="Alice Smith",
        )

        findings = detector.scan(surface)

        self.assertEqual([finding.entity for finding in findings], ["PERSON"])
        self.assertEqual(provider.calls, ["Alice Smith"])


class OpenAIPrivacyFilterComparisonTests(unittest.TestCase):
    def test_custom_privacy_filter_sets_run_with_mock_provider(self):
        dataset = {
            "name": "mock-privacy-filter",
            "cases": [
                {
                    "id": "privacy-filter-person-output",
                    "payload": {
                        "choices": [{"message": {"content": "Alice Smith checked in."}}]
                    },
                    "expected_entities": ["PERSON"],
                    "expected_detector_families": ["openai_privacy_filter"],
                }
            ],
        }
        report = compare_detector_sets(
            policy=load_policy("policies/default.yaml"),
            dataset=dataset,
            dataset_path=Path("mock-privacy-filter.json"),
            detector_sets=[
                parse_detector_set("privacy_filter=openai_privacy_filter"),
                parse_detector_set(
                    "default_privacy=regex,entropy,medical-regex,contextual-anchored,openai_privacy_filter"
                ),
            ],
            detector_providers={
                "openai_privacy_filter": OpenAIPrivacyFilterDetector(
                    FakePrivacyFilterProvider(
                        [
                            {
                                "category": "private_person",
                                "start": 0,
                                "end": 11,
                                "score": 0.99,
                            }
                        ]
                    )
                )
            },
        )

        results = report["detector_sets"]
        self.assertEqual([result["status"] for result in results], ["ok", "ok"])
        self.assertEqual(results[0]["detector_families"], ["openai_privacy_filter"])
        self.assertEqual(
            results[1]["detector_families"],
            ["regex", "entropy", "medical-regex", "contextual-anchored", "openai_privacy_filter"],
        )

    def test_cli_compare_reports_privacy_filter_unavailable_safely(self):
        stdout = StringIO()

        with patch.dict(
            os.environ,
            {
                "LSDF_OPENAI_PRIVACY_FILTER_MODEL": "lsdf/missing-privacy-filter-smoke",
                "LSDF_OPENAI_PRIVACY_FILTER_LOCAL_FILES_ONLY": "true",
            },
        ):
            with redirect_stdout(stdout):
                status = main(
                    [
                        "compare-detectors",
                        "evals/basic.json",
                        "--set",
                        "privacy=openai_privacy_filter",
                        "--format",
                        "markdown",
                    ]
                )

        output = stdout.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("privacy", output)
        self.assertIn("unavailable", output)
        self.assertNotIn("R3d1s_Pr0d_2024!Secure", output)


class OpenAIPrivacyFilterInstalledBuilderTests(unittest.TestCase):
    def test_transformers_provider_wraps_pipeline_output(self):
        provider = TransformersPrivacyFilterProvider(
            lambda text: [
                {"entity": "secret", "start": 7, "end": 13, "score": 0.91}
            ]
        )

        self.assertEqual(
            provider("token: abc123"),
            [{"entity": "secret", "start": 7, "end": 13, "score": 0.91}],
        )
        self.assertEqual(provider(""), [])

    def test_installed_builder_reports_unavailable_without_model_cache(self):
        with patch.dict(
            os.environ,
            {
                "LSDF_OPENAI_PRIVACY_FILTER_MODEL": "lsdf/missing-privacy-filter-smoke",
                "LSDF_OPENAI_PRIVACY_FILTER_LOCAL_FILES_ONLY": "true",
            },
        ):
            with self.assertRaisesRegex(RuntimeError, "openai_privacy_filter|privacy-filter"):
                build_installed_openai_privacy_filter_detector()

    def test_installed_builder_rejects_out_of_range_score_threshold(self):
        """A typo like LSDF_..._SCORE_THRESHOLD=1.85 must fail loudly at
        construction rather than silently silencing every finding (>1.0) or
        letting every span through (<0.0)."""
        for bad in (1.85, 2.0, -0.1, -1.0):
            with self.subTest(threshold=bad):
                with self.assertRaisesRegex(ValueError, r"score_threshold must be in"):
                    build_installed_openai_privacy_filter_detector(
                        score_threshold=bad,
                    )

    def test_installed_builder_rejects_out_of_range_env_var(self):
        with patch.dict(
            os.environ,
            {"LSDF_OPENAI_PRIVACY_FILTER_SCORE_THRESHOLD": "1.85"},
        ):
            with self.assertRaisesRegex(ValueError, r"score_threshold must be in"):
                build_installed_openai_privacy_filter_detector(
                    model_name="lsdf/missing-privacy-filter-smoke",
                )


class FakePrivacyFilterProvider:
    def __init__(self, spans):
        self.spans = spans
        self.calls = []

    def __call__(self, text):
        self.calls.append(text)
        return self.spans if text else []


if __name__ == "__main__":
    unittest.main()
