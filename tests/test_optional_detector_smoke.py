import json
import os
import unittest
from pathlib import Path

from lsdf.comparison import compare_detector_sets, parse_detector_set
from lsdf.policy import load_policy
from lsdf.scanners.openai_privacy_filter import (
    build_installed_openai_privacy_filter_detector,
)
from lsdf.scanners.presidio import build_installed_presidio_detector
from lsdf.surfaces import Surface


class OptionalDetectorSmokeTests(unittest.TestCase):
    def test_installed_presidio_detector_smoke_when_available(self):
        detector = _presidio_or_skip(self)
        surface = Surface(
            name="output.content",
            pointer=("choices", 0, "message", "content"),
            value="Alice Smith can be reached at dev@example.test or +1 202-555-0199.",
        )

        findings = detector.scan(surface)

        entities = {finding.entity for finding in findings}
        self.assertTrue(entities.intersection({"EMAIL", "PHONE", "PERSON"}))
        for finding in findings:
            self.assertEqual(finding.detector_family, "presidio")
            self.assertEqual(finding.surface, surface.name)
            self.assertNotIn(finding.value, json.dumps(finding.safe_dict()))

    def test_installed_privacy_filter_detector_smoke_when_available(self):
        detector = _privacy_filter_or_skip(self)
        surface = Surface(
            name="output.content",
            pointer=("choices", 0, "message", "content"),
            value=(
                "Contact Alice Smith at dev@example.test or +1 202-555-0199. "
                "The secret is api_LSDF_OPTIONAL_SMOKE_TOKEN."
            ),
        )

        findings = detector.scan(surface)

        entities = {finding.entity for finding in findings}
        self.assertTrue(
            entities.intersection({"EMAIL", "PHONE", "PERSON", "OTHER_SECRET", "BANK_ACCOUNT"})
        )
        for finding in findings:
            self.assertEqual(finding.detector_family, "openai_privacy_filter")
            self.assertEqual(finding.surface, surface.name)
            self.assertIn("provider_latency_seconds", finding.metadata)
            self.assertNotIn(finding.value, json.dumps(finding.safe_dict()))

    def test_optional_detector_battery_comparison_when_enabled(self):
        if os.environ.get("LSDF_RUN_OPTIONAL_DETECTOR_BATTERY_SMOKE") != "1":
            self.skipTest("set LSDF_RUN_OPTIONAL_DETECTOR_BATTERY_SMOKE=1 for bundled evaluation optional-adapter battery smoke")
        presidio = _presidio_or_skip(self)
        privacy_filter = _privacy_filter_or_skip(self)
        dataset_path = Path("evals/safety_matrix.json")
        dataset = json.loads(dataset_path.read_text(encoding="utf-8"))

        report = compare_detector_sets(
            policy=load_policy("policies/default.yaml"),
            dataset=dataset,
            dataset_path=dataset_path,
            detector_sets=[
                parse_detector_set("presidio=presidio"),
                parse_detector_set("privacy=openai_privacy_filter"),
                parse_detector_set(
                    "default_optional=regex,entropy,medical-regex,contextual-anchored,presidio,openai_privacy_filter"
                ),
            ],
            detector_providers={
                "presidio": presidio,
                "openai_privacy_filter": privacy_filter,
            },
        )

        self.assertEqual(
            [result["status"] for result in report["detector_sets"]],
            ["ok", "ok", "ok"],
        )
        self.assertNotIn("R3d1s_Pr0d_2024!Secure", json.dumps(report))


def _presidio_or_skip(test_case):
    try:
        return build_installed_presidio_detector()
    except Exception as exc:
        test_case.skipTest(f"presidio-analyzer is not available for smoke test: {exc}")


def _privacy_filter_or_skip(test_case):
    try:
        return build_installed_openai_privacy_filter_detector()
    except RuntimeError as exc:
        if os.environ.get("LSDF_REQUIRE_OPENAI_PRIVACY_FILTER") == "1":
            raise
        test_case.skipTest(f"OpenAI privacy-filter model path is not available for smoke test: {exc}")


if __name__ == "__main__":
    unittest.main()
