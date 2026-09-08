import io
import importlib.util
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from lsdf.cli import main
from lsdf.comparison import compare_detector_sets, default_detector_sets, parse_detector_set
from lsdf.policy import load_policy
from lsdf.reporting import format_detector_comparison_markdown
from lsdf.scanners.presidio import PresidioDetector


class DetectorComparisonTests(unittest.TestCase):
    def test_default_detector_sets_cover_dependency_light_progression(self):
        sets = default_detector_sets()

        self.assertEqual([detector_set.name for detector_set in sets], ["regex", "regex_entropy", "default"])
        self.assertEqual(
            sets[2].families,
            ("regex", "entropy", "medical-regex", "contextual-anchored"),
        )

    def test_parse_detector_set_requires_name_and_family_list(self):
        detector_set = parse_detector_set("baseline=regex,entropy")

        self.assertEqual(detector_set.name, "baseline")
        self.assertEqual(detector_set.families, ("regex", "entropy"))
        with self.assertRaisesRegex(ValueError, "NAME=family"):
            parse_detector_set("regex")
        with self.assertRaisesRegex(ValueError, "name cannot be empty"):
            parse_detector_set("=regex")
        with self.assertRaisesRegex(ValueError, "at least one"):
            parse_detector_set("empty=")

    def test_default_comparison_sets_run_basic_dataset_safely(self):
        dataset_path = Path("evals/basic.json")
        report = compare_detector_sets(
            policy=load_policy("policies/default.yaml"),
            dataset=_read_dataset(dataset_path),
            dataset_path=dataset_path,
        )

        self.assertEqual(report["dataset"], "basic.json")
        self.assertEqual([result["name"] for result in report["detector_sets"]], ["regex", "regex_entropy", "default"])
        self.assertEqual({result["status"] for result in report["detector_sets"]}, {"ok"})
        self.assertNotIn("R3d1s_Pr0d_2024!Secure", json.dumps(report))

    def test_eval_batteries_have_safe_comparison_reports(self):
        policy = load_policy("policies/default.yaml")
        for path in (
            Path("evals/safety_matrix.json"),
            Path("evals/utility_matrix.json"),
            Path("evals/observability_matrix.json"),
        ):
            with self.subTest(path=path):
                report = compare_detector_sets(
                    policy=policy,
                    dataset=_read_dataset(path),
                    dataset_path=path,
                )
                self.assertEqual(len(report["detector_sets"]), 3)
                self.assertEqual({result["status"] for result in report["detector_sets"]}, {"ok"})

    def test_unavailable_optional_detector_set_is_reported_not_raised(self):
        dataset_path = Path("evals/basic.json")
        report = compare_detector_sets(
            policy=load_policy("policies/default.yaml"),
            dataset=_read_dataset(dataset_path),
            dataset_path=dataset_path,
            detector_sets=[parse_detector_set("pii=presidio")],
        )

        result = report["detector_sets"][0]
        self.assertEqual(result["name"], "pii")
        self.assertEqual(result["status"], "unavailable")
        self.assertIn("presidio", result["reason"])

    def test_custom_presidio_sets_run_with_mock_provider(self):
        dataset_path = Path("mock-presidio.json")
        dataset = {
            "name": "mock-presidio",
            "cases": [
                {
                    "id": "person-output",
                    "payload": {
                        "choices": [{"message": {"content": "Alice Smith checked in."}}]
                    },
                    "expected_entities": ["PERSON"],
                    "expected_detector_families": ["presidio"],
                }
            ],
        }
        report = compare_detector_sets(
            policy=load_policy("policies/default.yaml"),
            dataset=dataset,
            dataset_path=dataset_path,
            detector_sets=[
                parse_detector_set("presidio=presidio"),
                parse_detector_set("default_presidio=regex,entropy,medical-regex,contextual-anchored,presidio"),
            ],
            detector_providers={
                "presidio": PresidioDetector(
                    FakePresidioAnalyzer(
                        [{"entity_type": "PERSON", "start": 0, "end": 11, "score": 0.99}]
                    )
                )
            },
        )

        results = report["detector_sets"]
        self.assertEqual([result["status"] for result in results], ["ok", "ok"])
        self.assertEqual(results[0]["detector_families"], ["presidio"])
        self.assertEqual(
            results[1]["detector_families"],
            ["regex", "entropy", "medical-regex", "contextual-anchored", "presidio"],
        )

    def test_comparison_reports_known_gap_leakage_counts(self):
        dataset_path = Path("known-gap.json")
        dataset = {
            "name": "known-gap",
            "cases": [
                {
                    "id": "known-gap-leak",
                    "payload": {
                        "choices": [
                            {"message": {"content": "The missing value is INTERNAL-123."}}
                        ]
                    },
                    "expected_absent": ["INTERNAL-123"],
                    "known_gap": True,
                }
            ],
        }

        report = compare_detector_sets(
            policy=load_policy("policies/default.yaml"),
            dataset=dataset,
            dataset_path=dataset_path,
            detector_sets=[parse_detector_set("regex=regex")],
        )
        result = report["detector_sets"][0]
        markdown = format_detector_comparison_markdown(report)

        self.assertEqual(result["known_gap_cases"], 1)
        self.assertEqual(result["known_gap_leaked_after"], 1)
        self.assertEqual(result["known_gap_would_fail"], 1)
        self.assertIn("Known-Gap Leaks", markdown)
        self.assertIn("Known-Gap Would-Fail", markdown)

    def test_comparative_protection_doc_is_linked_and_reproducible(self):
        doc = Path("docs/comparative-protection.md").read_text(encoding="utf-8")
        readme = Path("README.md").read_text(encoding="utf-8")

        self.assertIn("docs/comparative-protection.md", readme)
        for required in (
            "## Comparator Survey",
            "Microsoft Presidio",
            "`regex_only`",
            "`presidio`",
            "`lsdf_broad_pii`",
            "In the recorded comparison, `lsdf_broad_pii` had higher threat recall",
            "Dependency-light LSDF loses to `presidio` on `nemotron_pii`: 0.267 vs 0.326",
            "Dependency-light LSDF ties `regex_only` on `br_agentic_pii` at 0.846",
            "optional detector RNGs are seeded with `0`",
            "`EVAL.md` as the release-gate source of truth",
            "Presidio also produced benign false positives",
            "--entrypoint python optional-cli",
            "--seed 0",
            "compare-detectors",
        ):
            with self.subTest(required=required):
                self.assertIn(required, doc)

    def test_comparative_protection_generator_requires_measured_stacks(self):
        generator = _load_comparative_generator()

        with self.assertRaisesRegex(RuntimeError, "required comparator stack unavailable"):
            generator._assert_required_stacks_available(
                [
                    {"name": "regex_only", "status": "ok"},
                    {
                        "name": "presidio",
                        "status": "unavailable",
                        "reason": "missing optional dependency",
                    },
                    {"name": "lsdf_dependency_light", "status": "ok"},
                    {"name": "lsdf_broad_pii", "status": "ok"},
                ]
            )


class DetectorComparisonCliTests(unittest.TestCase):
    def test_compare_detectors_json_is_safe_by_default(self):
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            status = main(["compare-detectors", "evals/basic.json"])

        report = json.loads(stdout.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(report["detector_sets"][0]["name"], "regex")
        self.assertNotIn("R3d1s_Pr0d_2024!Secure", stdout.getvalue())

    def test_compare_detectors_reveal_sensitive_values_restores_debug_values(self):
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            status = main(
                ["compare-detectors", "evals/basic.json", "--reveal-sensitive-values"]
            )

        self.assertEqual(status, 0)
        self.assertIn("R3d1s_Pr0d_2024!Secure", stdout.getvalue())

    def test_compare_detectors_markdown_lists_unavailable_sets_safely(self):
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            status = main(
                [
                    "compare-detectors",
                    "evals/basic.json",
                    "--format",
                    "markdown",
                    "--set",
                    "optional=presidio",
                ]
            )

        output = stdout.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("# LSDF Detector Comparison", output)
        self.assertIn("optional", output)
        self.assertIn("unavailable", output)
        self.assertNotIn("R3d1s_Pr0d_2024!Secure", output)

    def test_compare_detectors_rejects_malformed_set(self):
        stderr = io.StringIO()

        with redirect_stderr(stderr):
            status = main(["compare-detectors", "evals/basic.json", "--set", "regex"])

        self.assertEqual(status, 2)
        self.assertIn("NAME=family", stderr.getvalue())


def _read_dataset(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _load_comparative_generator():
    import sys

    script_path = Path("scripts/build_comparative_protection.py")
    spec = importlib.util.spec_from_file_location(
        "build_comparative_protection",
        script_path,
    )
    if spec is None or spec.loader is None:
        raise AssertionError("Unable to load comparative protection generator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FakePresidioAnalyzer:
    def __init__(self, results):
        self.results = results

    def analyze(self, *, text, entities, language):
        return self.results if text else []


if __name__ == "__main__":
    unittest.main()
