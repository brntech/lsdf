import json
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from lsdf.artifacts import write_optional_detector_artifacts
from lsdf.cli import main
from lsdf.policy import load_policy
from lsdf.scanners.openai_privacy_filter import OpenAIPrivacyFilterDetector
from lsdf.scanners.presidio import PresidioDetector


class OptionalDetectorArtifactWorkflowTests(unittest.TestCase):
    def test_artifact_workflow_writes_safe_reports_with_mock_providers(self):
        with TemporaryDirectory() as tmpdir:
            dataset = _write_dataset(Path(tmpdir))
            output_dir = Path(tmpdir, "artifacts")

            result = write_optional_detector_artifacts(
                policy=load_policy("policies/default.yaml"),
                output_dir=output_dir,
                dataset_paths=[dataset],
                detector_providers={
                    "presidio": PresidioDetector(
                        FakePresidioAnalyzer(
                            [
                                {
                                    "entity_type": "PERSON",
                                    "start": 0,
                                    "end": 11,
                                    "score": 0.98,
                                }
                            ]
                        )
                    ),
                    "openai_privacy_filter": OpenAIPrivacyFilterDetector(
                        FakePrivacyFilterProvider(
                            [
                                {
                                    "category": "private_person",
                                    "start": 0,
                                    "end": 11,
                                    "score": 0.97,
                                }
                            ]
                        ),
                        provider_metadata={
                            "implementation": "test",
                            "model_name": "mock",
                            "load_seconds": 0.01,
                        },
                    ),
                },
                detector_status={
                    "presidio": {"status": "available", "finding_count": 1},
                    "openai_privacy_filter": {
                        "status": "available",
                        "finding_count": 1,
                        "provider": {
                            "implementation": "test",
                            "model_name": "mock",
                            "load_seconds": 0.01,
                        },
                    },
                },
            )

            manifest_path = output_dir / "manifest.json"
            notes_path = output_dir / "operational-notes.md"
            json_report = output_dir / "artifact-test.comparison.json"
            markdown_report = output_dir / "artifact-test.comparison.md"
            self.assertEqual(result.output_dir, output_dir)
            self.assertTrue(manifest_path.exists())
            self.assertTrue(notes_path.exists())
            self.assertTrue(json_report.exists())
            self.assertTrue(markdown_report.exists())
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(
                manifest["artifact_type"],
                "optional-detector-dependency-diagnostic",
            )
            self.assertEqual(manifest["reports"][0]["dataset"], "artifact-test")
            self.assertNotIn("Alice Smith", _read_all(output_dir))
            self.assertNotIn("dev@example.test", _read_all(output_dir))
            notes = notes_path.read_text(encoding="utf-8")
            self.assertIn("default_optional", markdown_report.read_text(encoding="utf-8"))
            self.assertIn("docker compose --profile optional", notes)
            self.assertIn("Dependency Diagnostic", notes)
            self.assertNotIn("pip install", notes)
            self.assertNotIn("PYTHONPATH", notes)
            self.assertNotIn("python3", notes)

    def test_cli_optional_detector_artifacts_writes_safe_unavailable_artifact(self):
        with TemporaryDirectory() as tmpdir:
            dataset = _write_dataset(Path(tmpdir))
            output_dir = Path(tmpdir, "cli-artifacts")
            stdout = StringIO()

            with redirect_stdout(stdout):
                status = main(
                    [
                        "optional-detector-artifacts",
                        "--dataset",
                        str(dataset),
                        "--output-dir",
                        str(output_dir),
                    ]
                )

            self.assertEqual(status, 0)
            manifest = json.loads(stdout.getvalue())
            self.assertEqual(
                manifest["artifact_type"],
                "optional-detector-dependency-diagnostic",
            )
            self.assertEqual(manifest["output_dir"], str(output_dir))
            self.assertTrue((output_dir / "manifest.json").exists())
            self.assertTrue((output_dir / "operational-notes.md").exists())
            self.assertNotIn("Alice Smith", stdout.getvalue())
            self.assertNotIn("dev@example.test", _read_all(output_dir))

    def test_committed_optional_detector_notes_stay_docker_only(self):
        notes = Path(
            "docs/artifacts/optional-detectors/2026-04-28/operational-notes.md"
        ).read_text(encoding="utf-8")

        self.assertIn("docker compose --profile optional", notes)
        self.assertNotIn("pip install", notes)
        self.assertNotIn("PYTHONPATH", notes)
        self.assertNotIn("python3", notes)


class FakePresidioAnalyzer:
    def __init__(self, results):
        self.results = results

    def analyze(self, *, text, entities, language):
        return self.results if text else []


class FakePrivacyFilterProvider:
    def __init__(self, spans):
        self.spans = spans

    def __call__(self, text):
        return self.spans if text else []


def _write_dataset(directory: Path) -> Path:
    path = directory / "artifact-dataset.json"
    path.write_text(
        json.dumps(
            {
                "name": "artifact-test",
                "cases": [
                    {
                        "id": "artifact-person",
                        "payload": {
                            "choices": [
                                {
                                    "message": {
                                        "content": "Alice Smith emailed dev@example.test."
                                    }
                                }
                            ]
                        },
                        "sensitive_values": ["Alice Smith", "dev@example.test"],
                        "expected_detector_families": ["presidio"],
                        "known_gap": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def _read_all(directory: Path) -> str:
    return "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(directory.iterdir())
        if path.is_file()
    )


if __name__ == "__main__":
    unittest.main()
