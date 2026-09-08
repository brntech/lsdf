# SPDX-License-Identifier: Apache-2.0
"""Checks run inside the runtime image, with only this script mounted."""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class RuntimeImageSmokeTests(unittest.TestCase):
    def cli(self, *args, expected=0):
        result = subprocess.run(
            [sys.executable, "-m", "lsdf.cli", *args],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(result.returncode, expected, "runtime CLI exit status")
        return result.stdout

    def test_runtime_contains_only_expected_evaluation_assets(self):
        self.assertEqual(
            {path.name for path in Path("evals").iterdir()},
            {
                "safety_matrix.json",
                "utility_matrix.json",
                "observability_matrix.json",
                "coding_matrix.json",
            },
        )
        self.assertTrue(Path("tests/foundation/fixtures").is_dir())
        self.assertFalse(list(Path("tests").rglob("*.py")))
        for path in (".git", "scripts", "examples", "docs", "AGENTS.md", "CLAUDE.md"):
            self.assertFalse(Path(path).exists(), path)

    def test_detector_dependencies_match_image_target(self):
        for module in ("torch", "transformers", "presidio_analyzer", "gliner"):
            if os.environ.get("LSDF_RUNTIME_OPTIONAL") == "true":
                self.assertIsNotNone(importlib.util.find_spec(module), module)
            else:
                self.assertIsNone(importlib.util.find_spec(module), module)
        if os.environ.get("LSDF_RUNTIME_OPTIONAL") == "true":
            worker = os.environ["LSDF_OPENAI_PRIVACY_FILTER_PYTHON"]
            self.assertTrue(Path(worker).is_file())
            result = subprocess.run(
                [worker, "-c", "import transformers; from transformers import AutoModelForTokenClassification, AutoTokenizer, pipeline; assert transformers.__version__ == '5.7.0'; assert callable(pipeline)"],
                capture_output=True, timeout=60,
            )
            self.assertEqual(result.returncode, 0, "optional worker startup")

    def test_image_default_gateway_profile_works_without_model_cache(self):
        from lsdf.engine import Firewall
        from lsdf.gateway import resolve_gateway_config
        from lsdf.policy import load_effective_policy

        config = resolve_gateway_config(upstream_base_url="http://127.0.0.1:9")
        self.assertEqual(config.policy_profile, "default")
        firewall = Firewall(load_effective_policy(config.policy_profile))
        self.assertIsNotNone(firewall)
        report = json.loads(self.cli("doctor", "--profile", config.policy_profile, "--format", "json"))
        self.assertEqual(report["status"], "ok")

    def test_doctor_and_all_builtin_policies_load(self):
        self.assertEqual(json.loads(self.cli("doctor", "--profile", "default", "--format", "json"))["status"], "ok")
        from lsdf.policy import POLICY_PROFILES, load_policy_profile
        for profile in POLICY_PROFILES:
            with self.subTest(profile=profile):
                self.assertIsNotNone(load_policy_profile(profile))

    def test_demo_and_proof_commands_have_their_assets(self):
        self.cli("demo", "--profile", "default")
        report = json.loads(self.cli("protection-report", "--profile", "default", "--format", "json"))
        self.assertEqual(report["dataset_count"], 3)
        self.assertGreater(report["totals"]["case_count"], 0)
        self.assertEqual(report["totals"]["audit_raw_value_violations"], 0)
        with tempfile.TemporaryDirectory() as destination:
            self.cli("proof-bundle", "--profile", "default", "--output", destination)
            manifest = json.loads(Path(destination, "manifest.json").read_text())
            self.assertEqual(manifest["status"], "ok")
            for path in manifest["files"].values():
                self.assertTrue(Path(path).is_file())


if __name__ == "__main__":
    unittest.main(verbosity=2)
