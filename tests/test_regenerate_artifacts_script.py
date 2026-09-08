import shutil
import subprocess
import unittest
from pathlib import Path


SCRIPT_PATH = Path("scripts/regenerate-artifacts.sh")


class RegenerateArtifactsScriptTests(unittest.TestCase):
    """The script ships as a reproducibility one-shot for operators. It is
    not exercised end-to-end by CI (the optional path needs the
    privacy-filter model cache), so this test pins the script's contract
    statically: it parses, names the artifacts it must rewrite, and gates
    the optional path on doctor."""

    def test_script_exists(self):
        self.assertTrue(SCRIPT_PATH.exists(), f"missing {SCRIPT_PATH}")

    def test_script_parses_cleanly(self):
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash interpreter not on PATH")
        result = subprocess.run(
            [bash, "-n", str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            result.returncode,
            0,
            f"bash -n failed: {result.stderr}",
        )

    def test_script_names_each_required_artifact_path(self):
        text = SCRIPT_PATH.read_text(encoding="utf-8")
        for required in (
            "docs/performance.md",
            "docs/system-recall.md",
            "EVAL.md",
            "docs/comparative-protection.md",
            "fp-lever-sweep-",
        ):
            with self.subTest(required=required):
                self.assertIn(required, text)

    def test_script_invokes_each_required_cli_subcommand(self):
        text = SCRIPT_PATH.read_text(encoding="utf-8")
        for command in (
            "cli latency-table",
            "cli detectors recall --regenerate",
            "cli eval-report",
            "build_comparative_protection.py",
            "cli fp-lever-table",
        ):
            with self.subTest(command=command):
                self.assertIn(command, text)

    def test_script_gates_optional_path_on_doctor(self):
        """Optional path must probe via doctor before invoking eval-report
        or fp-lever-table — operators on default-only environments
        should still get the latency table refreshed."""
        text = SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertIn("doctor --profile broad-pii-ml", text)
        self.assertIn("WARNING", text)
        self.assertIn("exit 0", text)

    def test_doctor_probe_precedes_optional_cli_invocations(self):
        """The doctor gate is only meaningful if it runs *before* the optional
        CLI invocations. A refactor that moves the gate downward would break
        the script at runtime but slip past the static contract — pin the
        ordering by byte offset."""
        text = SCRIPT_PATH.read_text(encoding="utf-8")
        doctor_idx = text.find("doctor --profile broad-pii-ml")
        eval_report_idx = text.find("optional-cli eval-report")
        fp_lever_idx = text.find("optional-cli fp-lever-table")
        self.assertGreater(doctor_idx, -1)
        self.assertGreater(eval_report_idx, -1)
        self.assertGreater(fp_lever_idx, -1)
        self.assertLess(doctor_idx, eval_report_idx)
        self.assertLess(doctor_idx, fp_lever_idx)

    def test_script_writes_artifacts_atomically(self):
        """Direct `> file` redirects truncate the destination before the
        command runs; a mid-stream failure leaves the committed artifact
        corrupted. Artifacts rendered from stdout must use a temp-file + mv
        pattern instead."""
        text = SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertIn("mktemp", text)
        self.assertIn("mv ", text)
        # And no direct redirect into the committed artifact paths.
        for committed in ("${PERF_OUT}", "${SYSTEM_RECALL_OUT}", "${EVAL_OUT}", "${SWEEP_OUT}"):
            with self.subTest(committed=committed):
                self.assertNotIn(f"> \"{committed}\"", text)

    def test_system_recall_artifact_has_single_writer(self):
        text = SCRIPT_PATH.read_text(encoding="utf-8")

        self.assertIn("--output \"${SYSTEM_RECALL_OUT}\"", text)
        self.assertNotIn("write_atomic \"${SYSTEM_RECALL_OUT}\"", text)

    def test_system_recall_regeneration_precedes_optional_model_gate(self):
        text = SCRIPT_PATH.read_text(encoding="utf-8")
        system_recall_idx = text.find("cli detectors recall --regenerate")
        doctor_idx = text.find("doctor --profile broad-pii-ml")
        self.assertGreater(system_recall_idx, -1)
        self.assertGreater(doctor_idx, -1)
        self.assertLess(system_recall_idx, doctor_idx)

    def test_script_commit_lookup_crosses_docker_desktop_bind_mount(self):
        text = SCRIPT_PATH.read_text(encoding="utf-8")

        self.assertIn("GIT_DISCOVERY_ACROSS_FILESYSTEM=1 git rev-parse", text)

    def test_script_uses_optional_profile_for_optional_artifacts(self):
        text = SCRIPT_PATH.read_text(encoding="utf-8")
        # Both optional CLI invocations must go through --profile optional
        # via the optional-cli service, not the dependency-light cli service.
        self.assertIn("--profile optional run --rm optional-cli eval-report", text)
        self.assertIn("--profile optional run --rm optional-cli fp-lever-table", text)


if __name__ == "__main__":
    unittest.main()
