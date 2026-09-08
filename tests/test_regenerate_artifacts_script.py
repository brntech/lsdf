import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


SCRIPT_PATH = Path("scripts/regenerate-artifacts.sh")
SNAPSHOTS = (
    "EVAL.md",
    "docs/performance.md",
    "docs/comparative-protection.md",
    "docs/fp-lever-sweep-2026-05-07.md",
)
REPORT_DIR = Path(".lsdf/current-reports")
FAKE_DOCKER = r"""#!/usr/bin/env python3
import json
import os
import subprocess
import sys
from pathlib import Path

args = sys.argv[1:]
with Path(os.environ["FAKE_DOCKER_LOG"]).open("a") as log:
    log.write(json.dumps(args) + "\n")
if "doctor" in args:
    broken = os.environ.get("FAKE_DOCTOR_BROKEN")
    if broken:
        if broken == "partial":
            print("{")
        print("synthetic probe startup failure", file=sys.stderr)
        sys.exit(125)
    families = os.environ.get("FAKE_DOCTOR_FAMILIES", "gliner,openai_privacy_filter").split(",")
    status = os.environ.get("FAKE_DOCTOR_STATUS", "ok")
    print(json.dumps({"status": status, "checks": [{"name": "detectors", "status": status, "families": families}]}))
    print("synthetic cache diagnostic", file=sys.stderr)
    sys.exit(int(os.environ.get("FAKE_DOCTOR_RC", "0")))
if "python" in args and "-c" in args:
    # Execute the script's real stdlib-only JSON check inside this test container.
    sys.exit(subprocess.run([sys.executable, *args[args.index("-c"):]]).returncode)
if "latency-table" in args:
    operation = "latency-full" if "optional-cli" in args else "latency-default"
elif "eval-report" in args:
    operation = "eval-full" if "optional-cli" in args else "eval-default"
else:
    operation = "other"
if os.environ.get("FAKE_FAIL") == operation:
    print("synthetic partial output")
    print("synthetic report failure", file=sys.stderr)
    sys.exit(23)
if os.environ.get("FAKE_EMPTY") == operation:
    sys.exit(0)
if "recall" in args:
    output = Path(args[args.index("--output") + 1])
    output.write_text("synthetic foundation recall\n")
    output.with_name("system-recall-history.jsonl").write_text('{"synthetic":true}\n')
print(json.dumps({"synthetic_command": args}))
"""


class RegenerateArtifactsScriptTests(unittest.TestCase):
    """Exercise the real shell orchestration with a fake Docker executable.

    All files live in a temporary minimal directory; no model/container commands
    are dispatched by this harness and no real benchmark snapshots are written.
    """

    def setUp(self):
        self.bash = shutil.which("bash")
        if self.bash is None:
            self.skipTest("bash interpreter not on PATH")
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        script = self.root / SCRIPT_PATH
        script.parent.mkdir()
        shutil.copyfile(SCRIPT_PATH, script)
        for name in SNAPSHOTS:
            snapshot = self.root / name
            snapshot.parent.mkdir(parents=True, exist_ok=True)
            snapshot.write_text("preserved historical snapshot: " + name)
        self.before = {name: (self.root / name).read_bytes() for name in SNAPSHOTS}
        reports = self.root / REPORT_DIR
        reports.mkdir(parents=True)
        for name in ("performance-default-balanced.md", "performance-full-matrix.md",
                     "eval-default-balanced.md", "eval-full-matrix.md", "comparative-protection.md"):
            (reports / name).write_text("previous scratch report")
        bindir = self.root / "bin"
        bindir.mkdir()
        docker = bindir / "docker"
        docker.write_text(FAKE_DOCKER)
        docker.chmod(0o755)
        self.log = self.root / "docker-calls.jsonl"
        self.env = {**os.environ, "PATH": str(bindir) + os.pathsep + os.environ["PATH"],
                    "FAKE_DOCKER_LOG": str(self.log)}

    def run_script(self, **env):
        result = subprocess.run(
            [self.bash, str(self.root / SCRIPT_PATH)],
            cwd=self.root, env={**self.env, **env}, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(
            {name: (self.root / name).read_bytes() for name in SNAPSHOTS},
            self.before,
            "current report generation must preserve recorded snapshots",
        )
        self.assertEqual(list((self.root / REPORT_DIR).glob("*.tmp.*")), [])
        return result

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def report(self, name):
        return (self.root / REPORT_DIR / name).read_text()

    def test_script_parses_cleanly(self):
        result = subprocess.run([self.bash, "-n", str(SCRIPT_PATH)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_ml_preserves_optional_reports_and_snapshots(self):
        result = self.run_script(FAKE_DOCTOR_RC="2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("synthetic cache diagnostic", result.stderr)
        for name in ("performance-full-matrix.md", "eval-full-matrix.md", "comparative-protection.md"):
            self.assertEqual(self.report(name), "previous scratch report")
            self.assertIn(name, result.stderr)
        self.assertIn("latency-table", self.report("performance-default-balanced.md"))
        self.assertIn("eval-report", self.report("eval-default-balanced.md"))
        calls = self.calls()
        optional = [args for args in calls if "optional-cli" in args]
        self.assertEqual(len(optional), 1)
        self.assertIn("doctor", optional[0])
        recall = next(args for args in calls if "recall" in args)
        self.assertIn("--regenerate", recall)
        self.assertIn("docs/system-recall.md", recall)
        self.assertTrue(any(arg.startswith("LSDF_COMMIT_SHA=") for arg in recall))
        self.assertLess(calls.index(recall), calls.index(optional[0]))
        self.assertEqual((self.root / "docs/system-recall.md").read_text(), "synthetic foundation recall\n")

    def test_ready_ml_writes_separate_current_reports(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        default_args = json.loads(self.report("performance-default-balanced.md"))["synthetic_command"]
        full_args = json.loads(self.report("performance-full-matrix.md"))["synthetic_command"]
        for args, profiles, iterations in (
            (default_args, ["default", "balanced"], "50"),
            (full_args, ["optional", "default", "balanced", "broad-pii", "broad-pii-ml"], "1"),
        ):
            self.assertEqual([args[i + 1] for i, arg in enumerate(args) if arg == "--profile"], profiles)
            self.assertEqual(args[args.index("--iterations") + 1], iterations)
        for name in ("eval-default-balanced.md", "eval-full-matrix.md", "comparative-protection.md"):
            self.assertIn("synthetic_command", self.report(name))
        self.assertEqual(len(list((self.root / REPORT_DIR).glob("fp-lever-sweep-*.md"))), 1)
        calls = self.calls()
        doctor_index = next(i for i, args in enumerate(calls) if "doctor" in args)
        self.assertTrue(all(i > doctor_index for i, args in enumerate(calls)
                            if "optional-cli" in args and "doctor" not in args))

    def test_successful_doctor_without_either_model_preserves_full_reports(self):
        for families in ("gliner", "openai_privacy_filter"):
            with self.subTest(families=families):
                self.log.unlink(missing_ok=True)
                result = self.run_script(FAKE_DOCTOR_FAMILIES=families)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("requires loaded gliner and openai_privacy_filter", result.stderr)
                for name in ("performance-full-matrix.md", "eval-full-matrix.md", "comparative-protection.md"):
                    self.assertEqual(self.report(name), "previous scratch report")
                doctor = json.loads(self.report("doctor-optional.json"))
                self.assertEqual(doctor["checks"][0]["families"], [families])
                optional = [args for args in self.calls() if "optional-cli" in args]
                self.assertEqual(len(optional), 1)
                self.assertIn("doctor", optional[0])

    def test_every_optional_command_overrides_operator_download_opt_ins(self):
        result = self.run_script(
            LSDF_GLINER_LOCAL_FILES_ONLY="false",
            LSDF_OPENAI_PRIVACY_FILTER_LOCAL_FILES_ONLY="false",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        optional = [args for args in self.calls() if "optional-cli" in args]
        self.assertEqual(len(optional), 5)
        for args in optional:
            overrides = [args[i + 1] for i, arg in enumerate(args) if arg == "-e"]
            self.assertIn("LSDF_GLINER_LOCAL_FILES_ONLY=true", overrides)
            self.assertIn("LSDF_OPENAI_PRIVACY_FILTER_LOCAL_FILES_ONLY=true", overrides)

    def test_probe_startup_failure_preserves_prior_json_without_authorizing_ml(self):
        previous = json.dumps({"status": "ok", "checks": [{
            "name": "detectors", "status": "ok", "families": ["gliner", "openai_privacy_filter"],
        }], "generation": "previous"})
        probe = self.root / REPORT_DIR / "doctor-optional.json"
        for broken in ("empty", "partial"):
            with self.subTest(broken=broken):
                self.log.unlink(missing_ok=True)
                probe.write_text(previous)
                result = self.run_script(FAKE_DOCTOR_BROKEN=broken)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(probe.read_text(), previous)
                self.assertIn("synthetic probe startup failure", result.stderr)
                self.assertIn("previous probe, if present, is unchanged", result.stderr)
                self.assertIn("retained probe is stale for this run", result.stderr)
                optional = [args for args in self.calls() if "optional-cli" in args]
                self.assertEqual(len(optional), 1)
                self.assertEqual(self.report("performance-full-matrix.md"), "previous scratch report")

    def test_fresh_valid_failed_probe_replaces_prior_json_and_skips_ml(self):
        probe = self.root / REPORT_DIR / "doctor-optional.json"
        probe.write_text(json.dumps({"status": "ok", "checks": [], "generation": "previous"}))
        result = self.run_script(FAKE_DOCTOR_RC="2", FAKE_DOCTOR_STATUS="error", FAKE_DOCTOR_FAMILIES="gliner")
        self.assertEqual(result.returncode, 0, result.stderr)
        fresh = json.loads(probe.read_text())
        self.assertEqual(fresh["status"], "error")
        self.assertNotIn("generation", fresh)
        self.assertEqual(fresh["checks"][0]["families"], ["gliner"])
        self.assertIn("doctor exit 2; probe not-ready", result.stderr)
        self.assertIn("Fresh diagnostics saved", result.stderr)
        self.assertEqual(len([args for args in self.calls() if "optional-cli" in args]), 1)
        self.assertEqual(self.report("performance-full-matrix.md"), "previous scratch report")

    def test_failed_or_empty_output_preserves_previous_scratch_report(self):
        for setting, operation, output, exit_code in (
            ("FAKE_FAIL", "latency-default", "performance-default-balanced.md", 23),
            ("FAKE_FAIL", "latency-full", "performance-full-matrix.md", 23),
            ("FAKE_EMPTY", "latency-default", "performance-default-balanced.md", 1),
        ):
            with self.subTest(setting=setting, operation=operation):
                (self.root / REPORT_DIR / output).write_text("previous scratch report")
                result = self.run_script(**{setting: operation})
                self.assertEqual(result.returncode, exit_code, result.stderr)
                self.assertEqual(self.report(output), "previous scratch report")
                self.assertIn("existing file unchanged", result.stderr)
                if setting == "FAKE_FAIL":
                    self.assertIn("synthetic report failure", result.stderr)


if __name__ == "__main__":
    unittest.main()
