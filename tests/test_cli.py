import io
import json
import unittest
import urllib.error
from contextlib import redirect_stderr, redirect_stdout
from tempfile import TemporaryDirectory
from pathlib import Path
from unittest.mock import patch

from lsdf.cli import main
from lsdf.detectors import DetectorUnavailableError


class CliTests(unittest.TestCase):
    def test_policy_validate_supports_profile(self):
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            status = main(["policy-validate", "--profile", "strict"])

        self.assertEqual(status, 0)
        self.assertEqual(json.loads(stdout.getvalue())["name"], "strict")

    def test_policy_validate_supports_broad_pii_ml_profile_without_loading_model(self):
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            status = main(["policy-validate", "--profile", "broad-pii-ml"])

        report = json.loads(stdout.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(report["name"], "broad-pii-ml")
        self.assertIn("openai_privacy_filter", report["detector_families"])

    def test_adapters_list_json_shows_user_facing_adapter_names(self):
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            status = main(["adapters", "list", "--format", "json"])

        report = json.loads(stdout.getvalue())
        self.assertEqual(status, 0)
        baseline_names = {row["name"] for row in report["baseline"]}
        adapter_rows = {row["name"]: row for row in report["adapters"]}
        optional_names = {row["name"] for row in report["optional"]}
        self.assertIn("contextual-anchored", baseline_names)
        self.assertIn("contextual-broad", adapter_rows)
        self.assertIn("prompt-injection", adapter_rows)
        self.assertEqual(adapter_rows["prompt-injection"]["family"], "xpia")
        self.assertIn("openai_privacy_filter", optional_names)

    def test_entities_list_json_uses_manifest_vocabulary(self):
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            status = main(["entities", "list", "--format", "json"])

        report = json.loads(stdout.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(str(report["version"]), "0.2")
        for category in ("PHI", "SECRET", "STRONG_ID", "INTERNAL_ID"):
            self.assertIn(category, report["categories"])
        self.assertIn("AWS_KEY", report["categories"]["SECRET"])
        self.assertIn("SWIFT", report["standalone_entities"])
        self.assertIn("OAUTH_TOKEN", report["reserved_subtypes"])

    def test_policy_explain_profile_json_shows_two_axes_and_performance(self):
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            status = main(["policy", "explain", "--profile", "default", "--format", "json"])

        report = json.loads(stdout.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(report["path"], "profile:default")
        self.assertEqual(report["policy"]["name"], "default")
        self.assertEqual(report["unsupported_actions"], [])
        self.assertEqual(report["unavailable_actions"], ["require_approval"])
        self.assertEqual(report["action"]["mode"], "redact")
        self.assertIn("families", report["detection"])
        self.assertIn("actions", report["action"])
        self.assertEqual(report["performance"]["source"], "docs/performance.md")
        self.assertIn("available", report["performance"])
        payloads = report["performance"].get("payloads", {})
        self.assertIn("small_chat_turn", payloads)
        self.assertIn("rag_heavy_session", payloads)
        self.assertNotIn("short_assistant_stream", payloads)
        self.assertNotIn("long_assistant_stream", payloads)
        self.assertNotIn("leak_straddle_stream", payloads)

    def test_policy_explain_markdown_labels_two_axes_and_performance(self):
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            status = main(
                [
                    "policy",
                    "explain",
                    "policies/default.yaml",
                    "--format",
                    "markdown",
                ]
            )

        body = stdout.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("- Unavailable actions: require_approval", body)
        self.assertIn("## Detection Axis", body)
        self.assertIn("## Action Axis", body)
        self.assertIn("## Performance", body)

    def test_policy_validate_rejects_healthcare_double_apply_without_traceback(self):
        stderr = io.StringIO()

        with redirect_stderr(stderr):
            status = main(
                [
                    "policy-validate",
                    "--profile",
                    "healthcare",
                    "--domain-pack",
                    "healthcare",
                ]
            )

        expected = (
            "Error: cannot compose --profile healthcare with --domain-pack healthcare\n"
            "  Both define rules under the `healthcare.*` namespace. Pick one:\n"
            "    --profile healthcare       (clinical defaults)\n"
            "    --profile broad-pii --domain-pack healthcare       (BYO base + pack overlay)"
        )
        self.assertEqual(status, 2)
        self.assertEqual(stderr.getvalue().strip(), expected)
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_policy_validate_notes_prompt_injection_healthcare_threat_model(self):
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            status = main(["policy-validate", "--profile", "strict", "--domain-pack", "healthcare"])

        report = json.loads(stdout.getvalue())
        self.assertEqual(status, 0)
        self.assertIn("notes", report)
        self.assertIn("prompt-injection detects RAG/tool-result attacks, not PHI", report["notes"][0])

    def test_policy_validate_path_wins_over_profile(self):
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            status = main(
                [
                    "policy-validate",
                    "policies/dev.yaml",
                    "--profile",
                    "strict",
                ]
            )

        self.assertEqual(status, 0)
        self.assertEqual(json.loads(stdout.getvalue())["name"], "dev")

    def test_eval_json_redacts_sensitive_values_by_default(self):
        dataset = _write_eval_dataset()
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            status = main(["eval", str(dataset)])

        self.assertEqual(status, 0)
        output = stdout.getvalue()
        self.assertNotIn("R3d1s_Pr0d_2024!Secure", output)
        report = json.loads(output)
        self.assertEqual(report["failed"], 0)
        self.assertEqual(
            report["detector_families"],
            ["regex", "entropy", "medical-regex", "contextual-anchored"],
        )

    def test_eval_reveal_sensitive_values_flag_restores_debug_values(self):
        dataset = _write_eval_dataset()
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            status = main(["eval", str(dataset), "--reveal-sensitive-values"])

        self.assertEqual(status, 0)
        self.assertIn("R3d1s_Pr0d_2024!Secure", stdout.getvalue())

    def test_eval_markdown_report_is_safe_by_default(self):
        dataset = _write_eval_dataset()
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            status = main(["eval", str(dataset), "--format", "markdown"])

        self.assertEqual(status, 0)
        output = stdout.getvalue()
        self.assertIn("# LSDF Eval Report", output)
        self.assertIn("- Dataset: cli_eval", output)
        self.assertNotIn("R3d1s_Pr0d_2024!Secure", output)

    def test_gateway_missing_upstream_config_returns_clear_error(self):
        stderr = io.StringIO()

        with patch.dict("os.environ", {}, clear=True), redirect_stderr(stderr):
            status = main(["gateway"])

        self.assertEqual(status, 2)
        self.assertIn("--upstream-base-url", stderr.getvalue())
        self.assertIn("LSDF_UPSTREAM_BASE_URL", stderr.getvalue())

    def test_gateway_reports_detector_unavailable_without_traceback(self):
        stderr = io.StringIO()

        with patch(
            "lsdf.cli.serve_gateway",
            side_effect=DetectorUnavailableError("optional detector missing"),
        ):
            with redirect_stderr(stderr):
                status = main(["gateway", "--upstream-base-url", "http://upstream.example"])

        self.assertEqual(status, 2)
        self.assertIn("Detector unavailable: optional detector missing", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_sanitize_observability_json_blocks_and_omits_raw_values(self):
        payload = _write_json_payload(
            {"span": {"attributes": {"token": "api_LSDF_FIXTURE_TOKEN_000000"}}}
        )
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            status = main(["sanitize-observability", str(payload), "--format", "json"])

        output = stdout.getvalue()
        report = json.loads(output)
        self.assertEqual(status, 1)
        self.assertTrue(report["blocked"])
        self.assertNotIn("api_LSDF_FIXTURE_TOKEN_000000", output)
        self.assertEqual(
            report["transformed_payload"]["span"]["attributes"]["token"],
            "<API_KEY:REDACTED>",
        )

    def test_doctor_json_reports_healthy_default_setup(self):
        stdout = io.StringIO()
        with TemporaryDirectory() as tmpdir:
            audit_path = Path(tmpdir, "audit.jsonl")
            with redirect_stdout(stdout):
                status = main(
                    [
                        "doctor",
                        "--audit-jsonl-path",
                        str(audit_path),
                        "--format",
                        "json",
                    ]
                )

        report = json.loads(stdout.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(report["status"], "ok")
        self.assertTrue(any(check["name"] == "policy" for check in report["checks"]))
        self.assertTrue(any(check["name"] == "detectors" for check in report["checks"]))

    def test_doctor_privacy_ml_reports_optional_detector_unavailable_in_base_image(self):
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            status = main(["doctor", "--profile", "broad-pii-ml", "--format", "json"])

        report = json.loads(stdout.getvalue())
        self.assertEqual(status, 1)
        self.assertEqual(report["status"], "error")
        self.assertTrue(
            any(
                "openai_privacy_filter" in error
                or "privacy-filter" in error
                or "gliner" in error.lower()
                for error in report["errors"]
            )
        )

    def test_doctor_reports_upstream_transport_error(self):
        stdout = io.StringIO()

        with patch(
            "lsdf.ux.urllib.request.urlopen",
            side_effect=urllib.error.URLError("refused"),
        ), redirect_stdout(stdout):
            status = main(
                [
                    "doctor",
                    "--upstream-base-url",
                    "http://127.0.0.1:9",
                    "--format",
                    "json",
                ]
            )

        report = json.loads(stdout.getvalue())
        self.assertEqual(status, 1)
        self.assertEqual(report["status"], "error")
        self.assertIn("Upstream reachability failed", report["errors"][0])

    def test_doctor_reports_unwritable_audit_path(self):
        with TemporaryDirectory() as tmpdir:
            parent_file = Path(tmpdir, "not-a-directory")
            parent_file.write_text("occupied", encoding="utf-8")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                status = main(
                    [
                        "doctor",
                        "--audit-jsonl-path",
                        str(parent_file / "audit.jsonl"),
                        "--format",
                        "json",
                    ]
                )

        report = json.loads(stdout.getvalue())
        self.assertEqual(status, 1)
        self.assertEqual(report["status"], "error")
        self.assertIn("Audit path is not writable", report["errors"][0])

    def test_init_writes_env_file_and_refuses_overwrite_without_force(self):
        with TemporaryDirectory() as tmpdir:
            output = Path(tmpdir, ".lsdf.env")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                status = main(
                    [
                        "init",
                        "--upstream",
                        "demo",
                        "--profile",
                        "strict",
                        "--audit-jsonl-path",
                        "/workspace/.lsdf/audit.jsonl",
                        "--output",
                        str(output),
                    ]
                )
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                second_status = main(["init", "--upstream", "demo", "--output", str(output)])

            content = output.read_text(encoding="utf-8")

        self.assertEqual(status, 0)
        self.assertEqual(second_status, 2)
        self.assertIn("LSDF_PROFILE=strict", content)
        self.assertIn("LSDF_UPSTREAM_BASE_URL=http://demo-upstream:8091", content)
        self.assertIn("LSDF_AUDIT_JSONL_PATH=/workspace/.lsdf/audit.jsonl", content)
        self.assertIn("already exists", stderr.getvalue())

    def test_init_custom_requires_upstream_base_url(self):
        stderr = io.StringIO()

        with redirect_stderr(stderr):
            status = main(["init", "--upstream", "custom"])

        self.assertEqual(status, 2)
        self.assertIn("--upstream-base-url is required", stderr.getvalue())

    def test_demo_text_and_json_are_raw_value_safe(self):
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            status = main(["demo", "--format", "json"])

        output = stdout.getvalue()
        report = json.loads(output)
        self.assertEqual(status, 0)
        self.assertTrue(report["raw_value_safe"])
        self.assertEqual(report["scenario_count"], 4)
        self.assertNotIn("api_LSDF_FIXTURE_TOKEN_000000", output)
        self.assertNotIn("000-00-0000", output)
        self.assertNotIn("LSDF-FIXTURE-00001", output)

    def test_explain_summarizes_policy_decisions_without_raw_values(self):
        payload = _write_json_payload(
            {"messages": [{"role": "user", "content": "Use api_LSDF_FIXTURE_TOKEN_000000"}]}
        )
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            status = main(["explain", str(payload), "--format", "json"])

        output = stdout.getvalue()
        report = json.loads(output)
        self.assertEqual(status, 1)
        self.assertTrue(report["blocked"])
        self.assertEqual(report["decisions"][0]["action"], "block")
        self.assertNotIn("api_LSDF_FIXTURE_TOKEN_000000", output)

    def test_explain_can_include_transformed_payload(self):
        payload = _write_json_payload(
            {"choices": [{"message": {"content": "Patient MRN: LSDF-FIXTURE-00001"}}]}
        )
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            status = main(
                [
                    "explain",
                    str(payload),
                    "--unknown-surface",
                    "output.content",
                    "--include-transformed-payload",
                    "--format",
                    "json",
                ]
            )

        report = json.loads(stdout.getvalue())
        self.assertEqual(status, 0)
        self.assertIn("transformed_payload", report)
        self.assertIn(
            "<MRN:REDACTED>",
            report["transformed_payload"]["choices"][0]["message"]["content"],
        )

    def test_audit_summary_counts_events_and_malformed_lines_safely(self):
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir, "audit.jsonl")
            path.write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "stage": "request_preflight",
                                "blocked": True,
                                "audit_event": {
                                    "decisions": [
                                        {
                                            "action": "block",
                                            "finding": {
                                                "entity": "API_KEY",
                                                "surface": "input.messages",
                                                "detector_family": "regex",
                                            },
                                        }
                                    ]
                                },
                            }
                        ),
                        json.dumps(
                            {
                                "stage": "stream_terminal",
                                "stream_state": "done",
                                "blocked": False,
                                "surfaces_inspected": ["output.stream_chunk"],
                                "audit_event": {"decisions": []},
                            }
                        ),
                        "{not-json",
                    ]
                ),
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                status = main(["audit-summary", str(path), "--format", "json"])

        report = json.loads(stdout.getvalue())
        self.assertEqual(status, 1)
        self.assertEqual(report["event_count"], 2)
        self.assertEqual(report["malformed_lines"], 1)
        self.assertEqual(report["blocked_events"], 1)
        self.assertEqual(report["by_action"]["block"], 1)
        self.assertEqual(report["by_stream_state"]["done"], 1)

    def test_benchmark_json_has_stable_safe_shape(self):
        payload = _write_json_payload(
            {"messages": [{"role": "user", "content": "Use api_LSDF_FIXTURE_TOKEN_000000"}]}
        )
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            status = main(["benchmark", str(payload), "--iterations", "2"])

        report = json.loads(stdout.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(report["iterations"], 2)
        self.assertEqual(report["mode"], "scan")
        self.assertIn("p95", report["latency_ms"])
        self.assertNotIn("api_LSDF_FIXTURE_TOKEN_000000", stdout.getvalue())

    def test_protection_report_json_uses_custom_dataset(self):
        dataset = _write_eval_dataset()
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            status = main(
                [
                    "protection-report",
                    "--dataset",
                    str(dataset),
                    "--format",
                    "json",
                ]
            )

        report = json.loads(stdout.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(report["dataset_count"], 1)
        self.assertEqual(report["totals"]["case_count"], 1)
        self.assertIn("by_surface", report["summary"])
        self.assertNotIn("R3d1s_Pr0d_2024!Secure", stdout.getvalue())

    def test_eval_report_markdown_runs_default_profile_only(self):
        """eval-report renders the per-detector-family table without optional models."""
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            status = main(
                [
                    "eval-report",
                    "--profile",
                    "default",
                    "--threat-dataset",
                    "evals/piece_b_replay.json",
                    "--benign-dataset",
                    "evals/false_positive.json",
                    "--iterations",
                    "5",
                    "--format",
                    "markdown",
                ]
            )
        body = stdout.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("# LSDF Eval Report", body)
        self.assertIn("Threat-corpus containment", body)
        self.assertIn("Per-detector-family signal vs noise", body)
        self.assertIn("default", body)
        self.assertIn("regex", body)
        # Sanitised replay corpus has fixture-shaped values; none of them should
        # appear verbatim in the report (only family-level counts).
        self.assertNotIn("AKIAIOSFODNN7LSDFFIX", body)

    def test_eval_report_json_includes_family_signal_to_noise(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            status = main(
                [
                    "eval-report",
                    "--profile",
                    "default",
                    "--threat-dataset",
                    "evals/piece_b_replay.json",
                    "--benign-dataset",
                    "evals/false_positive.json",
                    "--iterations",
                    "3",
                    "--format",
                    "json",
                ]
            )
        report = json.loads(stdout.getvalue())
        self.assertEqual(status, 0)
        profile = next(p for p in report["profiles"] if p["profile"] == "default")
        self.assertTrue(profile["available"])
        families = {row["family"] for row in profile["by_detector_family"]}
        self.assertIn("regex", families)
        self.assertGreaterEqual(profile["benchmark"]["iterations"], 1)
        # threat-containment numbers are real, not zeros from a no-op pipeline:
        self.assertEqual(len(profile["threats"]), 1)
        threat = profile["threats"][0]
        self.assertEqual(threat["case_count"], 40)
        self.assertGreater(
            threat["sensitive_values_leaked_before"],
            threat["sensitive_values_leaked_after"],
            "threat sensitive_values_leaked_after must be lower than _before",
        )

    def test_eval_report_failed_healthcare_gate_returns_nonzero(self):
        for report_format in ("json", "markdown"):
            with self.subTest(report_format=report_format):
                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    status = main([
                        "eval-report", "--profile", "healthcare",
                        "--iterations", "1", "--format", report_format,
                    ])
                self.assertEqual(status, 1)
                self.assertIn("ai4privacy_multilingual recall missing", stdout.getvalue())
                if report_format == "json":
                    self.assertFalse(json.loads(stdout.getvalue())["release_gate"]["passed"])
                else:
                    self.assertIn("| healthcare | FAIL |", stdout.getvalue())

    def test_eval_report_explicit_missing_dataset_returns_input_error(self):
        with TemporaryDirectory() as directory:
            missing = Path(directory) / "not-supplied.json"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = main([
                    "eval-report", "--profile", "healthcare",
                    "--threat-dataset", str(missing), "--format", "json",
                ])
        self.assertEqual(status, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("Threat dataset not found", stderr.getvalue())

    def test_eval_report_marks_unknown_profile_unavailable_without_aborting(self):
        """Reviewer fix: a bad profile must NOT abort the whole report."""
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = main(
                [
                    "eval-report",
                    "--profile",
                    "default",
                    "--profile",
                    "this-profile-does-not-exist",
                    "--threat-dataset",
                    "evals/piece_b_replay.json",
                    "--benign-dataset",
                    "evals/false_positive.json",
                    "--iterations",
                    "2",
                    "--format",
                    "json",
                ]
            )
        self.assertEqual(status, 0)
        report = json.loads(stdout.getvalue())
        good = next(p for p in report["profiles"] if p["profile"] == "default")
        bad = next(
            p for p in report["profiles"] if p["profile"] == "this-profile-does-not-exist"
        )
        self.assertTrue(good["available"])
        self.assertFalse(bad["available"])
        self.assertIn("error", bad)

    def test_detectors_recall_markdown_defaults_to_active_profile_summary(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            status = main(["detectors", "recall"])

        body = stdout.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("# LSDF System Recall", body)
        self.assertIn("Foundation-layer detector recall", body)
        self.assertIn("| regex.jwt | JWT | foundation |", body)
        self.assertIn("Coverage gaps:", body)
        self.assertIn(
            "profile/entity pairs in gated profiles have no in-scope detector "
            "with a non-zero foundation floor",
            body,
        )
        self.assertNotIn("## Full matrix", body)
        self.assertNotIn(
            "## Gaps - gated profile entities without an in-scope foundation floor",
            body,
        )
        self.assertNotIn("| xpia.indirect_injection | PROMPT_INJECTION | foundation |", body)
        self.assertIn("| yes |", body)
        self.assertIn("N/A - engine does not target", body)

    def test_detectors_recall_all_prints_full_matrix(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            status = main(["detectors", "recall", "--all"])

        body = stdout.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("## Summary - active-profile detectors", body)
        self.assertIn("## Full matrix", body)
        self.assertIn("| xpia.indirect_injection | PROMPT_INJECTION | foundation |", body)
        self.assertNotIn(
            "## Gaps - gated profile entities without an in-scope foundation floor",
            body,
        )

    def test_detectors_recall_gaps_prints_gap_section_without_full_matrix(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            status = main(["detectors", "recall", "--gaps"])

        body = stdout.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("Coverage gaps:", body)
        self.assertIn(
            "## Gaps - gated profile entities without an in-scope foundation floor",
            body,
        )
        self.assertIn("| SWIFT | broad-pii, broad-pii-ml, healthcare | _none_ |", body)
        self.assertNotIn("| _none_ | _none_ | _none_ |", body)
        self.assertNotIn("## Full matrix", body)

    def test_detectors_recall_json_contains_aggregate_rows(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            status = main(["detectors", "recall", "--format", "json"])

        report = json.loads(stdout.getvalue())
        self.assertEqual(status, 0)
        self.assertIn("generated_at", report)
        self.assertIn("commit_sha", report)
        self.assertIn("floors", report)
        self.assertIn("out_of_scope", report)
        self.assertIn("coverage_gaps", report)
        self.assertIn("count", report["coverage_gaps"])
        self.assertGreater(report["coverage_gaps"]["count"], 0)
        self.assertIn(
            {
                "entity": "SWIFT",
                "profiles": ["broad-pii", "broad-pii-ml", "healthcare"],
                "enabled_detectors": [],
            },
            report["coverage_gaps"]["pairs"],
        )
        self.assertGreater(len(report["results"]), 100)
        row = next(row for row in report["results"] if row["detector"] == "regex.jwt")
        self.assertEqual(
            set(row),
            {"detector", "corpus", "entity", "recall", "specificity", "tp", "fn", "fp", "tn"},
        )

    def test_detectors_recall_regenerate_writes_report_and_history(self):
        with TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir, "system-recall.md")
            history_path = Path(tmpdir, "system-recall-history.jsonl")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                status = main(
                    [
                        "detectors",
                        "recall",
                        "--regenerate",
                        "--output",
                        str(output_path),
                        "--history",
                        str(history_path),
                    ]
                )
            body = stdout.getvalue()
            rendered = output_path.read_text(encoding="utf-8")
            first_history_row = json.loads(
                history_path.read_text(encoding="utf-8").splitlines()[0]
            )

        self.assertEqual(status, 0)
        self.assertIn("# LSDF System Recall", body)
        self.assertIn("# LSDF System Recall", rendered)
        self.assertEqual(
            set(first_history_row),
            {
                "timestamp",
                "commit_sha",
                "detector",
                "corpus",
                "entity",
                "recall",
                "specificity",
                "tp",
                "fn",
                "fp",
                "tn",
            },
        )

    def test_latency_table_markdown_runs_default_profile_only(self):
        """latency-table renders the per-payload table without optional models."""
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            status = main(
                [
                    "latency-table",
                    "--profile", "default",
                    "--iterations", "3",
                    "--format", "markdown",
                ]
            )
        body = stdout.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("# LSDF Latency Suite", body)
        self.assertIn("Payload matrix", body)
        self.assertIn("small_chat_turn", body)
        self.assertIn("rag_heavy_session", body)
        self.assertIn("p99", body)
        # Synthetic fixtures must NOT leak verbatim into the report. Cover all
        # four fixture families exercised by build_payload_matrix: bearer
        # (medium_with_rag), Azure SAS (large_assistant_reply), GitHub PAT and
        # Anthropic key (rag_heavy_session). A regression on any matching
        # recognizer would surface here.
        self.assertNotIn("LSDFFIXTUREbearer", body)
        self.assertNotIn("LSDFFIXTUREsig", body)
        self.assertNotIn("ghp_LSDFFIXTURE", body)
        self.assertNotIn("sk-ant-api03-LSDFFIXTURE", body)

    def test_latency_table_json_includes_per_case_percentiles(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            status = main(
                [
                    "latency-table",
                    "--profile", "default",
                    "--iterations", "3",
                    "--format", "json",
                ]
            )
        report = json.loads(stdout.getvalue())
        self.assertEqual(status, 0)
        profile = next(p for p in report["profiles"] if p["profile"] == "default")
        self.assertTrue(profile["available"])
        case_names = {case["name"] for case in profile["cases"]}
        self.assertEqual(
            case_names,
            {"small_chat_turn", "medium_with_rag", "large_assistant_reply", "rag_heavy_session"},
        )
        for case in profile["cases"]:
            self.assertIn("p50", case["latency_ms"])
            self.assertIn("p95", case["latency_ms"])
            self.assertIn("p99", case["latency_ms"])

    def test_latency_table_json_includes_streaming_per_chunk_percentiles(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            status = main(
                [
                    "latency-table",
                    "--profile", "default",
                    "--iterations", "3",
                    "--format", "json",
                ]
            )
        report = json.loads(stdout.getvalue())
        self.assertEqual(status, 0)
        # Top-level streaming-cases metadata
        self.assertIn("streaming_cases", report)
        stream_names = {entry["name"] for entry in report["streaming_cases"]}
        self.assertEqual(
            stream_names,
            {"short_assistant_stream", "long_assistant_stream", "leak_straddle_stream"},
        )
        # Per-profile streaming-cases block with measured percentiles
        profile = next(p for p in report["profiles"] if p["profile"] == "default")
        self.assertIn("streaming_cases", profile)
        for case in profile["streaming_cases"]:
            self.assertGreater(case["chunks_per_iteration"], 0)
            for key in ("p50", "p95", "p99", "max"):
                self.assertIn(key, case["per_chunk_latency_ms"])
                self.assertIn(key, case["end_to_end_latency_ms"])
            # The per-chunk p50 should be measurably > 0 — if it is
            # zero, either timing failed or the chunks aren't reaching
            # the firewall.
            self.assertGreaterEqual(case["per_chunk_latency_ms"]["p50"], 0.0)

    def test_leak_straddle_stream_actually_crosses_holdback_boundary(self):
        # Reviewer fix: the prior leak_straddle_deltas built a 143-char
        # text well below the 512-char default holdback, so the buffer
        # never released mid-stream and the "boundary detection" claim
        # was vacuous. The reworked case prepends ~700 chars of filler
        # so the buffer crosses the holdback before the secret arrives.
        from lsdf.latency_suite import _leak_straddle_deltas
        from lsdf.streaming import DEFAULT_STREAM_HOLDBACK_CHARS

        chunks = _leak_straddle_deltas()
        total_chars = sum(len(c) for c in chunks)
        # Must be substantially longer than the holdback so the
        # boundary is actually crossed mid-stream.
        self.assertGreater(
            total_chars,
            DEFAULT_STREAM_HOLDBACK_CHARS,
            "leak_straddle_stream must exceed the holdback to exercise "
            "the cross-boundary detection path",
        )
        # The Stripe-shape secret must appear AFTER the holdback bytes
        # so it actually straddles or follows the release boundary.
        text = "".join(chunks)
        secret_index = text.find("sk_live_LSDFFIXTUREaaaa")
        self.assertGreaterEqual(secret_index, 0)
        self.assertGreater(
            secret_index,
            DEFAULT_STREAM_HOLDBACK_CHARS // 2,
            "secret must arrive deep into the stream so the buffer has "
            "already begun releasing prefix bytes when it lands",
        )

    def test_latency_table_markdown_includes_streaming_section(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            status = main(
                [
                    "latency-table",
                    "--profile", "default",
                    "--iterations", "3",
                    "--format", "markdown",
                ]
            )
        body = stdout.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("Streaming per-chunk inspection", body)
        self.assertIn("short_assistant_stream", body)
        self.assertIn("long_assistant_stream", body)
        self.assertIn("leak_straddle_stream", body)

    def test_latency_table_marks_unknown_profile_unavailable(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            status = main(
                [
                    "latency-table",
                    "--profile", "default",
                    "--profile", "this-profile-does-not-exist",
                    "--iterations", "2",
                    "--format", "json",
                ]
            )
        self.assertEqual(status, 0)
        report = json.loads(stdout.getvalue())
        bad = next(p for p in report["profiles"] if p["profile"] == "this-profile-does-not-exist")
        self.assertFalse(bad["available"])
        self.assertIn("error", bad)

    def test_release_eval_ratio_helper(self):
        """Unit-test the signal/noise math directly so coverage isn't only via CLI."""
        from lsdf.release_eval import _ratio

        self.assertEqual(_ratio(0, 0), "n/a")
        self.assertEqual(_ratio(36, 0), "∞ (no benign findings)")
        self.assertEqual(_ratio(0, 5), "0.0:1")
        self.assertEqual(_ratio(36, 4), "9.0:1")
        self.assertEqual(_ratio(1, 2), "0.5:1")

    def test_quickstart_json_examples_are_valid(self):
        for path in Path("examples/quickstart").glob("*.json"):
            with self.subTest(path=path):
                json.loads(path.read_text(encoding="utf-8"))

    def test_new_developer_docs_stay_docker_only(self):
        for path in (
            Path("README.md"),
            Path("docs/container-workflow.md"),
            Path("docs/detector-composition.md"),
            Path("docs/integration-recipes.md"),
            Path("docs/production-operations.md"),
            Path("docs/security-model.md"),
            Path("docs/compatibility-matrix.md"),
            Path("docs/provider-playbook.md"),
            Path("docs/policy-cookbook.md"),
            Path("examples/quickstart/README.md"),
            Path("examples/integrations/end_to_end_flow.md"),
        ):
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path):
                self.assertNotIn("pip install", text)
                self.assertNotIn("PYTHONPATH=src", text)
                self.assertNotIn("python3 -m lsdf", text)
                self.assertIn("docker compose", text)


def _write_eval_dataset() -> Path:
    tmpdir = TemporaryDirectory()
    path = Path(tmpdir.name, "dataset.json")
    path.write_text(
        json.dumps(
            {
                "name": "cli_eval",
                "cases": [
                    {
                        "id": "cli-secret",
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
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    _TEMP_DIRS.append(tmpdir)
    return path


def _write_json_payload(payload) -> Path:
    tmpdir = TemporaryDirectory()
    path = Path(tmpdir.name, "payload.json")
    path.write_text(json.dumps(payload), encoding="utf-8")
    _TEMP_DIRS.append(tmpdir)
    return path


_TEMP_DIRS = []


if __name__ == "__main__":
    unittest.main()
