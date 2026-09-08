import io
import json
import os
import sqlite3
import threading
import unittest
import urllib.request
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from lsdf import Firewall, load_effective_policy, load_policy
from lsdf.audit import JsonlAuditSink
from lsdf.cli import main
from lsdf.gateway import GatewayConfig, LSDFGatewayHandler, handle_chat_completion, resolve_gateway_config
from lsdf.metrics import MetricsRecorder, summarize_metrics_jsonl
from lsdf.security_ops import sign_policy_file, verify_policy_signature
from lsdf.vault import EncryptedSqliteTokenVault, generate_vault_key, vault_status


class MetricsAndHealthTests(unittest.TestCase):
    def test_metrics_recorder_jsonl_and_summary_are_raw_value_safe(self):
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir, "metrics.jsonl")
            recorder = MetricsRecorder(enabled=True, jsonl_path=path)
            recorder.increment("inspection_action_total", action="redact", entity="API_KEY")
            recorder.observe_ms("request_inspection_ms", 1.5, stage="request_preflight")

            text = path.read_text(encoding="utf-8")
            summary = summarize_metrics_jsonl(path)

        self.assertNotIn("api_LSDF_FIXTURE_TOKEN_000000", text)
        self.assertEqual(summary["event_count"], 2)
        self.assertEqual(summary["by_name"]["inspection_action_total"], 1)
        self.assertIn("request_inspection_ms", summary["duration_ms"])

    def test_gateway_metrics_endpoint_returns_prometheus_and_json(self):
        metrics = MetricsRecorder(enabled=True)
        metrics.increment("gateway_requests_total", stream=False)
        upstream = _start_server(_health_upstream_handler())
        upstream_url = _server_url(upstream)

        class Handler(LSDFGatewayHandler):
            gateway_config = GatewayConfig(
                policy_path=None,
                policy_profile="default",
                upstream_base_url=upstream_url,
                metrics_enabled=True,
            )
            gateway_firewall = Firewall(load_policy("policies/default.yaml"))
            gateway_metrics = metrics

        gateway = _start_server(Handler)
        gateway_url = _server_url(gateway)
        try:
            metrics_text = urllib.request.urlopen(f"{gateway_url}/lsdf/metrics", timeout=5).read().decode("utf-8")
            health = json.loads(urllib.request.urlopen(f"{gateway_url}/lsdf/health", timeout=5).read())
            metrics_json = json.loads(urllib.request.urlopen(f"{gateway_url}/lsdf/metrics?format=json", timeout=5).read())
        finally:
            gateway.shutdown()
            gateway.server_close()
            upstream.shutdown()
            upstream.server_close()

        self.assertIn("lsdf_gateway_requests_total", metrics_text)
        self.assertEqual(health["status"], "ok")
        self.assertTrue(health["metrics"]["enabled"])
        self.assertIn("gateway_requests_total{stream=False}", metrics_json["counters"])

    def test_metrics_cli_summary_outputs_json(self):
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir, "metrics.jsonl")
            MetricsRecorder(enabled=True, jsonl_path=path).increment("gateway_requests_total")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                status = main(["metrics-summary", str(path), "--format", "json"])

        self.assertEqual(status, 0)
        self.assertEqual(json.loads(stdout.getvalue())["event_count"], 1)

    def test_smoke_cli_reports_gateway_health(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}' if self.path.startswith("/lsdf/health") else b"metric 1\n")

            def log_message(self, format, *args):
                return

        server = _start_server(Handler)
        try:
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                status = main(["smoke", "--upstream-base-url", _server_url(server), "--format", "json"])
        finally:
            server.shutdown()
            server.server_close()

        self.assertEqual(status, 0)
        self.assertEqual(json.loads(stdout.getvalue())["status"], "ok")


class VaultTests(unittest.TestCase):
    def test_vault_tokenization_encrypts_plaintext_and_resolves_with_key(self):
        raw = "000-00-0000"
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir, "vault.sqlite")
            key = generate_vault_key()
            vault = EncryptedSqliteTokenVault(path, key)
            token = vault.tokenize(raw, entity="US_SSN", metadata={"surface": "input.messages"})
            resolved = vault.resolve(token)
            blob = path.read_bytes()
            status = vault_status(path)

        self.assertRegex(token, r"^lsdf_tok_us_ssn_[0-9a-f]{20}$")
        self.assertEqual(resolved, raw)
        self.assertNotIn(raw.encode("utf-8"), blob)
        self.assertEqual(status["token_count"], 1)

    def test_firewall_uses_vault_tokens_when_configured(self):
        with TemporaryDirectory() as tmpdir:
            key = generate_vault_key()
            vault = EncryptedSqliteTokenVault(Path(tmpdir, "vault.sqlite"), key)
            firewall = Firewall(load_policy("policies/default.yaml"), token_vault=vault)
            result = firewall.inspect({"messages": [{"role": "user", "content": "SSN 000-00-0000"}]})
            token = result.transformed_payload["messages"][0]["content"].split()[-1]
            resolved = vault.resolve(token)

        self.assertTrue(token.startswith("lsdf_tok_us_ssn_"))
        self.assertEqual(resolved, "000-00-0000")

    def test_vault_cli_resolve_redacts_by_default_and_reveals_only_with_flag(self):
        raw = "000-00-0000"
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir, "vault.sqlite")
            key = generate_vault_key()
            token = EncryptedSqliteTokenVault(path, key).tokenize(raw, entity="US_SSN")
            env = {"LSDF_VAULT_KEY": key}
            stdout = io.StringIO()
            with patch.dict(os.environ, env, clear=True), redirect_stdout(stdout):
                status = main(["vault", "resolve", token, "--vault-path", str(path)])
            safe_output = stdout.getvalue()
            stdout = io.StringIO()
            with patch.dict(os.environ, env, clear=True), redirect_stdout(stdout):
                reveal_status = main([
                    "vault",
                    "resolve",
                    token,
                    "--vault-path",
                    str(path),
                    "--reveal-sensitive-value",
                ])

        self.assertEqual(status, 0)
        self.assertEqual(reveal_status, 0)
        self.assertNotIn(raw, safe_output)
        self.assertIn("[REDACTED len=11]", safe_output)
        self.assertEqual(stdout.getvalue().strip(), raw)


class SecurityAndPolicyTests(unittest.TestCase):
    def test_domain_pack_composition_changes_policy_name_and_rules(self):
        policy = load_effective_policy("default", domain_packs=["financial"])

        self.assertIn("financial", policy.name)
        self.assertIn("domain-financial-block-payment-dispatch", {rule.id for rule in policy.rules})

    def test_healthcare_profile_rejects_healthcare_domain_pack_double_apply(self):
        expected = (
            "Error: cannot compose --profile healthcare with --domain-pack healthcare\n"
            "  Both define rules under the `healthcare.*` namespace. Pick one:\n"
            "    --profile healthcare       (clinical defaults)\n"
            "    --profile broad-pii --domain-pack healthcare       (BYO base + pack overlay)"
        )

        with self.assertRaisesRegex(ValueError, "cannot compose --profile healthcare") as ctx:
            load_effective_policy("healthcare", domain_packs=["healthcare"])

        self.assertEqual(str(ctx.exception), expected)

    def test_resolve_gateway_config_reads_operations_env(self):
        config = resolve_gateway_config(
            upstream_base_url="http://gateway.example",
            environ={
                "LSDF_METRICS_ENABLED": "true",
                "LSDF_METRICS_JSONL_PATH": "metrics.jsonl",
                "LSDF_AUDIT_ROTATE_BYTES": "1024",
                "LSDF_DOMAIN_PACKS": "financial,enterprise-dlp",
                "LSDF_TOKENIZATION_MODE": "vault",
                "LSDF_VAULT_PATH": "vault.sqlite",
                "LSDF_VAULT_KEY": generate_vault_key(),
            },
        )

        self.assertTrue(config.metrics_enabled)
        self.assertEqual(config.metrics_jsonl_path, "metrics.jsonl")
        self.assertEqual(config.audit_rotate_bytes, 1024)
        self.assertEqual(config.domain_packs, ("financial", "enterprise-dlp"))
        self.assertEqual(config.tokenization_mode, "vault")

    def test_audit_rotation_preserves_valid_jsonl_lines(self):
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir, "audit.jsonl")
            sink = JsonlAuditSink(path, rotate_bytes=1, rotate_backups=2)
            sink.write({"stage": "one", "blocked": False})
            sink.write({"stage": "two", "blocked": False})
            lines = path.read_text(encoding="utf-8").splitlines()
            rotated = path.with_suffix(path.suffix + ".1")
            self.assertTrue(rotated.exists())
            self.assertTrue(all(json.loads(line) for line in lines))

    def test_policy_sign_and_verify(self):
        with TemporaryDirectory() as tmpdir:
            signature = Path(tmpdir, "default.sig")
            sign_report = sign_policy_file(Path("policies/default.yaml"), signature)
            verify_report = verify_policy_signature(Path("policies/default.yaml"), signature)

        self.assertTrue(sign_report["signed"])
        self.assertTrue(verify_report["valid"])

    def test_security_and_audit_export_cli_are_raw_value_safe(self):
        raw = "api_LSDF_FIXTURE_TOKEN_000000"
        with TemporaryDirectory() as tmpdir:
            audit_path = Path(tmpdir, "audit.jsonl")
            handle_chat_completion(
                {"messages": [{"role": "user", "content": f"Use {raw}"}]},
                Firewall(load_policy("policies/default.yaml")),
                lambda _payload: (200, {"content-type": "application/json"}, b"{}"),
                audit_sink=JsonlAuditSink(audit_path),
            )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                export_status = main(["audit-export", str(audit_path), "--target", "splunk"])
            export_output = stdout.getvalue()
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                report_status = main(["security-report", "--audit-jsonl-path", str(audit_path), "--format", "json"])
            report_output = stdout.getvalue()

        self.assertEqual(export_status, 0)
        self.assertEqual(report_status, 0)
        self.assertNotIn(raw, export_output)
        self.assertNotIn(raw, report_output)
        self.assertEqual(json.loads(export_output.splitlines()[0])["target"], "splunk")

    def test_simulate_policy_dataset_counts_known_gaps_without_raw_values(self):
        with TemporaryDirectory() as tmpdir:
            dataset = Path(tmpdir, "dataset.json")
            dataset.write_text(
                json.dumps(
                    {
                        "name": "known-gap-demo",
                        "cases": [
                            {
                                "id": "gap",
                                "known_gap": True,
                                "payload": {"choices": [{"message": {"content": "safe"}}]},
                                "expected_blocked": True,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                status = main(["simulate-policy", str(dataset), "--format", "json"])

        report = json.loads(stdout.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(report["failed"], 0)
        self.assertEqual(report["known_gap_would_fail"], 1)


def _start_server(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _server_url(server):
    host, port = server.server_address
    return f"http://{host}:{port}"


def _health_upstream_handler():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

        def log_message(self, format, *args):
            return

    return Handler


if __name__ == "__main__":
    unittest.main()
