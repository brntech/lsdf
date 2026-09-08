import io
import importlib.util
import json
import os
import sqlite3
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from lsdf import Firewall, load_policy
from lsdf.cli import main
from lsdf.demo_runner import run_demo
from lsdf.gateway import GatewayConfig, LSDFGatewayHandler
from lsdf.metrics import MetricsRecorder
from lsdf.security_ops import (
    generate_policy_keypair,
    sign_policy_file,
    verify_policy_signature,
)
from lsdf.vault import EncryptedSqliteTokenVault, generate_vault_key


class ManagementEndpointTests(unittest.TestCase):
    def test_management_token_protects_health_and_metrics(self):
        upstream = _start_server(_safe_upstream_handler())

        class Handler(LSDFGatewayHandler):
            gateway_config = GatewayConfig(
                policy_path=None,
                policy_profile="default",
                upstream_base_url=_server_url(upstream),
                management_token="secret-token",
            )
            gateway_firewall = Firewall(load_policy("policies/default.yaml"))
            gateway_metrics = MetricsRecorder(enabled=True)

        gateway = _start_server(Handler)
        url = _server_url(gateway)
        try:
            with self.assertRaises(urllib.error.HTTPError) as missing:
                urllib.request.urlopen(f"{url}/lsdf/health", timeout=5)
            request = urllib.request.Request(
                f"{url}/lsdf/health",
                headers={"X-LSDF-Management-Token": "secret-token"},
            )
            health = json.loads(urllib.request.urlopen(request, timeout=5).read())
        finally:
            gateway.shutdown()
            gateway.server_close()
            upstream.shutdown()
            upstream.server_close()

        self.assertEqual(missing.exception.code, 401)
        self.assertTrue(health["management"]["auth_required"])

    def test_management_can_be_disabled_without_affecting_chat_proxy(self):
        upstream = _start_server(_safe_upstream_handler())

        class Handler(LSDFGatewayHandler):
            gateway_config = GatewayConfig(
                policy_path=None,
                policy_profile="default",
                upstream_base_url=_server_url(upstream),
                management_enabled=False,
            )
            gateway_firewall = Firewall(load_policy("policies/default.yaml"))

        gateway = _start_server(Handler)
        url = _server_url(gateway)
        try:
            with self.assertRaises(urllib.error.HTTPError) as missing:
                urllib.request.urlopen(f"{url}/lsdf/metrics", timeout=5)
            request = urllib.request.Request(
                f"{url}/v1/chat/completions",
                data=json.dumps({"messages": [{"role": "user", "content": "hello"}]}).encode("utf-8"),
                headers={"content-type": "application/json"},
                method="POST",
            )
            response = json.loads(urllib.request.urlopen(request, timeout=5).read())
        finally:
            gateway.shutdown()
            gateway.server_close()
            upstream.shutdown()
            upstream.server_close()

        self.assertEqual(missing.exception.code, 404)
        self.assertEqual(response["choices"][0]["message"]["content"], "ok")


class FirstRunCliTests(unittest.TestCase):
    def test_smoke_accepts_gateway_base_url_and_legacy_alias(self):
        gateway = _start_server(_management_handler())
        url = _server_url(gateway)
        try:
            for flag in ("--gateway-base-url", "--upstream-base-url"):
                with self.subTest(flag=flag):
                    stdout = io.StringIO()
                    with redirect_stdout(stdout):
                        status = main(["smoke", flag, url, "--format", "json"])
                    self.assertEqual(status, 0)
                    self.assertEqual(json.loads(stdout.getvalue())["gateway_base_url"], url)
        finally:
            gateway.shutdown()
            gateway.server_close()

    def test_quickstart_report_summarizes_gateway_audit_and_metrics(self):
        gateway = _start_server(_management_handler())
        url = _server_url(gateway)
        with TemporaryDirectory() as tmpdir:
            audit = Path(tmpdir, "audit.jsonl")
            metrics = Path(tmpdir, "metrics.jsonl")
            audit.write_text('{"stage":"request_preflight","blocked":false}\n', encoding="utf-8")
            metrics.write_text('{"type":"counter","name":"gateway_requests_total","labels":{}}\n', encoding="utf-8")
            try:
                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    status = main(
                        [
                            "quickstart-report",
                            "--gateway-base-url",
                            url,
                            "--audit-jsonl-path",
                            str(audit),
                            "--metrics-jsonl-path",
                            str(metrics),
                            "--format",
                            "markdown",
                        ]
                    )
            finally:
                gateway.shutdown()
                gateway.server_close()

        output = stdout.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("# LSDF Quickstart Report", output)
        self.assertNotIn("api_LSDF_FIXTURE_TOKEN_000000", output)

    def test_demo_runner_reports_golden_path_without_raw_values(self):
        gateway = _start_server(_demo_gateway_handler())
        url = _server_url(gateway)
        with TemporaryDirectory() as tmpdir:
            audit = Path(tmpdir, "audit.jsonl")
            metrics = Path(tmpdir, "metrics.jsonl")
            audit.write_text('{"stage":"request_preflight","blocked":false}\n', encoding="utf-8")
            metrics.write_text('{"type":"counter","name":"gateway_requests_total","labels":{}}\n', encoding="utf-8")
            try:
                report = run_demo(
                    gateway_base_url=url,
                    audit_jsonl_path=audit,
                    metrics_jsonl_path=metrics,
                )
            finally:
                gateway.shutdown()
                gateway.server_close()

        self.assertEqual(report["status"], "ok")
        self.assertNotIn("api_LSDF_FIXTURE_TOKEN_000000", json.dumps(report))

    def test_adoption_init_presets_and_demo_script(self):
        with TemporaryDirectory() as tmpdir:
            openrouter_env = Path(tmpdir, "openrouter.env")
            litellm_env = Path(tmpdir, "litellm.env")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                openrouter_status = main(
                    ["init", "--upstream", "openrouter", "--output", str(openrouter_env)]
                )
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                overwrite_status = main(
                    ["init", "--upstream", "openrouter", "--output", str(openrouter_env)]
                )
            with redirect_stdout(io.StringIO()):
                litellm_status = main(
                    ["init", "--upstream", "litellm", "--output", str(litellm_env)]
                )
            script_stdout = io.StringIO()
            with redirect_stdout(script_stdout):
                script_status = main(["demo-script", "--format", "markdown"])
            openrouter_content = openrouter_env.read_text(encoding="utf-8")
            litellm_content = litellm_env.read_text(encoding="utf-8")

        self.assertEqual(openrouter_status, 0)
        self.assertEqual(overwrite_status, 2)
        self.assertEqual(litellm_status, 0)
        self.assertEqual(script_status, 0)
        self.assertIn("LSDF_UPSTREAM_BASE_URL=https://openrouter.ai/api/v1", openrouter_content)
        self.assertIn("LSDF_UPSTREAM_BASE_URL=http://host.docker.internal:4000", litellm_content)
        self.assertIn("# LSDF_UPSTREAM_API_KEY=${LSDF_UPSTREAM_API_KEY}", openrouter_content)
        self.assertNotIn("sk-", openrouter_content)
        self.assertIn("already exists", stderr.getvalue())
        self.assertIn("# LSDF Golden Demo Script", script_stdout.getvalue())

    def test_policy_explain_outputs_safe_shapes(self):
        for output_format in ("text", "json", "markdown"):
            with self.subTest(output_format=output_format):
                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    status = main(
                        [
                            "policy",
                            "explain",
                            "policies/default.yaml",
                            "--format",
                            output_format,
                        ]
                    )
                output = stdout.getvalue()
                self.assertEqual(status, 0)
                self.assertIn("default", output)
                self.assertIn("require_approval", output)
                self.assertNotIn("api_LSDF_FIXTURE_TOKEN_000000", output)


class GovernanceAndVaultTests(unittest.TestCase):
    def test_ed25519_policy_sign_verify_and_tamper_failure(self):
        with TemporaryDirectory() as tmpdir:
            public_key = Path(tmpdir, "policy.pub")
            private_key = Path(tmpdir, "policy.key")
            signature = Path(tmpdir, "default.sig")
            tampered = Path(tmpdir, "tampered.yaml")
            generate_policy_keypair(public_key, private_key)
            sign_report = sign_policy_file(Path("policies/default.yaml"), signature, private_key)
            verify_report = verify_policy_signature(Path("policies/default.yaml"), signature, public_key)
            tampered.write_text(Path("policies/default.yaml").read_text(encoding="utf-8") + "\n", encoding="utf-8")
            tampered_report = verify_policy_signature(tampered, signature, public_key)

        self.assertTrue(sign_report["signed"])
        self.assertFalse(sign_report["legacy"])
        self.assertTrue(verify_report["valid"])
        self.assertFalse(tampered_report["valid"])

    def test_legacy_policy_signature_still_verifies_with_marker(self):
        with TemporaryDirectory() as tmpdir:
            signature = Path(tmpdir, "legacy.sig")
            sign_policy_file(Path("policies/default.yaml"), signature)
            verify_report = verify_policy_signature(Path("policies/default.yaml"), signature)

        self.assertTrue(verify_report["valid"])
        self.assertTrue(verify_report["legacy"])

    def test_policy_cli_keygen_sign_verify(self):
        with TemporaryDirectory() as tmpdir:
            public_key = Path(tmpdir, "policy.pub")
            private_key = Path(tmpdir, "policy.key")
            signature = Path(tmpdir, "default.sig")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                key_status = main(["policy", "keygen", "--public-key", str(public_key), "--private-key", str(private_key)])
            with redirect_stdout(io.StringIO()):
                sign_status = main(["policy", "sign", "policies/default.yaml", "--private-key", str(private_key), "--output", str(signature)])
            verify_stdout = io.StringIO()
            with redirect_stdout(verify_stdout):
                verify_status = main(["policy", "verify", "policies/default.yaml", "--signature", str(signature), "--public-key", str(public_key)])

        self.assertEqual(key_status, 0)
        self.assertEqual(sign_status, 0)
        self.assertEqual(verify_status, 0)
        self.assertTrue(json.loads(verify_stdout.getvalue())["valid"])

    def test_vault_backup_check_and_rotate_key(self):
        raw = "000-00-0000"
        with TemporaryDirectory() as tmpdir:
            source = Path(tmpdir, "vault.sqlite")
            backup = Path(tmpdir, "vault.backup.sqlite")
            rotated = Path(tmpdir, "vault.rotated.sqlite")
            old_key = generate_vault_key()
            new_key = generate_vault_key()
            token = EncryptedSqliteTokenVault(source, old_key).tokenize(raw, entity="US_SSN")
            env = {"OLD": old_key, "NEW": new_key}
            with redirect_stdout(io.StringIO()):
                check_status = main(["vault", "check", "--vault-path", str(source)])
            with redirect_stdout(io.StringIO()):
                backup_status = main(["vault", "backup", "--vault-path", str(source), "--output", str(backup)])
            with patch.dict(os.environ, env, clear=True), redirect_stdout(io.StringIO()):
                rotate_status = main(
                    [
                        "vault",
                        "rotate-key",
                        "--vault-path",
                        str(source),
                        "--old-key-env",
                        "OLD",
                        "--new-key-env",
                        "NEW",
                        "--output",
                        str(rotated),
                    ]
                )
            resolved = EncryptedSqliteTokenVault(rotated, new_key).resolve(token)
            with self.assertRaises(ValueError):
                EncryptedSqliteTokenVault(rotated, old_key).resolve(token)
            backup_blob = backup.read_bytes()

        self.assertEqual(check_status, 0)
        self.assertEqual(backup_status, 0)
        self.assertEqual(rotate_status, 0)
        self.assertEqual(resolved, raw)
        self.assertNotIn(raw.encode("utf-8"), backup_blob)

    def test_vault_check_reports_corrupt_file_safely(self):
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir, "vault.sqlite")
            sqlite3.connect(path).close()
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                status = main(["vault", "check", "--vault-path", str(path)])

        self.assertEqual(status, 1)
        self.assertFalse(json.loads(stdout.getvalue())["valid"])


class ProofBundleTests(unittest.TestCase):
    def test_proof_bundle_writes_safe_bundle(self):
        with TemporaryDirectory() as tmpdir:
            output = Path(tmpdir, "bundle")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                status = main(["proof-bundle", "--output", str(output), "--format", "json"])
            report = json.loads(stdout.getvalue())
            manifest_exists = (output / "manifest.json").exists()
            readme_exists = (output / "README.md").exists()

        self.assertEqual(status, 0)
        self.assertTrue(manifest_exists)
        self.assertTrue(readme_exists)
        self.assertIn("known_gap_cases", report)
        self.assertNotIn("api_LSDF_FIXTURE_TOKEN_000000", json.dumps(report))

    def test_adoption_docs_and_samples_are_safe(self):
        docs = [
            Path("docs/policy-cookbook.md"),
            Path("docs/provider-playbook.md"),
            Path("docs/operational-rollout-guide.md"),
            Path("examples/demo-media/golden-demo-transcript.md"),
            Path("examples/demo-media/golden-demo.captured.txt"),
            Path("examples/demo-media/golden-demo.cast"),
            Path("examples/integrations/litellm_proxy/README.md"),
            Path("CHANGELOG.md"),
        ]
        for path in docs:
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path):
                self.assertNotIn("pip install", text)
                # PYTHONPATH=src and python3 -m lsdf only apply to docs that
                # promote a manual quickstart; the captured demo artifacts
                # legitimately reference `python3 -m lsdf.cast_recorder` as
                # the regen command, so we exempt them from those checks.
                if path.name not in {"golden-demo.captured.txt", "golden-demo.cast"}:
                    self.assertNotIn("PYTHONPATH=src", text)
                    self.assertNotIn("python3 -m lsdf", text)
                self.assertNotIn("api_LSDF_FIXTURE_TOKEN_000000", text)
                self.assertNotIn("000-00-0000", text)
                self.assertNotIn("LSDF-FIXTURE-00001", text)
        for path in (
            Path("docs/policy-cookbook.md"),
            Path("docs/provider-playbook.md"),
            Path("docs/operational-rollout-guide.md"),
            Path("examples/demo-media/golden-demo-transcript.md"),
            Path("examples/integrations/litellm_proxy/README.md"),
        ):
            self.assertIn("docker compose", path.read_text(encoding="utf-8"))

        recipes = Path("docs/integration-recipes.md").read_text(encoding="utf-8")
        self.assertIn("http://localhost:8080/v1", recipes)
        self.assertIn("https://openrouter.ai/api/v1", recipes)
        self.assertIn("--profile litellm-demo", recipes)
        self.assertIn("http://host.docker.internal:4000", Path("examples/env/litellm.lsdf.env").read_text(encoding="utf-8"))
        self.assertIn("https://openrouter.ai/api/v1", Path("examples/env/openrouter.lsdf.env").read_text(encoding="utf-8"))

    def test_sample_proof_bundle_is_present_parseable_and_safe(self):
        root = Path("examples/proof-bundle-sample")
        expected = [
            "manifest.json",
            "policy-summary.json",
            "protection-report.json",
            "security-report.json",
            "audit-schema.json",
            "README.md",
        ]
        for name in expected:
            with self.subTest(name=name):
                self.assertTrue((root / name).exists())
        for path in root.glob("*.json"):
            payload = json.loads(path.read_text(encoding="utf-8"))
            text = json.dumps(payload)
            with self.subTest(path=path):
                self.assertNotIn("api_LSDF_FIXTURE_TOKEN_000000", text)
                self.assertNotIn("000-00-0000", text)
                self.assertNotIn("LSDF-FIXTURE-00001", text)
        audit_schema = json.loads((root / "audit-schema.json").read_text(encoding="utf-8"))
        self.assertEqual(audit_schema["event_shape"]["scope"], "span|surface on each decision")
        self.assertEqual(
            audit_schema["event_shape"]["scope_escalated"],
            "boolean on each decision",
        )

    def test_runnable_observability_and_litellm_proxy_examples_are_safe(self):
        module = _load_runnable_examples_module()
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            status = module.main(["--scenario", "observability"])
        output = stdout.getvalue()

        self.assertEqual(status, 0)
        self.assertIn("<US_SSN:REDACTED>", output)
        self.assertNotIn("000-00-0000", output)
        self.assertNotIn("api_LSDF_FIXTURE_TOKEN_000000", output)
        self.assertEqual(module._scenario_payload("litellm-proxy")["model"], "local-model")
        self.assertTrue(module._scenario_payload("litellm-proxy")["stream"])

    def test_litellm_demo_compose_profile_is_wired(self):
        import yaml

        compose = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))
        services = compose["services"]
        self.assertIn("litellm-proxy-demo", services)
        self.assertIn("litellm-demo-gateway", services)
        self.assertIn("litellm-demo-runner", services)
        self.assertIn("litellm-demo", services["litellm-demo-runner"]["profiles"])
        self.assertEqual(
            services["litellm-demo-gateway"]["environment"]["LSDF_UPSTREAM_BASE_URL"],
            "http://litellm-proxy-demo:4000",
        )

    def test_gateway_ml_compose_profile_is_optional_and_uses_privacy_ml(self):
        import yaml

        compose = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))
        dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
        gateway = compose["services"]["gateway"]
        gateway_ml = compose["services"]["gateway-ml"]
        optional_test = compose["services"]["optional-test"]

        self.assertEqual(gateway["build"]["target"], "base")
        self.assertEqual(gateway["environment"]["LSDF_PROFILE"], "${LSDF_PROFILE:-default}")
        self.assertIn("optional", gateway_ml["profiles"])
        self.assertEqual(gateway_ml["build"]["target"], "optional-detectors")
        self.assertEqual(gateway_ml["environment"]["LSDF_PROFILE"], "${LSDF_PROFILE:-broad-pii-ml}")
        self.assertEqual(
            gateway_ml["environment"]["LSDF_OPENAI_PRIVACY_FILTER_MODEL"],
            "${LSDF_OPENAI_PRIVACY_FILTER_MODEL:-openai/privacy-filter}",
        )
        self.assertTrue(
            any("lsdf-hf-cache:/opt/lsdf-cache/huggingface" in volume for volume in gateway_ml["volumes"])
        )
        self.assertIn("https://download.pytorch.org/whl/cpu", dockerfile)
        self.assertIn("presidio-analyzer==2.2.362", dockerfile)
        self.assertIn("transformers==4.51.0", dockerfile)
        self.assertIn("transformers==5.7.0", dockerfile)
        self.assertIn("gliner==0.2.22", dockerfile)
        self.assertIn("LSDF_OPENAI_PRIVACY_FILTER_PYTHON", dockerfile)
        self.assertIn("torch==2.11.0+cpu", dockerfile)
        self.assertEqual(
            optional_test["environment"]["LSDF_REQUIRE_OPENAI_PRIVACY_FILTER"],
            "${LSDF_REQUIRE_OPENAI_PRIVACY_FILTER:-}",
        )

    def test_measured_protection_and_detector_contract_docs_are_safe_and_specific(self):
        measured = Path("docs/measured-protection.md").read_text(encoding="utf-8")
        contract = Path("docs/detector-adapter-contract.md").read_text(encoding="utf-8")
        readme = Path("README.md").read_text(encoding="utf-8")

        self.assertIn("broad-pii-ml", measured)
        self.assertIn("The public corpora and reproducible artifacts above provide the recorded evaluation evidence.", measured)
        self.assertIn("not public proof of universal detection", measured)
        self.assertNotIn("stored credential-leak outputs", measured)
        self.assertIn("Arabic, Chinese, and Spanish", measured)
        self.assertIn("local-files-only model loading", measured)
        self.assertIn("detector-unavailable diagnostic", readme)
        self.assertIn("OpenAI privacy-filter is the bundled optional ML reference adapter", contract)
        self.assertIn("bounded holdback window", contract)
        self.assertIn("broad-pii", readme)
        self.assertIn("OpenAI privacy-filter", readme)
        for text in (measured, contract, readme):
            self.assertNotIn("api_LSDF_FIXTURE_TOKEN_000000", text)
            self.assertNotRegex(text, r"\b" + "Piece" + r"\s*[AB]\b")
            self.assertNotIn("Broad" + "LM", text)

    def test_healthcare_limit_language_is_publicly_documented(self):
        combined = "\n".join(
            Path(path).read_text(encoding="utf-8")
            for path in (
                "README.md",
                "docs/measured-protection.md",
                "docs/policy-cookbook.md",
                "docs/security-model.md",
            )
        )

        self.assertIn("not full HIPAA de-identification", combined)
        self.assertIn("lightweight pattern", combined)
        self.assertIn("medical NER", combined)

    def test_proxy_demo_deduplicates_openai_style_v1_upstream_base(self):
        from lsdf.openai_proxy_demo import _join_openai_url

        self.assertEqual(
            _join_openai_url("https://example.test/api/v1", "/v1/chat/completions"),
            "https://example.test/api/v1/chat/completions",
        )
        self.assertEqual(
            _join_openai_url("http://demo-upstream:8091", "/v1/chat/completions"),
            "http://demo-upstream:8091/v1/chat/completions",
        )

    def test_proxy_demo_forwards_sse_streams(self):
        from lsdf.openai_proxy_demo import OpenAIProxyDemoHandler

        upstream = _start_server(_streaming_proxy_upstream_handler())

        class ProxyHandler(OpenAIProxyDemoHandler):
            upstream_base_url = _server_url(upstream)

        proxy = _start_server(ProxyHandler)
        try:
            request = urllib.request.Request(
                f"{_server_url(proxy)}/v1/chat/completions",
                data=json.dumps(
                    {
                        "model": "local-model",
                        "stream": True,
                        "messages": [{"role": "user", "content": "hello"}],
                    }
                ).encode("utf-8"),
                headers={"content-type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                content_type = response.headers.get("content-type", "")
                body = response.read().decode("utf-8")
        finally:
            proxy.shutdown()
            proxy.server_close()
            upstream.shutdown()
            upstream.server_close()

        self.assertIn("text/event-stream", content_type)
        self.assertIn("data: ", body)
        self.assertIn("[DONE]", body)


def _start_server(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _server_url(server):
    host, port = server.server_address
    return f"http://{host}:{port}"


def _load_runnable_examples_module():
    path = Path("examples/integrations/runnable_client_examples.py")
    spec = importlib.util.spec_from_file_location("runnable_client_examples_under_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _safe_upstream_handler():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self._send_json({"status": "ok"})

        def do_POST(self):
            self._send_json({"choices": [{"message": {"content": "ok"}}]})

        def _send_json(self, payload):
            body = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            return

    return Handler


def _streaming_proxy_upstream_handler():
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.send_header("cache-control", "no-cache")
            self.end_headers()
            self.wfile.write(
                b'data: {"choices":[{"index":0,"delta":{"content":"hello"}}]}\n\n'
            )
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()

        def log_message(self, format, *args):
            return

    return Handler


def _management_handler():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.end_headers()
            if self.path.startswith("/lsdf/metrics"):
                self.wfile.write(b"lsdf_gateway_requests_total 1\n")
            else:
                self.wfile.write(b'{"status":"ok"}')

        def log_message(self, format, *args):
            return

    return Handler


def _demo_gateway_handler():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.end_headers()
            if self.path.startswith("/lsdf/metrics"):
                self.wfile.write(b"lsdf_gateway_requests_total 1\n")
            else:
                self.wfile.write(b'{"status":"ok"}')

        def do_POST(self):
            length = int(self.headers.get("content-length", "0"))
            payload = json.loads(self.rfile.read(length))
            text = json.dumps(payload).lower()
            if "billing system" in text:
                self._send(403, b'{"error":{"type":"sensitive_data_blocked"}}')
            elif payload.get("stream") and "tool-call" in text:
                self._send(200, b'event: error\ndata: {"error":{"type":"sensitive_data_blocked"}}\n\n')
            elif payload.get("stream"):
                self._send(200, b'data: {"choices":[{"delta":{"content":"<API_KEY:REDACTED>"}}]}\n\ndata: [DONE]\n\n')
            else:
                self._send(200, b'{"choices":[{"message":{"content":"<MRN:REDACTED>"}}]}')

        def _send(self, status, body):
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            return

    return Handler


if __name__ == "__main__":
    unittest.main()
