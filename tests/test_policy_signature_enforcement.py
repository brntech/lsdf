import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from lsdf.cli import main
from lsdf.gateway import GatewayConfig, GatewayConfigError, serve_gateway
from lsdf.security_ops import generate_policy_keypair, sign_policy_file, verify_policy_signature


class PolicySignatureEnforcementTests(unittest.TestCase):
    def setUp(self):
        self.scratch = TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.policy = Path(self.scratch.name, "policy.yaml")
        self.policy.write_text("version: 0.2\nname: signed-policy\naction:\n  mode: redact\n  rules: []\n", encoding="utf-8")
        self.signature = self.policy.with_suffix(".yaml.sig")
        self.public_key = Path(self.scratch.name, "public.pem")
        self.private_key = Path(self.scratch.name, "private.pem")
        generate_policy_keypair(self.public_key, self.private_key)

    def config(self, public_key=True):
        return GatewayConfig(
            policy_path=str(self.policy), policy_profile="default",
            upstream_base_url="http://127.0.0.1:1", require_policy_signature=True,
            policy_public_key=str(self.public_key) if public_key else None,
        )

    def test_required_gateway_accepts_valid_ed25519(self):
        sign_policy_file(self.policy, self.signature, self.private_key)
        with patch("lsdf.gateway.ThreadingHTTPServer") as server:
            serve_gateway(config=self.config())
            server.return_value.serve_forever.assert_called_once()

    def test_modified_policy_and_recomputed_legacy_hash_cannot_downgrade_gateway(self):
        sign_policy_file(self.policy, self.signature, self.private_key)
        self.policy.write_text(self.policy.read_text().replace("redact", "monitor"), encoding="utf-8")
        sign_policy_file(self.policy, self.signature)
        self.assertFalse(verify_policy_signature(self.policy, self.signature, self.public_key)["valid"])
        for public_key in (True, False):
            with self.subTest(public_key=public_key), patch("lsdf.gateway.ThreadingHTTPServer") as server:
                with self.assertRaises(GatewayConfigError):
                    serve_gateway(config=self.config(public_key))
                server.assert_not_called()

    def test_modern_signature_requires_key_and_rejects_tampering(self):
        sign_policy_file(self.policy, self.signature, self.private_key)
        with self.assertRaises(GatewayConfigError):
            serve_gateway(config=self.config(False))
        self.policy.write_text(self.policy.read_text().replace("redact", "monitor"), encoding="utf-8")
        self.assertFalse(verify_policy_signature(self.policy, self.signature, self.public_key)["valid"])

    def test_legacy_cli_migration_is_labeled_and_cannot_ignore_public_key(self):
        sign_policy_file(self.policy, self.signature)
        for extra, expected in (([], 0), (["--public-key", str(self.public_key)], 1)):
            with self.subTest(public_key=bool(extra)), redirect_stdout(io.StringIO()) as output:
                status = main(["policy", "verify", str(self.policy), *extra])
            report = json.loads(output.getvalue())
            self.assertEqual(status, expected)
            self.assertTrue(report["legacy"])
            self.assertEqual(report["algorithm"], "sha256")
            self.assertEqual(report["valid"], expected == 0)


    def test_gateway_loads_verified_snapshot_despite_path_swap_after_verification(self):
        sign_policy_file(self.policy, self.signature, self.private_key)

        def verify_then_swap(*args, **kwargs):
            report = verify_policy_signature(*args, **kwargs)
            self.policy.write_text(self.policy.read_text().replace("redact", "monitor"), encoding="utf-8")
            return report

        with patch("lsdf.gateway.verify_policy_signature", side_effect=verify_then_swap):
            with patch("lsdf.gateway.ThreadingHTTPServer") as server:
                serve_gateway(config=self.config())
                handler = server.call_args.args[1]
                self.assertEqual(handler.gateway_firewall.policy.mode, "redact")
        self.assertIn("monitor", self.policy.read_text())

    def test_verifier_hashes_and_verifies_same_snapshot_during_path_swap(self):
        import hashlib
        snapshot = self.policy.read_bytes()
        sign_policy_file(self.policy, self.signature, self.private_key)
        read_bytes = Path.read_bytes

        def swap_while_loading_key(path):
            if path == self.public_key:
                self.policy.write_bytes(snapshot.replace(b"redact", b"monitor"))
            return read_bytes(path)

        with patch.object(Path, "read_bytes", swap_while_loading_key):
            report = verify_policy_signature(self.policy, self.signature, self.public_key)
        self.assertTrue(report["valid"])
        self.assertEqual(report["sha256"], hashlib.sha256(snapshot).hexdigest())
        self.assertFalse(verify_policy_signature(self.policy, self.signature, self.public_key)["valid"])

    def test_signer_validates_hashes_and_signs_same_snapshot(self):
        import hashlib
        from lsdf.policy import load_policy_bytes

        snapshot = self.policy.read_bytes()

        def parse_then_swap(payload):
            policy = load_policy_bytes(payload)
            self.policy.write_bytes(snapshot.replace(b"redact", b"monitor"))
            return policy

        for private_key in (None, self.private_key):
            with self.subTest(legacy=private_key is None):
                self.policy.write_bytes(snapshot)
                with patch("lsdf.security_ops.load_policy_bytes", side_effect=parse_then_swap):
                    report = sign_policy_file(self.policy, self.signature, private_key)
                public_key = self.public_key if private_key else None
                self.assertEqual(report["sha256"], hashlib.sha256(snapshot).hexdigest())
                self.assertTrue(verify_policy_signature(self.policy, self.signature, public_key, policy_bytes=snapshot)["valid"])
                self.assertFalse(verify_policy_signature(self.policy, self.signature, public_key)["valid"])
