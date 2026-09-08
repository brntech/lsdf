import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from lsdf.engine import Firewall
from lsdf.observability import sanitize_observability
from lsdf.policy import AuditConfig, Policy, Rule
from lsdf.types import Finding, PolicyEnforcementError
from lsdf.vault import EncryptedSqliteTokenVault, generate_vault_key


class ExactTraceScanner:
    def scan(self, surface):
        if surface.value not in ("alpha", "123"):
            return []
        return [Finding("US_SSN", surface.name, surface.pointer, 0, len(surface.value), surface.value, 1.0)]


def trace_policy(action="tokenize", on_fail=None, mode="redact"):
    return Policy(
        version="0.2", name="trace-enforcement", mode=mode,
        entities={"US_SSN"}, surfaces={"logs.traces"},
        rules=[Rule("trace-rule", {"entity": "US_SSN"}, action, on_fail=on_fail)],
        audit=AuditConfig(),
    )


class ObservabilityEnforcementTests(unittest.TestCase):
    def test_exception_halts_root_and_nested_traces_before_transform(self):
        firewall = Firewall(trace_policy(on_fail="exception", mode="monitor"), scanner=ExactTraceScanner())
        for payload in ("alpha", {"value": "alpha"}):
            with self.subTest(root=isinstance(payload, str)), self.assertRaises(PolicyEnforcementError):
                sanitize_observability(payload, firewall)

    def test_root_and_nested_scalar_tokens_use_encrypted_vault(self):
        with TemporaryDirectory() as scratch:
            vault = EncryptedSqliteTokenVault(Path(scratch, "vault.sqlite"), generate_vault_key())
            firewall = Firewall(trace_policy(), scanner=ExactTraceScanner(), token_vault=vault)
            for value in ("alpha", 123):
                for nested in (False, True):
                    with self.subTest(value_type=type(value).__name__, nested=nested):
                        result = sanitize_observability({"value": value} if nested else value, firewall)
                        token = result.transformed_payload["value"] if nested else result.transformed_payload
                        self.assertEqual(vault.resolve(token), str(value))
                        self.assertNotIn(str(value), json.dumps(result.audit_event))

    def test_monitor_mode_does_not_create_vault_tokens(self):
        with TemporaryDirectory() as scratch:
            vault = EncryptedSqliteTokenVault(Path(scratch, "vault.sqlite"), generate_vault_key())
            firewall = Firewall(trace_policy(mode="monitor"), scanner=ExactTraceScanner(), token_vault=vault)
            result = sanitize_observability("alpha", firewall)
            self.assertEqual(result.transformed_payload, "alpha")
            self.assertEqual(vault.status()["token_count"], 0)
