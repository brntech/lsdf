"""Tests for the Presidio-parity operator vocabulary (`replace`, `hash`,
`encrypt`).

The bundled actions before this layer were `allow | warn | log | redact |
mask | tokenize | block`. This module adds three Presidio anonymizer-
engine parity operators with per-rule parameters validated at policy
load:

  - `replace`: replace the matched span with operator-supplied literal
  - `hash`: replace with `<{ENTITY}:HASH:<algo>=<hex16>>`
  - `encrypt`: Fernet-encrypted ciphertext via env-configured key

These tests pin parameter validation, transform output shape, and
the encrypt round-trip via the operator-controlled key.
"""

from __future__ import annotations

import os
import re
import unittest
from textwrap import dedent

from cryptography.fernet import Fernet

from lsdf.policy import VALID_ACTIONS, VALID_HASH_ALGOS
from lsdf.transforms import TRANSFORMING_ACTIONS, _replacement
from lsdf.types import Finding, PolicyDecision


def _finding(value: str = "Hunter22!!", entity: str = "OTHER_SECRET") -> Finding:
    return Finding(
        entity=entity,
        surface="output.content",
        pointer=(),
        start=0,
        end=len(value),
        value=value,
        confidence=1.0,
    )


def _decision(action: str, **kwargs) -> PolicyDecision:
    finding = kwargs.pop("finding", None) or _finding()
    return PolicyDecision(
        finding=finding,
        action=action,
        rule_id=kwargs.pop("rule_id", "test-rule"),
        severity=kwargs.pop("severity", "high"),
        **kwargs,
    )


class OperatorVocabularyConstantsTests(unittest.TestCase):
    def test_three_new_actions_present_in_valid_actions(self):
        for action in ("replace", "hash", "encrypt"):
            self.assertIn(action, VALID_ACTIONS)

    def test_retired_audit_only_actions_are_invalid(self):
        for action in ("allow", "warn", "log"):
            self.assertNotIn(action, VALID_ACTIONS)

    def test_core_transforming_actions_still_valid(self):
        for action in ("redact", "mask", "tokenize", "block"):
            self.assertIn(action, VALID_ACTIONS)

    def test_supported_hash_algos_cover_common_choices(self):
        self.assertEqual(VALID_HASH_ALGOS, {"sha256", "sha512", "blake2b"})

    def test_transforming_actions_includes_new_operators(self):
        for action in ("replace", "hash", "encrypt"):
            self.assertIn(action, TRANSFORMING_ACTIONS)


class ReplaceOperatorTests(unittest.TestCase):
    def test_replace_emits_operator_supplied_literal(self):
        decision = _decision("replace", replacement="[CUSTOMER]")
        self.assertEqual(_replacement(decision), "[CUSTOMER]")

    def test_replace_falls_back_to_entity_marker_when_replacement_missing(self):
        # Should never happen in practice — policy load rejects it —
        # but the transform layer should not raise on a malformed
        # decision (raise-on-load is the invariant; the transform
        # layer's job is to keep producing a non-leaky string).
        decision = _decision("replace", replacement=None)
        self.assertIn("REPLACED", _replacement(decision))


class HashOperatorTests(unittest.TestCase):
    def test_sha256_default_emits_truncated_hex(self):
        decision = _decision("hash", hash_algo="sha256")
        out = _replacement(decision)
        self.assertTrue(out.startswith("<OTHER_SECRET:HASH:sha256="), out)
        match = re.match(r"<OTHER_SECRET:HASH:sha256=([0-9a-f]+)>", out)
        self.assertIsNotNone(match, out)
        self.assertEqual(len(match.group(1)), 16, "expected 64-bit truncated hex")

    def test_blake2b_emits_blake2b_marker(self):
        decision = _decision("hash", hash_algo="blake2b")
        self.assertTrue(_replacement(decision).startswith("<OTHER_SECRET:HASH:blake2b="))

    def test_hash_is_deterministic_across_calls(self):
        # The same input + algo must always produce the same output —
        # operators rely on this for stable correlation across audit
        # events and traces.
        d1 = _decision("hash", hash_algo="sha256")
        d2 = _decision("hash", hash_algo="sha256")
        self.assertEqual(_replacement(d1), _replacement(d2))

    def test_hash_value_does_not_leak_raw_value_substring(self):
        decision = _decision("hash", hash_algo="sha256")
        self.assertNotIn("Hunter22!!", _replacement(decision))


class EncryptOperatorTests(unittest.TestCase):
    def setUp(self):
        self.key = Fernet.generate_key().decode("ascii")
        self.env_var = "LSDF_TEST_ENCRYPT_KEY_OPS"
        os.environ[self.env_var] = self.key
        self.addCleanup(os.environ.pop, self.env_var, None)

    def test_encrypt_emits_ciphertext_marker(self):
        decision = _decision("encrypt", encrypt_key_env=self.env_var)
        out = _replacement(decision)
        self.assertTrue(out.startswith("<OTHER_SECRET:ENC:"), out)
        self.assertTrue(out.endswith(">"), out)

    def test_encrypt_round_trip_recovers_original_value(self):
        decision = _decision(
            "encrypt", encrypt_key_env=self.env_var, finding=_finding(value="VerySecret_99")
        )
        out = _replacement(decision)
        match = re.match(r"<OTHER_SECRET:ENC:(.+)>", out)
        self.assertIsNotNone(match)
        plaintext = Fernet(self.key.encode()).decrypt(match.group(1).encode()).decode()
        self.assertEqual(plaintext, "VerySecret_99")

    def test_encrypt_does_not_leak_raw_value_substring(self):
        decision = _decision(
            "encrypt", encrypt_key_env=self.env_var, finding=_finding(value="VerySecret_99")
        )
        self.assertNotIn("VerySecret_99", _replacement(decision))

    def test_encrypt_raises_when_env_var_unset(self):
        decision = _decision("encrypt", encrypt_key_env="LSDF_DEFINITELY_UNSET_VAR")
        with self.assertRaises(ValueError) as ctx:
            _replacement(decision)
        # The message must name both the rule and the missing env var so
        # an operator can find the misconfiguration without a debugger.
        self.assertIn("LSDF_DEFINITELY_UNSET_VAR", str(ctx.exception))
        self.assertIn("test-rule", str(ctx.exception))

    def test_encrypt_raises_when_key_is_invalid(self):
        os.environ[self.env_var] = "not-a-fernet-key"
        decision = _decision("encrypt", encrypt_key_env=self.env_var)
        with self.assertRaises(ValueError) as ctx:
            _replacement(decision)
        self.assertIn(self.env_var, str(ctx.exception))


class PolicyLoadValidationTests(unittest.TestCase):
    """Per-rule operator parameters must be validated at policy load."""

    def _load_yaml(self, body: str):
        from pathlib import Path
        from tempfile import NamedTemporaryFile

        from lsdf.policy import load_policy

        with NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(body)
            tmp_path = tmp.name
        try:
            return load_policy(tmp_path)
        finally:
            Path(tmp_path).unlink()

    def _policy_body(self, action_block: str) -> str:
        # `action_block` carries action + any per-action params. Each
        # line lands inside the same mapping as `match:`, so each line
        # gets indented to match the rule-item body under action.rules.
        body_lines = [f"      {line}" for line in action_block.splitlines() if line.strip()]
        action_text = "\n".join(body_lines)
        return dedent(
            """\
            version: "0.2"
            name: test-policy
            detection:
              entities:
                - SECRET
            action:
              mode: redact
              rules:
                - id: rule-1
                  match:
                    entity_in_category: SECRET
                    surface: output.content
            """
        ) + action_text + "\n"

    def test_replace_without_replacement_is_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            self._load_yaml(self._policy_body("action: replace"))
        self.assertIn("replacement", str(ctx.exception))

    def test_replace_with_replacement_loads(self):
        policy = self._load_yaml(
            self._policy_body("action: replace\nreplacement: '[CUSTOMER]'")
        )
        self.assertEqual(policy.rules[0].action, "replace")
        self.assertEqual(policy.rules[0].replacement, "[CUSTOMER]")

    def test_replacement_on_non_replace_action_is_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            self._load_yaml(
                self._policy_body("action: redact\nreplacement: '[CUSTOMER]'")
            )
        self.assertIn("replacement", str(ctx.exception))

    def test_hash_without_algo_defaults_to_sha256(self):
        policy = self._load_yaml(self._policy_body("action: hash"))
        self.assertEqual(policy.rules[0].action, "hash")
        self.assertEqual(policy.rules[0].hash_algo, "sha256")

    def test_hash_with_unsupported_algo_is_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            self._load_yaml(self._policy_body("action: hash\nhash_algo: md4-32"))
        self.assertIn("hash_algo", str(ctx.exception))

    def test_hash_algo_on_non_hash_action_is_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            self._load_yaml(
                self._policy_body("action: redact\nhash_algo: sha256")
            )
        self.assertIn("hash_algo", str(ctx.exception))

    def test_encrypt_without_key_env_is_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            self._load_yaml(self._policy_body("action: encrypt"))
        self.assertIn("encrypt_key_env", str(ctx.exception))

    def test_encrypt_with_blank_key_env_is_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            self._load_yaml(
                self._policy_body("action: encrypt\nencrypt_key_env: '   '")
            )
        self.assertIn("encrypt_key_env", str(ctx.exception))

    def test_encrypt_with_key_env_loads(self):
        policy = self._load_yaml(
            self._policy_body("action: encrypt\nencrypt_key_env: MY_KEY_ENV")
        )
        self.assertEqual(policy.rules[0].action, "encrypt")
        self.assertEqual(policy.rules[0].encrypt_key_env, "MY_KEY_ENV")

    def test_encrypt_key_env_on_non_encrypt_action_is_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            self._load_yaml(
                self._policy_body("action: redact\nencrypt_key_env: MY_KEY")
            )
        self.assertIn("encrypt_key_env", str(ctx.exception))


class FirewallEndToEndTests(unittest.TestCase):
    """The new operators must produce raw-value-safe transformed payloads
    when invoked through `Firewall.inspect`."""

    def _policy_path(self, body: str) -> str:
        from pathlib import Path
        from tempfile import NamedTemporaryFile

        with NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(body)
            return tmp.name

    def _firewall(self, action_block: str):
        from lsdf import Firewall, load_policy

        body_lines = [f"      {line}" for line in action_block.splitlines() if line.strip()]
        action_text = "\n".join(body_lines)
        body = dedent(
            """\
            version: "0.2"
            name: t
            detection:
              entities:
                - US_SSN
            action:
              mode: redact
              rules:
                - id: ssn-rule
                  match:
                    entity: US_SSN
                    surface: output.content
            """
        ) + action_text + "\n"
        return Firewall(load_policy(self._policy_path(body)))

    def test_replace_transforms_payload(self):
        firewall = self._firewall("action: replace\nreplacement: '[REDACTED-SSN]'")
        result = firewall.inspect(
            {"choices": [{"message": {"content": "SSN 123-45-6789"}}]}
        )
        text = result.transformed_payload["choices"][0]["message"]["content"]
        self.assertNotIn("123-45-6789", text)
        self.assertIn("[REDACTED-SSN]", text)

    def test_hash_transforms_payload(self):
        firewall = self._firewall("action: hash")
        result = firewall.inspect(
            {"choices": [{"message": {"content": "SSN 123-45-6789"}}]}
        )
        text = result.transformed_payload["choices"][0]["message"]["content"]
        self.assertNotIn("123-45-6789", text)
        self.assertIn("HASH:sha256=", text)

    def test_encrypt_transforms_payload_and_round_trips(self):
        env_var = "LSDF_E2E_ENCRYPT_KEY"
        key = Fernet.generate_key().decode("ascii")
        os.environ[env_var] = key
        try:
            firewall = self._firewall(
                f"action: encrypt\nencrypt_key_env: {env_var}"
            )
            result = firewall.inspect(
                {"choices": [{"message": {"content": "SSN 123-45-6789"}}]}
            )
            text = result.transformed_payload["choices"][0]["message"]["content"]
            self.assertNotIn("123-45-6789", text)
            self.assertIn("ENC:", text)
            match = re.search(r"<US_SSN:ENC:(.+?)>", text)
            self.assertIsNotNone(match, text)
            recovered = (
                Fernet(key.encode()).decrypt(match.group(1).encode()).decode()
            )
            self.assertEqual(recovered, "123-45-6789")
        finally:
            os.environ.pop(env_var, None)


class EvaluateErrorIsolationTests(unittest.TestCase):
    """Reviewer fix: a per-case inspection error (e.g. encrypt with an
    unset env var) must not crash the entire `Firewall.evaluate` run."""

    def _firewall_with_encrypt(self, env_var: str):
        from pathlib import Path
        from tempfile import NamedTemporaryFile

        from lsdf import Firewall, load_policy

        body = dedent(
            f"""\
            version: "0.2"
            name: t
            detection:
              entities:
                - US_SSN
            action:
              mode: redact
              rules:
                - id: ssn-rule
                  match:
                    entity: US_SSN
                    surface: output.content
                  action: encrypt
                  encrypt_key_env: {env_var}
            """
        )
        with NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(body)
            tmp_path = tmp.name
        try:
            return Firewall(load_policy(tmp_path))
        finally:
            Path(tmp_path).unlink()

    def test_evaluate_marks_case_failed_when_encrypt_env_var_unset(self):
        env_var = "LSDF_ENC_KEY_NEVER_SET"
        os.environ.pop(env_var, None)
        firewall = self._firewall_with_encrypt(env_var)
        cases = [
            {
                "id": "case-clean",
                "payload": {
                    "choices": [{"message": {"content": "no leaks here"}}]
                },
            },
            {
                "id": "case-with-ssn",
                "payload": {
                    "choices": [
                        {"message": {"content": "SSN 123-45-6789"}}
                    ]
                },
                "sensitive_values": ["123-45-6789"],
                "expected_absent": ["123-45-6789"],
            },
        ]
        # Must not raise — the bad case is isolated, not propagated.
        report = firewall.evaluate(cases)
        self.assertEqual(report["case_count"], 2)
        self.assertGreaterEqual(report["failed"], 1)
        # Find the failed case and confirm the error is recorded.
        failed_case = next(
            (r for r in report["results"] if r["id"] == "case-with-ssn"),
            None,
        )
        self.assertIsNotNone(failed_case)
        self.assertFalse(failed_case["passed"])
        self.assertEqual(failed_case["failures"], ["inspection_error: invalid_payload_or_transform"])
        self.assertEqual(failed_case["error_category"], "invalid_payload_or_transform")
        self.assertEqual(report["evaluation_errors"], 1)
        self.assertEqual(report["evaluation_error_categories"], {"invalid_payload_or_transform": 1})
        self.assertTrue(next(r for r in report["results"] if r["id"] == "case-clean")["passed"])
        self.assertNotIn(env_var, str(report))


if __name__ == "__main__":
    unittest.main()
