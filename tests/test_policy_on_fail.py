"""Per-rule `on_fail` enum behavior.

`on_fail` is the per-rule analog of the policy-level `mode` field. It lets
        operators mix redact/block/observe behavior on a per-rule basis instead of
        having the policy-wide mode switch be the only knob:

  - on_fail = mask     (default explicit) — apply the action's transform.
                       Equivalent to redact-mode default behavior.
  - on_fail = observe  — log the decision, do NOT apply the transform, and
                       do NOT block. Per-rule analog of mode=monitor.
  - on_fail = block    — set blocked=True regardless of whether the rule's
                       action is "block". Useful for "any time this rule
                       fires, halt the request" overrides on otherwise
                       gentle actions.
  - on_fail = reask    — apply the transform AND surface a `reask_hint` flag
                       in the audit event. Without an external request-park
                       and resume protocol, LSDF can't actually retry — but
                       the flag tells a wrapping orchestration layer to
                       re-issue the call with a redaction prefix.
  - on_fail = exception — raise `PolicyEnforcementError` when the rule
                       fires. For "this should never happen, halt loudly"
                       cases.

When `on_fail` is unset (None), mode-driven behavior is preserved:
redact-mode applies transforms and blocks on action=block; monitor-mode
audits without enforcing.
"""

import unittest

from lsdf import Firewall
from lsdf.policy import AuditConfig, DetectorConfig, Policy, Rule
from lsdf.types import PolicyEnforcementError


def _policy_with_rule(rule: Rule, *, mode: str = "redact") -> Policy:
    return Policy(
        version="0.2",
        name="on-fail-test",
        mode=mode,
        entities={"API_KEY"},
        surfaces={"input.messages", "output.content"},
        rules=[rule],
        audit=AuditConfig(),
        detectors=DetectorConfig(),
    )


def _api_key_payload() -> dict:
    # Synthetic API-key-shaped fixture matching the bundled regex.secret
    # fixture style ("api_LSDF_FIXTURE_TOKEN_..." prefix is recognised by the
    # default detector chain).
    return {
        "messages": [
            {
                "role": "user",
                "content": "remember api_LSDF_FIXTURE_TOKEN_000000 for the call",
            }
        ]
    }


class OnFailDefaultTests(unittest.TestCase):
    """When on_fail is unset (None), behavior must match pre-on_fail semantics."""

    def test_default_redact_mode_applies_transform(self):
        rule = Rule(
            id="redact-keys",
            match={"entity": "API_KEY", "surface": "input.messages"},
            action="redact",
        )
        firewall = Firewall(_policy_with_rule(rule, mode="redact"))
        result = firewall.inspect(_api_key_payload())
        self.assertNotIn(
            "api_LSDF_FIXTURE_TOKEN_000000",
            result.transformed_payload["messages"][0]["content"],
        )
        self.assertFalse(result.blocked)

    def test_default_monitor_mode_skips_transform(self):
        rule = Rule(
            id="redact-keys",
            match={"entity": "API_KEY", "surface": "input.messages"},
            action="redact",
        )
        firewall = Firewall(_policy_with_rule(rule, mode="monitor"))
        result = firewall.inspect(_api_key_payload())
        self.assertIn(
            "api_LSDF_FIXTURE_TOKEN_000000",
            result.transformed_payload["messages"][0]["content"],
        )
        self.assertFalse(result.blocked)

    def test_default_redact_mode_blocks_on_action_block(self):
        rule = Rule(
            id="block-keys",
            match={"entity": "API_KEY", "surface": "input.messages"},
            action="block",
        )
        firewall = Firewall(_policy_with_rule(rule, mode="redact"))
        result = firewall.inspect(_api_key_payload())
        self.assertTrue(result.blocked)


class OnFailObserveTests(unittest.TestCase):
    def test_observe_in_redact_mode_skips_transform_keeps_audit(self):
        rule = Rule(
            id="observe-keys",
            match={"entity": "API_KEY", "surface": "input.messages"},
            action="redact",
            on_fail="observe",
        )
        firewall = Firewall(_policy_with_rule(rule, mode="redact"))
        result = firewall.inspect(_api_key_payload())

        self.assertIn(
            "api_LSDF_FIXTURE_TOKEN_000000",
            result.transformed_payload["messages"][0]["content"],
            "observe should NOT apply the transform even in redact mode",
        )
        self.assertFalse(result.blocked)
        self.assertEqual(
            len(result.decisions),
            1,
            "observe should still surface the decision in the audit trail",
        )

    def test_observe_overrides_action_block(self):
        rule = Rule(
            id="observe-keys",
            match={"entity": "API_KEY", "surface": "input.messages"},
            action="block",
            on_fail="observe",
        )
        firewall = Firewall(_policy_with_rule(rule, mode="redact"))
        result = firewall.inspect(_api_key_payload())
        self.assertFalse(
            result.blocked,
            "observe must downgrade block-action to log-only at the rule level",
        )


class OnFailBlockTests(unittest.TestCase):
    def test_block_overrides_gentle_action(self):
        rule = Rule(
            id="block-on-key",
            match={"entity": "API_KEY", "surface": "input.messages"},
            action="redact",
            on_fail="block",
        )
        firewall = Firewall(_policy_with_rule(rule, mode="redact"))
        result = firewall.inspect(_api_key_payload())
        self.assertTrue(
            result.blocked,
            "on_fail=block must escalate to blocked even if action is a transform",
        )

    def test_block_in_monitor_mode_still_blocks(self):
        # The whole point of on_fail=block is to be louder than the policy-
        # level mode for specific rules.
        rule = Rule(
            id="block-on-key",
            match={"entity": "API_KEY", "surface": "input.messages"},
            action="redact",
            on_fail="block",
        )
        firewall = Firewall(_policy_with_rule(rule, mode="monitor"))
        result = firewall.inspect(_api_key_payload())
        self.assertTrue(
            result.blocked,
            "on_fail=block escalates regardless of policy mode",
        )

    def test_block_audit_event_blocked_field_matches_inspection_result(self):
        # Reviewer caught: a stale `blocked` field in the audit event would
        # contradict InspectionResult.blocked when on_fail=block fires on a
        # rule whose action is not literally "block". Both must agree.
        rule = Rule(
            id="block-on-key",
            match={"entity": "API_KEY", "surface": "input.messages"},
            action="redact",
            on_fail="block",
        )
        firewall = Firewall(_policy_with_rule(rule, mode="redact"))
        result = firewall.inspect(_api_key_payload())
        self.assertTrue(result.blocked)
        self.assertTrue(
            result.audit_event["blocked"],
            "audit_event['blocked'] must agree with InspectionResult.blocked "
            "when on_fail=block escalates a transform action",
        )

    def test_block_with_redact_action_still_redacts(self):
        # Reviewer caught: action=redact + on_fail=block should both halt the
        # request AND scrub the payload. Otherwise the unredacted value sits
        # in result.transformed_payload even though the request was blocked,
        # which is a downstream-surface footgun (the gateway might still hand
        # the structure to a logger / tracer / observability shim).
        rule = Rule(
            id="redact-and-halt",
            match={"entity": "API_KEY", "surface": "input.messages"},
            action="redact",
            on_fail="block",
        )
        firewall = Firewall(_policy_with_rule(rule, mode="redact"))
        result = firewall.inspect(_api_key_payload())
        self.assertTrue(result.blocked)
        self.assertNotIn(
            "api_LSDF_FIXTURE_TOKEN_000000",
            result.transformed_payload["messages"][0]["content"],
            "on_fail=block must apply the rule's action transform so the "
            "halted-but-still-structurally-present payload is raw-value-safe",
        )


class OnFailReaskTests(unittest.TestCase):
    def test_reask_applies_transform_and_flags_audit(self):
        rule = Rule(
            id="reask-on-key",
            match={"entity": "API_KEY", "surface": "input.messages"},
            action="redact",
            on_fail="reask",
        )
        firewall = Firewall(_policy_with_rule(rule, mode="redact"))
        result = firewall.inspect(_api_key_payload())
        self.assertNotIn(
            "api_LSDF_FIXTURE_TOKEN_000000",
            result.transformed_payload["messages"][0]["content"],
            "reask should apply the action's transform like default mask",
        )
        self.assertTrue(
            result.audit_event.get("reask_hint"),
            "reask must surface a reask_hint flag in the audit event so a "
            "wrapping orchestration layer can decide to re-issue with a "
            "redaction prefix",
        )


class OnFailExceptionTests(unittest.TestCase):
    def test_exception_raises_policy_enforcement_error(self):
        rule = Rule(
            id="halt-on-key",
            match={"entity": "API_KEY", "surface": "input.messages"},
            action="redact",
            on_fail="exception",
        )
        firewall = Firewall(_policy_with_rule(rule, mode="redact"))
        with self.assertRaises(PolicyEnforcementError) as caught:
            firewall.inspect(_api_key_payload())
        message = str(caught.exception)
        # The error message must name the rule and entity so an operator can
        # find the offending rule without re-running with debug logging.
        self.assertIn("halt-on-key", message)
        self.assertIn("API_KEY", message)


class OnFailMaskExplicitTests(unittest.TestCase):
    def test_mask_is_explicit_default(self):
        # `on_fail: mask` is the explicit form of the default — same behavior
        # as omitting on_fail entirely. This test pins that equivalence so
        # operators can be explicit in policy YAML without behavior drift.
        rule = Rule(
            id="mask-keys",
            match={"entity": "API_KEY", "surface": "input.messages"},
            action="redact",
            on_fail="mask",
        )
        firewall = Firewall(_policy_with_rule(rule, mode="redact"))
        result = firewall.inspect(_api_key_payload())
        self.assertNotIn(
            "api_LSDF_FIXTURE_TOKEN_000000",
            result.transformed_payload["messages"][0]["content"],
        )
        self.assertFalse(result.blocked)


class OnFailValidationTests(unittest.TestCase):
    def test_invalid_on_fail_value_raises_at_policy_load(self):
        from lsdf import load_policy
        from pathlib import Path
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.yaml"
            path.write_text(
                "version: 0.2\n"
                "name: bad\n"
                "detection: {entities: [API_KEY]}\n"
                "action:\n"
                "  mode: redact\n"
                "  rules:\n"
                "    - id: bad-on-fail\n"
                "      match: {entity: API_KEY, surface: input.messages}\n"
                "      action: redact\n"
                "      on_fail: bogus\n"
            )
            with self.assertRaises(ValueError) as caught:
                load_policy(path)
            self.assertIn("on_fail", str(caught.exception))
            self.assertIn("bogus", str(caught.exception))

    def test_valid_on_fail_values_load_without_error(self):
        from lsdf import load_policy
        from pathlib import Path
        from tempfile import TemporaryDirectory

        for value in ("block", "mask", "reask", "observe", "exception"):
            with TemporaryDirectory() as tmp:
                path = Path(tmp) / "ok.yaml"
                path.write_text(
                    "version: 0.2\n"
                    "name: ok\n"
                    "detection: {entities: [API_KEY]}\n"
                    "action:\n"
                    "  mode: redact\n"
                    "  rules:\n"
                    f"    - id: rule-{value}\n"
                    "      match: {entity: API_KEY, surface: input.messages}\n"
                    "      action: redact\n"
                    f"      on_fail: {value}\n"
                )
                policy = load_policy(path)
                self.assertEqual(policy.rules[0].on_fail, value)



class MixedOnFailOrderingTests(unittest.TestCase):
    def test_monitor_escalation_dominates_in_both_finding_orders(self):
        from lsdf.types import Finding

        class OrderedScanner:
            def __init__(self, reverse):
                self.reverse = reverse

            def scan(self, surface):
                findings = [
                    Finding("API_KEY", surface.name, surface.pointer, 0, 2, "AA", 1.0),
                    Finding("US_SSN", surface.name, surface.pointer, 2, 4, "BB", 1.0),
                ]
                return list(reversed(findings)) if self.reverse else findings

        for reverse in (False, True):
            for escalation in ("block", "exception", None):
                with self.subTest(reverse=reverse, escalation=escalation):
                    policy = Policy(
                        version="0.2", name="mixed-on-fail", mode="monitor",
                        entities={"API_KEY", "US_SSN"}, surfaces={"input.messages"},
                        rules=[
                            Rule("ordinary-block", {"entity": "API_KEY"}, "block"),
                            Rule("escalation", {"entity": "US_SSN"}, "redact", on_fail=escalation),
                        ], audit=AuditConfig(),
                    )
                    firewall = Firewall(policy, scanner=OrderedScanner(reverse))
                    if escalation == "exception":
                        with self.assertRaises(PolicyEnforcementError):
                            firewall.inspect("AABB")
                    else:
                        result = firewall.inspect("AABB")
                        self.assertEqual(result.blocked, escalation == "block")
                        self.assertEqual(result.audit_event["blocked"], result.blocked)
                        if escalation is None:
                            self.assertEqual(result.transformed_payload, "AABB")



if __name__ == "__main__":
    unittest.main()
