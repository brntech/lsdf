from __future__ import annotations

import unittest
import warnings
from pathlib import Path
from tempfile import TemporaryDirectory
from textwrap import dedent

from lsdf import Firewall, load_policy
from lsdf.types import Finding


class StaticScanner:
    def __init__(self, findings: list[Finding]):
        self.findings = findings

    def scan(self, surface):
        return [
            finding
            for finding in self.findings
            if finding.surface == surface.name and finding.pointer == surface.pointer
        ]


def _write_policy(body: str) -> Path:
    tmpdir = TemporaryDirectory()
    path = Path(tmpdir.name) / "policy.yaml"
    path.write_text(dedent(body).strip() + "\n", encoding="utf-8")
    _TEMP_DIRS.append(tmpdir)
    return path


def _finding(entity: str, value: str = "TOKEN") -> Finding:
    content = f"prefix {value} suffix"
    start = content.index(value)
    return Finding(
        entity=entity,
        surface="output.content",
        pointer=("choices", 0, "message", "content"),
        start=start,
        end=start + len(value),
        value=value,
        confidence=0.99,
        detector_id="test.detector",
        detector_family="test",
    )


def _policy_path(
    rules: str,
    *,
    mode: str = "redact",
    entities: str = "",
    adapters: str = "",
) -> Path:
    adapter_list = f"[{adapters}]" if adapters else "[]"
    return _write_policy(
        f"""
        version: 0.2
        name: v02-test
        detection:
          adapters: {adapter_list}
          entities: [{entities}]
        action:
          mode: {mode}
          rules:
        {rules}
        audit:
          store_raw_values: false
        """
    )


class PolicySchemaV02LoadTests(unittest.TestCase):
    def test_minimal_v02_policy_loads(self):
        policy = load_policy(
            _policy_path(
                """
            - id: redact-api-key
              match: {entity: API_KEY, surface: output.content}
              action: redact
              priority: 10
                """,
                entities="SECRET",
            )
        )

        self.assertEqual(policy.version, "0.2")
        self.assertEqual(policy.mode, "redact")

    def test_legacy_enforce_shape_is_rejected(self):
        path = _write_policy(
            """
            version: 0.1
            name: old
            mode: enforce
            entities: [API_KEY]
            surfaces: [output.content]
            rules: []
            """
        )

        with self.assertRaisesRegex(ValueError, "action"):
            load_policy(path)

    def test_retired_log_action_is_rejected(self):
        path = _policy_path(
            """
            - id: log-api-key
              match: {entity: API_KEY, surface: output.content}
              action: log
            """
        )

        with self.assertRaisesRegex(ValueError, "invalid action"):
            load_policy(path)


class EntityMatchingV02Tests(unittest.TestCase):
    def test_category_match_catches_member_entity(self):
        policy = load_policy(
            _policy_path(
                """
            - id: redact-secret-category
              match: {entity_in_category: SECRET, surface: output.content}
              action: redact
                """
            )
        )
        result = Firewall(policy, scanner=StaticScanner([_finding("API_KEY")])).inspect(
            {"choices": [{"message": {"content": "prefix TOKEN suffix"}}]}
        )

        self.assertEqual(result.decisions[0].rule_id, "redact-secret-category")

    def test_positive_entity_match_fields_are_or_semantics(self):
        policy = load_policy(
            _policy_path(
                """
            - id: redact-contact-or-secret
              match:
                entity_any_of: [EMAIL]
                entity_in_category: SECRET
                surface: output.content
              action: redact
                """
            )
        )
        result = Firewall(policy, scanner=StaticScanner([_finding("API_KEY")])).inspect(
            {"choices": [{"message": {"content": "prefix TOKEN suffix"}}]}
        )

        self.assertEqual(result.decisions[0].rule_id, "redact-contact-or-secret")

    def test_entity_except_subtracts_from_category(self):
        policy = load_policy(
            _policy_path(
                """
            - id: redact-secret-category-except-api-key
              match:
                entity_in_category: SECRET
                entity_except: [API_KEY]
                surface: output.content
              action: redact
                """
            )
        )
        result = Firewall(policy, scanner=StaticScanner([_finding("API_KEY")])).inspect(
            {"choices": [{"message": {"content": "prefix TOKEN suffix"}}]}
        )

        self.assertEqual(result.decisions, [])


class ManifestValidationV02Tests(unittest.TestCase):
    def test_emitted_entity_loads_without_warning(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            load_policy(
                _policy_path(
                    """
            - id: redact-api-key
              match: {entity: API_KEY, surface: output.content}
              action: redact
                    """
                )
            )

        self.assertEqual(caught, [])

    def test_reserved_subtype_loads_with_warning(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            load_policy(
                _policy_path(
                    """
            - id: redact-oauth-token
              match: {entity: OAUTH_TOKEN, surface: output.content}
              action: redact
                    """
                )
            )

        self.assertTrue(any("RESERVED_SUBTYPE_WARNING" in str(item.message) for item in caught))
        self.assertTrue(any("regex.gcp_oauth" in str(item.message) for item in caught))

    def test_gliner_only_subtype_loads_without_warning_when_gliner_is_active(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            load_policy(
                _policy_path(
                    """
            - id: redact-health-insurance-id
              match: {entity: HEALTH_INSURANCE_ID, surface: output.content}
              action: redact
                    """,
                    adapters="gliner",
                )
            )

        self.assertEqual(caught, [])

    def test_inactive_adapter_entity_warns_about_no_active_emitter(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            load_policy(
                _policy_path(
                    """
            - id: block-prompt-injection
              match: {entity: PROMPT_INJECTION, surface: input.rag_context}
              action: block
                    """
                )
            )

        self.assertTrue(any("NO_ACTIVE_EMITTER_WARNING" in str(item.message) for item in caught))
        self.assertTrue(any("PROMPT_INJECTION" in str(item.message) for item in caught))

    def test_standalone_entity_without_emitter_warns_not_hard_error(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            load_policy(
                _policy_path(
                    """
            - id: tokenize-swift
              match: {entity: SWIFT, surface: output.content}
              action: tokenize
                    """
                )
            )

        self.assertTrue(any("NO_ACTIVE_EMITTER_WARNING" in str(item.message) for item in caught))
        self.assertTrue(any("SWIFT" in str(item.message) for item in caught))

    def test_unknown_entity_is_hard_error_with_category_suggestion(self):
        path = _policy_path(
            """
            - id: redact-secretish
              match: {entity: SUPER_SECRET, surface: output.content}
              action: redact
            """
        )

        with self.assertRaisesRegex(ValueError, "entity_in_category: SECRET"):
            load_policy(path)

    def test_unknown_category_is_hard_error(self):
        path = _policy_path(
            """
            - id: redact-unknown-category
              match: {entity_in_category: TOKENISH, surface: output.content}
              action: redact
            """
        )

        with self.assertRaisesRegex(ValueError, "unknown entity category"):
            load_policy(path)

    def test_unknown_detection_entity_scope_is_hard_error(self):
        path = _policy_path(
            """
            - id: redact-api-key
              match: {entity: API_KEY, surface: output.content}
              action: redact
            """,
            entities="SECRETISH",
        )

        with self.assertRaisesRegex(ValueError, "detection.entities"):
            load_policy(path)


class SurfaceScopeV02Tests(unittest.TestCase):
    def test_surface_scope_replaces_whole_surface_and_audits_scope(self):
        value = "HbA1c 8.2%"
        policy = load_policy(
            _policy_path(
                """
            - id: redact-whole-phi-output
              match: {entity_in_category: PHI, surface: output.content}
              action: redact
              scope: surface
              priority: 50
                """
            )
        )
        result = Firewall(policy, scanner=StaticScanner([_finding("LAB_VALUE", value)])).inspect(
            {"choices": [{"message": {"content": f"prefix {value} suffix"}}]}
        )

        decision = result.decisions[0]
        self.assertEqual(
            result.transformed_payload["choices"][0]["message"]["content"],
            "<LAB_VALUE:REDACTED>",
        )
        self.assertEqual(decision.scope, "surface")
        self.assertTrue(decision.scope_escalated)
        self.assertEqual(result.audit_event["decisions"][0]["scope"], "surface")
        self.assertTrue(result.audit_event["decisions"][0]["scope_escalated"])

    def test_surface_scope_rejected_on_streaming_surface(self):
        path = _policy_path(
            """
            - id: redact-whole-stream
              match: {entity: LAB_VALUE, surface: output.stream_chunk}
              action: redact
              scope: surface
            """
        )

        with self.assertRaisesRegex(ValueError, "streaming-capable surface"):
            load_policy(path)

    def test_surface_scope_rejected_on_wildcard_surface(self):
        path = _policy_path(
            """
            - id: redact-whole-any
              match: {entity: LAB_VALUE, surface: any}
              action: redact
              scope: surface
            """
        )

        with self.assertRaisesRegex(ValueError, "streaming-capable surface"):
            load_policy(path)

    def test_surface_scope_rejected_when_surface_omitted(self):
        path = _policy_path(
            """
            - id: redact-whole-unspecified
              match: {entity: LAB_VALUE}
              action: redact
              scope: surface
            """
        )

        with self.assertRaisesRegex(ValueError, "streaming-capable surface"):
            load_policy(path)


class RulePrecedenceV02Tests(unittest.TestCase):
    def test_higher_priority_wins_before_action_class(self):
        policy = load_policy(
            _policy_path(
                """
            - id: lower-priority-block
              match: {entity: API_KEY, surface: output.content}
              action: block
              priority: 10
            - id: higher-priority-redact
              match: {entity: API_KEY, surface: output.content}
              action: redact
              priority: 20
                """
            )
        )
        result = Firewall(policy, scanner=StaticScanner([_finding("API_KEY")])).inspect(
            {"choices": [{"message": {"content": "prefix TOKEN suffix"}}]}
        )

        self.assertEqual(result.decisions[0].rule_id, "higher-priority-redact")

    def test_equal_priority_block_beats_surface_redact(self):
        policy = load_policy(
            _policy_path(
                """
            - id: surface-redact
              match: {entity: LAB_VALUE, surface: output.content}
              action: redact
              scope: surface
              priority: 50
            - id: span-block
              match: {entity: LAB_VALUE, surface: output.content}
              action: block
              priority: 50
                """
            )
        )
        result = Firewall(policy, scanner=StaticScanner([_finding("LAB_VALUE")])).inspect(
            {"choices": [{"message": {"content": "prefix TOKEN suffix"}}]}
        )

        self.assertEqual(result.decisions[0].rule_id, "span-block")

    def test_equal_priority_and_action_surface_beats_span(self):
        policy = load_policy(
            _policy_path(
                """
            - id: span-redact
              match: {entity: LAB_VALUE, surface: output.content}
              action: redact
              priority: 50
            - id: surface-redact
              match: {entity: LAB_VALUE, surface: output.content}
              action: redact
              scope: surface
              priority: 50
                """
            )
        )
        result = Firewall(policy, scanner=StaticScanner([_finding("LAB_VALUE")])).inspect(
            {"choices": [{"message": {"content": "prefix TOKEN suffix"}}]}
        )

        self.assertEqual(result.decisions[0].rule_id, "surface-redact")

    def test_equal_priority_user_rule_beats_pack_rule_same_action(self):
        policy = load_policy(
            _policy_path(
                """
            - id: healthcare.pack-redact
              match: {entity: LAB_VALUE, surface: output.content}
              action: redact
              priority: 50
            - id: custom-redact
              match: {entity: LAB_VALUE, surface: output.content}
              action: redact
              priority: 50
                """
            )
        )
        result = Firewall(policy, scanner=StaticScanner([_finding("LAB_VALUE")])).inspect(
            {"choices": [{"message": {"content": "prefix TOKEN suffix"}}]}
        )

        self.assertEqual(result.decisions[0].rule_id, "custom-redact")


_TEMP_DIRS = []


if __name__ == "__main__":
    unittest.main()
