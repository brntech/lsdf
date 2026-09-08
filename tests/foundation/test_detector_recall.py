# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import unittest
from pathlib import Path

import yaml

try:
    import pytest as _pytest
except ModuleNotFoundError:
    class _NoopMark:
        def __getattr__(self, _name):
            def decorator(obj):
                return obj

            return decorator

    class _NoopPytest:
        mark = _NoopMark()

    _pytest = _NoopPytest()

from lsdf.policy import load_subtype_manifest
from lsdf.system_recall import (
    FOUNDATION_CORPUS,
    _fixture_paths,
    _load_fixture,
    assert_foundation_floors,
    evaluate_foundation_fixtures,
)


FIXTURE_ROOT = Path(__file__).parent / "fixtures"
MANIFEST_PATH = Path("policies/subtype-emission-manifest.yaml")
EXPANDED_FIXTURE_DETECTOR_PREFIXES = (
    "contextual.",
    "contextual-broad.",
    "gliner.",
    "openai_privacy_filter.",
    "presidio.",
)


@_pytest.mark.slow
class FoundationFixtureShapeTests(unittest.TestCase):
    def test_manifest_detector_entity_pairs_have_fixture_files(self):
        expected = _manifest_detector_entity_pairs()
        actual = {(path.parent.name, path.stem) for path in _fixture_paths(FIXTURE_ROOT)}
        missing = sorted(expected - actual)
        self.assertEqual([], missing)

    def test_fixture_files_follow_foundation_shape(self):
        fixtures = list(_fixture_paths(FIXTURE_ROOT))
        self.assertTrue(fixtures, f"no fixtures found under {FIXTURE_ROOT}")
        for path in fixtures:
            with self.subTest(path=path):
                fixture = _load_fixture(path)
                self.assertEqual(path.parent.name, fixture["detector"])
                self.assertEqual(path.stem, fixture["entity"])
                self.assertIsInstance(fixture.get("description"), str)
                self.assertTrue(fixture["description"].strip())
                cases = fixture["cases"]
                self.assertTrue(cases)
                positive_count = sum(case["role"] == "positive" for case in cases)
                negative_count = sum(case["role"] == "negative" for case in cases)
                if fixture["detector"].startswith(EXPANDED_FIXTURE_DETECTOR_PREFIXES):
                    self.assertGreaterEqual(positive_count, 30)
                    self.assertGreaterEqual(negative_count, 15)
                    positive_texts = [
                        case["text"] for case in cases if case["role"] == "positive"
                    ]
                    negative_texts = [
                        case["text"] for case in cases if case["role"] == "negative"
                    ]
                    self.assertEqual(positive_count, len(set(positive_texts)))
                    self.assertEqual(negative_count, len(set(negative_texts)))
                    self.assertTrue(set(positive_texts).isdisjoint(negative_texts))
                ids = [case["id"] for case in cases]
                self.assertEqual(len(ids), len(set(ids)))
                self.assertTrue(any(case["role"] == "positive" for case in cases))
                self.assertTrue(any(case["role"] == "negative" for case in cases))
                for case in cases:
                    self.assertIn(case["role"], {"positive", "negative"})
                    self.assertIsInstance(case["text"], str)
                    self.assertTrue(case["text"].strip())
                    self.assertIsInstance(case.get("note", ""), str)


@_pytest.mark.slow
@_pytest.mark.optional_adapter
class FoundationDetectorRecallTests(unittest.TestCase):
    def test_detector_foundation_fixtures_emit_structured_metrics(self):
        results = list(evaluate_foundation_fixtures(fixture_root=FIXTURE_ROOT))
        self.assertTrue(results, f"no foundation results from {FIXTURE_ROOT}")
        for row in results:
            with self.subTest(detector=row.detector, entity=row.entity):
                data = row.as_dict()
                self.assertEqual(data["corpus"], FOUNDATION_CORPUS)
                self.assertGreater(data["tp"] + data["fn"], 0)
                self.assertGreater(data["tn"] + data["fp"], 0)
                self.assertGreaterEqual(data["recall"], 0.0)
                self.assertLessEqual(data["recall"], 1.0)
                self.assertGreaterEqual(data["specificity"], 0.0)
                self.assertLessEqual(data["specificity"], 1.0)

    def test_optional_adapter_fakes_emit_real_specificity_signal(self):
        rows = {
            (row.detector, row.entity): row
            for row in evaluate_foundation_fixtures(fixture_root=FIXTURE_ROOT)
        }

        for key in (
            ("gliner.pii_phi", "PERSON"),
            ("openai_privacy_filter.reference_model", "BANK_ACCOUNT"),
            ("presidio.analyzer", "PHONE"),
        ):
            with self.subTest(detector=key[0], entity=key[1]):
                row = rows[key]
                self.assertGreater(row.fp, 0)
                self.assertLess(row.specificity, 1.0)

    def test_detector_foundation_fixtures_meet_declared_manifest_floors(self):
        results = list(evaluate_foundation_fixtures(fixture_root=FIXTURE_ROOT))
        assert_foundation_floors(results, manifest=load_subtype_manifest())


def _manifest_detector_entity_pairs() -> set[tuple[str, str]]:
    with MANIFEST_PATH.open("r", encoding="utf-8") as handle:
        manifest = yaml.safe_load(handle)
    return {
        (detector, entity)
        for detector, config in manifest["detectors"].items()
        for entity in config.get("emits", [])
    }


if __name__ == "__main__":
    unittest.main()
