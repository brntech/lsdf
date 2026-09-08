import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from lsdf.policy import load_subtype_manifest
from lsdf.system_recall import (
    coverage_gaps_for_gated_profiles,
    format_system_recall_markdown,
    system_recall_report,
)


class ManifestFloorTests(unittest.TestCase):
    def test_committed_manifest_declares_floor_for_every_foundation_fixture(self):
        manifest = load_subtype_manifest()
        floor_pairs = manifest["foundation_floor_pairs"]
        out_of_scope_pairs = manifest["foundation_out_of_scope_pairs"]
        fixture_pairs = {
            (path.parent.name, path.stem)
            for path in Path("tests/foundation/fixtures").glob("*/*.json")
        }

        self.assertEqual(fixture_pairs, floor_pairs | out_of_scope_pairs)
        self.assertFalse(floor_pairs & out_of_scope_pairs)

    def test_declared_floor_without_fixture_hard_fails(self):
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            manifest_path = root / "manifest.yaml"
            manifest_path.write_text(
                """
version: 0.2
detectors:
  regex.jwt:
    emits: [JWT]
    pattern_summary: "JWTs."
    recall_floor:
      foundation:
        JWT: 0.95
    specificity_floor:
      foundation:
        JWT: 0.95
standalone_entities: []
reserved_subtypes: {}
categories: {}
""".strip()
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "without fixture"):
                load_subtype_manifest(path=manifest_path, fixture_root=root / "fixtures")

    def test_out_of_scope_without_fixture_hard_fails(self):
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            manifest_path = root / "manifest.yaml"
            manifest_path.write_text(
                """
version: 0.2
detectors:
  regex.jwt:
    emits: [JWT]
    pattern_summary: "JWTs."
    out_of_scope:
      foundation:
        JWT: true
standalone_entities: []
reserved_subtypes: {}
categories: {}
""".strip()
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "without fixture"):
                load_subtype_manifest(path=manifest_path, fixture_root=root / "fixtures")

    def test_out_of_scope_and_floor_overlap_hard_fails(self):
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            fixture_dir = root / "fixtures" / "regex.jwt"
            fixture_dir.mkdir(parents=True)
            (fixture_dir / "JWT.json").write_text("{}", encoding="utf-8")
            manifest_path = root / "manifest.yaml"
            manifest_path.write_text(
                """
version: 0.2
detectors:
  regex.jwt:
    emits: [JWT]
    pattern_summary: "JWTs."
    out_of_scope:
      foundation:
        JWT: true
    recall_floor:
      foundation:
        JWT: 0.95
    specificity_floor:
      foundation:
        JWT: 0.95
standalone_entities: []
reserved_subtypes: {}
categories: {}
""".strip()
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "out_of_scope pairs must not declare"):
                load_subtype_manifest(path=manifest_path, fixture_root=root / "fixtures")

    def test_zero_recall_floor_hard_fails(self):
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            fixture_dir = root / "fixtures" / "regex.jwt"
            fixture_dir.mkdir(parents=True)
            (fixture_dir / "JWT.json").write_text("{}", encoding="utf-8")
            manifest_path = root / "manifest.yaml"
            manifest_path.write_text(
                """
version: 0.2
detectors:
  regex.jwt:
    emits: [JWT]
    pattern_summary: "JWTs."
    recall_floor:
      foundation:
        JWT: 0.00
    specificity_floor:
      foundation:
        JWT: 0.95
standalone_entities: []
reserved_subtypes: {}
categories: {}
""".strip()
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "greater than 0.0"):
                load_subtype_manifest(path=manifest_path, fixture_root=root / "fixtures")

    def test_coverage_gap_enumeration_reports_missing_floors_without_failing(self):
        manifest = _without_foundation_floor(load_subtype_manifest(), "regex.jwt", "JWT")

        gaps = coverage_gaps_for_gated_profiles(
            manifest=manifest,
            profile_names=("healthcare",),
        )

        self.assertGreater(gaps["count"], 0)
        self.assertIn(
            {
                "entity": "JWT",
                "profiles": ["healthcare"],
                "enabled_detectors": ["regex.jwt"],
            },
            gaps["pairs"],
        )

    def test_committed_manifest_reports_profile_entities_without_emitters_as_gaps(self):
        gaps = coverage_gaps_for_gated_profiles()

        self.assertGreater(gaps["count"], 0)
        self.assertIn(
            {
                "entity": "SWIFT",
                "profiles": ["broad-pii", "broad-pii-ml", "healthcare"],
                "enabled_detectors": [],
            },
            gaps["pairs"],
        )
        self.assertIn(
            {
                "entity": "HEALTH_INSURANCE_ID",
                "profiles": ["healthcare"],
                "enabled_detectors": [],
            },
            gaps["pairs"],
        )

    def test_system_recall_report_warns_when_gaps_exist(self):
        manifest = _without_foundation_floor(load_subtype_manifest(), "regex.jwt", "JWT")

        with self.assertWarnsRegex(UserWarning, "FOUNDATION_COVERAGE_GAP_WARNING"):
            report = system_recall_report(
                manifest=manifest,
                profile_names=("healthcare",),
                generated_at="2026-05-07T00:00:00Z",
                commit_sha="abc1234",
            )

        self.assertGreater(report["coverage_gaps"]["count"], 0)

    def test_system_recall_markdown_renders_gap_count_and_section(self):
        markdown = format_system_recall_markdown(
            [
                {
                    "detector": "regex.jwt",
                    "corpus": "foundation",
                    "entity": "JWT",
                    "recall": 1.0,
                    "specificity": 1.0,
                    "tp": 1,
                    "fn": 0,
                    "fp": 0,
                    "tn": 1,
                }
            ],
            generated_at="2026-05-07T00:00:00Z",
            commit_sha="abc1234",
            coverage_gaps={
                "available": True,
                "count": 1,
                "active_pairs": [
                    {
                        "detector": "regex.jwt",
                        "entity": "JWT",
                        "profiles": ["healthcare"],
                    }
                ],
                "pairs": [
                    {
                        "entity": "JWT",
                        "profiles": ["healthcare"],
                        "enabled_detectors": ["regex.jwt"],
                    }
                ],
            },
        )

        self.assertIn(
            "Coverage gaps: 1 profile/entity pairs in gated profiles have no "
            "in-scope detector with a non-zero foundation floor.",
            markdown,
        )
        self.assertIn("| JWT | healthcare | regex.jwt |", markdown)


def _without_foundation_floor(manifest: dict, detector: str, entity: str) -> dict:
    key = (detector, "foundation", entity)
    recall_floors = dict(manifest["recall_floors"])
    specificity_floors = dict(manifest["specificity_floors"])
    recall_floors.pop(key)
    specificity_floors.pop(key)
    return {
        **manifest,
        "recall_floors": recall_floors,
        "specificity_floors": specificity_floors,
        "foundation_floor_pairs": {
            (floor_detector, floor_entity)
            for floor_detector, corpus, floor_entity in recall_floors
            if corpus == "foundation"
        },
    }


if __name__ == "__main__":
    unittest.main()
