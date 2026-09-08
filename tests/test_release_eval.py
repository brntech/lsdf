"""Tests for `lsdf.release_eval` — the EVAL.md generator.

The release-evaluation harness reports per-corpus containment for
multiple threat datasets (piece_b_replay, medical_phi_replay,
nemotron_pii) and per-corpus FP load for benign datasets. These tests
pin the multi-corpus contract so the report shape stays stable across
refactors.
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lsdf.policy import load_policy_profile, release_gated_profile_names
from lsdf.release_eval import (
    DEFAULT_BENIGN_DATASETS,
    DEFAULT_PROFILES,
    DEFAULT_THREAT_DATASETS,
    format_release_evaluation_markdown,
    release_evaluation,
)


V02_RELEASE_GATED_CORPORA_BY_PROFILE = {
    "broad-pii": ("piece_b_replay", "medical_phi_replay", "br_agentic_pii"),
    "broad-pii-ml": ("piece_b_replay", "medical_phi_replay", "br_agentic_pii"),
    "healthcare": (
        "piece_b_replay",
        "medical_phi_replay",
        "nemotron_pii",
        "ai4privacy_multilingual",
        "br_agentic_pii",
    ),
}


class ReleaseEvaluationMultiCorpusTests(unittest.TestCase):
    def _run_default_profile(self, **overrides):
        return release_evaluation(
            profiles=("default",),
            iterations=3,
            **overrides,
        )

    def test_default_threat_datasets_include_only_bundled_corpora(self):
        self.assertEqual(
            {path.name for path in DEFAULT_THREAT_DATASETS},
            {
                "piece_b_replay.json", "medical_phi_replay.json",
                "nemotron_pii.json", "br_agentic_pii.json",
            },
        )
        self.assertFalse(Path("evals/ai4privacy_multilingual.json").exists())

    def test_external_corpus_requires_an_explicit_path(self):
        # Independently authored input exercises local loading, not upstream data.
        payload = {
            "name": "ai4privacy_multilingual",
            "source": "LSDF-owned interface test fixture",
            "source_license": "Apache-2.0",
            "cases": [{
                "id": "owned-external-interface",
                "surface": "output.content",
                "payload": {"choices": [{"message": {
                    "content": "Fixture email: sample.user@example.invalid",
                }}]},
                "sensitive_values": ["sample.user@example.invalid"],
                "expected_entities": ["EMAIL"],
            }],
        }
        with tempfile.TemporaryDirectory() as directory:
            external = Path(directory) / "separately-supplied.json"
            external.write_text(json.dumps(payload), encoding="utf-8")
            report = self._run_default_profile(
                threat_datasets=DEFAULT_THREAT_DATASETS + (external,),
            )
        self.assertEqual(len(report["threat_datasets"]), 5)
        metadata = report["threat_datasets"][-1]
        self.assertEqual(metadata["name"], "ai4privacy_multilingual")
        self.assertEqual(metadata["path"], str(external))
        self.assertEqual(metadata["case_count"], 1)
        self.assertEqual(metadata["source"], payload["source"])
        self.assertEqual(metadata["source_license"], payload["source_license"])

    def test_default_profiles_include_recall_closure_profiles(self):
        self.assertEqual(
            DEFAULT_PROFILES,
            ("default", "balanced", "broad-pii", "broad-pii-ml"),
        )

    def test_report_lists_each_threat_dataset_once(self):
        report = self._run_default_profile()
        names = [t["name"] for t in report["threat_datasets"]]
        self.assertEqual(len(names), len(set(names)))
        self.assertIn("piece_b_replay", names)
        self.assertIn("medical_phi_replay", names)
        self.assertIn("nemotron_pii", names)
        self.assertNotIn("ai4privacy_multilingual", names)
        self.assertIn("br_agentic_pii", names)

    def test_per_profile_threats_match_dataset_count(self):
        report = self._run_default_profile()
        for profile in report["profiles"]:
            if not profile.get("available"):
                continue
            self.assertEqual(
                len(profile["threats"]),
                len(report["threat_datasets"]),
                f"profile {profile['profile']} should have one threat block per dataset",
            )

    def test_per_threat_block_carries_containment_fields(self):
        report = self._run_default_profile()
        required = {
            "path",
            "name",
            "case_count",
            "passed",
            "blocked",
            "sensitive_values_leaked_before",
            "sensitive_values_leaked_after",
            "cases_with_sensitive_values_after",
            "by_detector_family",
        }
        for profile in report["profiles"]:
            if not profile.get("available"):
                continue
            for threat in profile["threats"]:
                missing = required - threat.keys()
                self.assertFalse(
                    missing,
                    f"{profile['profile']}/{threat['name']} missing {missing}",
                )

    def test_signal_to_noise_aggregates_across_threat_corpora(self):
        report = self._run_default_profile()
        for profile in report["profiles"]:
            if not profile.get("available"):
                continue
            family_table = {row["family"]: row for row in profile["by_detector_family"]}
            per_threat_totals: dict[str, int] = {}
            for threat in profile["threats"]:
                for family, count in threat["by_detector_family"].items():
                    per_threat_totals[family] = (
                        per_threat_totals.get(family, 0) + int(count)
                    )
            for family, expected in per_threat_totals.items():
                self.assertEqual(
                    family_table.get(family, {}).get("threat_findings"),
                    expected,
                    f"family {family!r} signal must equal sum across threat corpora",
                )

    def test_missing_threat_dataset_raises_with_path_in_message(self):
        # Programmatic callers (not the CLI) do not get
        # `print(str(exc), file=sys.stderr)` for free — the path needs
        # to live in the exception itself or debugging is painful.
        with self.assertRaises(FileNotFoundError) as ctx:
            release_evaluation(
                profiles=("default",),
                threat_datasets=(Path("evals/does_not_exist.json"),),
                iterations=1,
            )
        self.assertIn("does_not_exist.json", str(ctx.exception))
        self.assertIn("Threat", str(ctx.exception))

    def test_missing_benign_dataset_raises_with_path_in_message(self):
        with self.assertRaises(FileNotFoundError) as ctx:
            release_evaluation(
                profiles=("default",),
                benign_datasets=(Path("evals/does_not_exist_benign.json"),),
                iterations=1,
            )
        self.assertIn("does_not_exist_benign.json", str(ctx.exception))
        self.assertIn("Benign", str(ctx.exception))

    def test_singular_threat_dataset_kwarg_still_works(self):
        # Pre-refactor callers passed `threat_dataset=` (singular). The
        # CLI no longer does, but the kwarg lingers as a thin shim so
        # external scripts holding a single Path don't break silently.
        report = release_evaluation(
            profiles=("default",),
            iterations=3,
            threat_dataset=Path("evals/piece_b_replay.json"),
        )
        self.assertEqual(len(report["threat_datasets"]), 1)
        self.assertEqual(report["threat_datasets"][0]["name"], "piece_b_replay")

    def test_nemotron_pii_corpus_metadata_carries_source_attribution(self):
        report = self._run_default_profile()
        nemotron = next(
            (t for t in report["threat_datasets"] if t["name"] == "nemotron_pii"),
            None,
        )
        self.assertIsNotNone(nemotron)
        self.assertEqual(nemotron["source"], "nvidia/Nemotron-PII")
        self.assertEqual(nemotron["source_license"], "CC-BY-4.0")
        self.assertTrue(nemotron["source_url"].startswith("https://huggingface.co/"))

    def test_markdown_renders_one_row_per_profile_per_threat(self):
        report = self._run_default_profile()
        markdown = format_release_evaluation_markdown(report)
        # Threat-corpus containment section: one row per (profile, threat).
        for profile in report["profiles"]:
            if not profile.get("available"):
                continue
            for threat in profile["threats"]:
                # Every (profile, threat-name) pair must appear in the same row.
                row_marker = f"| {profile['profile']} | {threat['name']} |"
                self.assertIn(
                    row_marker,
                    markdown,
                    f"missing containment row for {profile['profile']}/{threat['name']}",
                )

    def test_markdown_corpus_table_lists_internal_and_external_sources(self):
        report = self._run_default_profile()
        markdown = format_release_evaluation_markdown(report)
        # Internal corpora print "_internal_"; Nemotron-PII prints
        # backticked source plus license.
        self.assertIn("`nvidia/Nemotron-PII` (CC-BY-4.0)", markdown)
        self.assertIn("`guardion/BR-Agentic-PII-Benchmark` (MIT)", markdown)
        self.assertIn("## External Corpus Selection", markdown)
        self.assertIn("BR-Agentic was selected because", markdown)
        self.assertIn("_internal_", markdown)


class DetectionMetricsTests(unittest.TestCase):
    """Pin presidio-research-shaped recall / specificity / F2 metrics."""

    @classmethod
    def setUpClass(cls):
        cls.report = release_evaluation(
            profiles=("default",),
            iterations=3,
        )
        cls.profile = next(
            p for p in cls.report["profiles"] if p["profile"] == "default"
        )

    def test_profile_exposes_detection_metrics_block(self):
        metrics = self.profile.get("detection_metrics")
        self.assertIsNotNone(metrics)
        self.assertIn("benign_specificity", metrics)
        self.assertIn("benign_fp_case_rate", metrics)
        self.assertIn("per_corpus", metrics)

    def test_per_corpus_recall_matches_value_containment_arithmetic(self):
        metrics = self.profile["detection_metrics"]
        per_corpus = {row["name"]: row for row in metrics["per_corpus"]}
        for threat in self.profile["threats"]:
            row = per_corpus.get(threat["name"])
            self.assertIsNotNone(row)
            before = threat["sensitive_values_leaked_before"]
            after = threat["sensitive_values_leaked_after"]
            if before == 0:
                self.assertIsNone(row["value_recall"])
                continue
            expected = (before - after) / before
            self.assertAlmostEqual(row["value_recall"], expected, places=6)

    def test_specificity_is_one_when_benign_corpora_pass_uniformly(self):
        # The default profile keeps every benign case passing on the
        # bundled corpora; if that ever changes this test surfaces it.
        for benign in self.profile["benign"]:
            self.assertEqual(benign["failed"], 0, f"{benign['name']} regressed FPs")
        self.assertAlmostEqual(
            self.profile["detection_metrics"]["benign_specificity"], 1.0, places=6
        )

    def test_f2_falls_within_zero_one_bounds(self):
        # F-beta is only bounded by [min(P,R), max(P,R)] at β=1; for
        # β≠1 the only reliable invariant is 0 ≤ F2 ≤ 1 when both
        # inputs are in [0, 1].
        metrics = self.profile["detection_metrics"]
        specificity = metrics["benign_specificity"]
        for row in metrics["per_corpus"]:
            recall = row["value_recall"]
            f2 = row["f2"]
            if recall is None or specificity is None:
                self.assertIsNone(f2)
                continue
            if recall == 0 or specificity == 0:
                self.assertEqual(f2, 0.0)
                continue
            self.assertGreaterEqual(f2, 0.0)
            self.assertLessEqual(f2, 1.0 + 1e-9)

    def test_f2_weights_recall_more_than_specificity(self):
        # Sanity-check β=2 weighting: a (recall=0.5, spec=0.9) point
        # should score lower than (recall=0.9, spec=0.5) under F2,
        # because F2 is recall-weighted.
        from lsdf.release_eval import _f_beta

        recall_heavy = _f_beta(0.9, 0.5, beta=2.0)
        spec_heavy = _f_beta(0.5, 0.9, beta=2.0)
        self.assertGreater(recall_heavy, spec_heavy)

    def test_per_entity_recall_is_case_level(self):
        rows = self.profile.get("entity_recall") or []
        self.assertGreater(len(rows), 0)
        for row in rows:
            self.assertIn("entity", row)
            self.assertIn("expected_cases", row)
            self.assertIn("contained_cases", row)
            self.assertIn("containment_recall", row)
            self.assertIn("exact_tag_cases", row)
            self.assertIn("exact_tag_recall", row)
            # Backward-compatible aliases for the pre-split exact-tag metric.
            self.assertIn("detected_cases", row)
            self.assertIn("recall", row)
            self.assertEqual(row["detected_cases"], row["exact_tag_cases"])
            self.assertEqual(row["recall"], row["exact_tag_recall"])
            self.assertGreaterEqual(row["expected_cases"], row["contained_cases"])
            self.assertGreaterEqual(row["expected_cases"], row["exact_tag_cases"])
            if row["expected_cases"] == 0:
                self.assertIsNone(row["containment_recall"])
                self.assertIsNone(row["exact_tag_recall"])
            else:
                self.assertAlmostEqual(
                    row["containment_recall"],
                    row["contained_cases"] / row["expected_cases"],
                    places=6,
                )
                self.assertAlmostEqual(
                    row["exact_tag_recall"],
                    row["exact_tag_cases"] / row["expected_cases"],
                    places=6,
                )

    def test_per_entity_recall_orders_by_expected_count_desc(self):
        rows = self.profile.get("entity_recall") or []
        expected_counts = [row["expected_cases"] for row in rows]
        self.assertEqual(
            expected_counts, sorted(expected_counts, reverse=True),
            "entity_recall must sort by expected_cases desc for at-a-glance reading",
        )

    def test_markdown_includes_detection_metrics_and_entity_recall_sections(self):
        markdown = format_release_evaluation_markdown(self.report)
        self.assertIn("## Release Gate", markdown)
        self.assertIn("## Detection metrics", markdown)
        self.assertIn("presidio-research", markdown)
        self.assertIn("## Per-entity-type containment and exact-tag recall", markdown)
        self.assertIn("Contained cases", markdown)
        self.assertIn("Exact-tag cases", markdown)
        self.assertIn("Exact tags measure attribution, not leak prevention", markdown)

    def test_markdown_cross_references_system_recall_artifact(self):
        markdown = format_release_evaluation_markdown(self.report)

        self.assertIn("## System-level detector recall", markdown)
        self.assertIn("See `docs/system-recall.md`", markdown)
        self.assertIn("engine-capability contract", markdown)
        self.assertNotIn("forthcoming", markdown)

    def test_gate_promise_corpora_match_v02_release_gate_source_dict(self):
        actual = {}
        for profile_name in V02_RELEASE_GATED_CORPORA_BY_PROFILE:
            promise = load_policy_profile(profile_name).gate_promise
            self.assertIsNotNone(promise)
            actual[profile_name] = promise.corpora

        self.assertEqual(actual, V02_RELEASE_GATED_CORPORA_BY_PROFILE)

    def test_release_gated_profiles_are_discovered_from_profile_yaml(self):
        self.assertEqual(
            set(release_gated_profile_names()),
            set(V02_RELEASE_GATED_CORPORA_BY_PROFILE),
        )

    def test_profiles_without_gate_promise_are_not_release_gated(self):
        from lsdf.release_eval import _release_gate

        for profile_name in ("default", "balanced", "monitor", "dev", "strict"):
            self.assertIsNone(load_policy_profile(profile_name).gate_promise)

        gate = _release_gate(
            [
                {
                    "profile": "default",
                    "available": True,
                    "gate_promise": None,
                    "detection_metrics": {
                        "benign_specificity": 0.0,
                        "per_corpus": [],
                    },
                }
            ]
        )

        self.assertTrue(gate["passed"])
        self.assertEqual(gate["profiles"], [])

    def test_release_eval_keeps_unavailable_gated_profile_in_gate(self):
        with mock.patch(
            "lsdf.release_eval.load_policy_profile",
            side_effect=ValueError("broken profile"),
        ), mock.patch(
            "lsdf.release_eval.load_effective_policy",
            side_effect=ValueError("broken fallback"),
        ):
            report = release_evaluation(
                profiles=("broad-pii",),
                threat_dataset=Path("evals/piece_b_replay.json"),
                iterations=1,
            )

        gate = report["release_gate"]
        self.assertFalse(gate["passed"])
        self.assertEqual(gate["profiles"][0]["profile"], "broad-pii")
        self.assertIn("profile unavailable", gate["profiles"][0]["failures"])

    def _gate_promise(self, profile_name: str) -> dict[str, object]:
        promise = load_policy_profile(profile_name).gate_promise
        self.assertIsNotNone(promise)
        return promise.as_dict()

    def test_release_gate_asserts_recall_and_specificity_floors(self):
        from lsdf.release_eval import _release_gate

        profiles = []
        for name in ("broad-pii", "broad-pii-ml"):
            profiles.append(
                {
                    "profile": name,
                    "available": True,
                    "gate_promise": self._gate_promise(name),
                    "detection_metrics": {
                        "benign_specificity": 0.95,
                        "per_corpus": [
                            {"name": "piece_b_replay", "value_recall": 0.90},
                            {"name": "medical_phi_replay", "value_recall": 0.91},
                            {"name": "br_agentic_pii", "value_recall": 0.92},
                        ],
                    },
                }
            )

        gate = _release_gate(profiles)

        self.assertTrue(gate["passed"])

    def test_release_gate_fails_when_required_corpus_is_missing(self):
        from lsdf.release_eval import _release_gate

        profiles = [
            {
                "profile": "broad-pii",
                "available": True,
                "gate_promise": self._gate_promise("broad-pii"),
                "detection_metrics": {
                    "benign_specificity": 0.95,
                    "per_corpus": [
                        {"name": "nemotron_pii", "value_recall": 0.99},
                        {"name": "ai4privacy_multilingual", "value_recall": 0.99},
                    ],
                },
            }
        ]

        gate = _release_gate(profiles)

        self.assertFalse(gate["passed"])
        failures = " ".join(" ".join(row["failures"]) for row in gate["profiles"])
        self.assertIn("piece_b_replay recall missing", failures)
        self.assertIn("medical_phi_replay recall missing", failures)
        self.assertIn("br_agentic_pii recall missing", failures)

    def test_release_gate_does_not_gate_broad_profiles_on_external_multilingual(self):
        from lsdf.release_eval import _release_gate

        profiles = [
            {
                "profile": "broad-pii",
                "available": True,
                "gate_promise": self._gate_promise("broad-pii"),
                "detection_metrics": {
                    "benign_specificity": 0.95,
                    "per_corpus": [
                        {"name": "piece_b_replay", "value_recall": 0.90},
                        {"name": "medical_phi_replay", "value_recall": 0.91},
                        {"name": "br_agentic_pii", "value_recall": 0.92},
                        {"name": "nemotron_pii", "value_recall": 0.10},
                        {"name": "ai4privacy_multilingual", "value_recall": 0.10},
                    ],
                },
            }
        ]

        gate = _release_gate(profiles)

        self.assertTrue(gate["passed"])
        self.assertEqual(gate["profiles"][0]["failures"], [])

    def test_release_gate_fails_healthcare_when_nemotron_below_floor(self):
        from lsdf.release_eval import _release_gate

        profiles = [
            {
                "profile": "healthcare",
                "available": True,
                "gate_promise": self._gate_promise("healthcare"),
                "detection_metrics": {
                    "benign_specificity": 0.95,
                    "per_corpus": [
                        {"name": "piece_b_replay", "value_recall": 0.90},
                        {"name": "medical_phi_replay", "value_recall": 0.91},
                        {"name": "br_agentic_pii", "value_recall": 0.92},
                        {"name": "nemotron_pii", "value_recall": 0.89},
                        {"name": "ai4privacy_multilingual", "value_recall": 0.91},
                    ],
                },
            }
        ]

        gate = _release_gate(profiles)

        self.assertFalse(gate["passed"])
        failures = " ".join(" ".join(row["failures"]) for row in gate["profiles"])
        self.assertIn("nemotron_pii recall", failures)
        self.assertNotIn("ai4privacy_multilingual recall", failures)

    def test_healthcare_gate_fails_when_external_corpus_is_not_supplied(self):
        from lsdf.release_eval import _release_gate

        promise = self._gate_promise("healthcare")
        gate = _release_gate([{
            "profile": "healthcare",
            "available": True,
            "gate_promise": promise,
            "detection_metrics": {
                "benign_specificity": 1.0,
                "per_corpus": [
                    {"name": name, "value_recall": 1.0}
                    for name in promise["corpora"]
                    if name != "ai4privacy_multilingual"
                ],
            },
        }])
        self.assertFalse(gate["passed"])
        self.assertEqual(
            gate["profiles"][0]["failures"],
            ["ai4privacy_multilingual recall missing"],
        )

    def test_release_gate_fails_healthcare_when_ai4privacy_below_floor(self):
        from lsdf.release_eval import _release_gate

        profiles = [
            {
                "profile": "healthcare",
                "available": True,
                "gate_promise": self._gate_promise("healthcare"),
                "detection_metrics": {
                    "benign_specificity": 0.95,
                    "per_corpus": [
                        {"name": "piece_b_replay", "value_recall": 0.90},
                        {"name": "medical_phi_replay", "value_recall": 0.91},
                        {"name": "br_agentic_pii", "value_recall": 0.92},
                        {"name": "nemotron_pii", "value_recall": 0.91},
                        {"name": "ai4privacy_multilingual", "value_recall": 0.89},
                    ],
                },
            }
        ]

        gate = _release_gate(profiles)

        self.assertFalse(gate["passed"])
        failures = " ".join(" ".join(row["failures"]) for row in gate["profiles"])
        self.assertIn("ai4privacy_multilingual recall", failures)
        self.assertNotIn("nemotron_pii recall", failures)

    def test_release_gate_fails_below_any_floor(self):
        from lsdf.release_eval import _release_gate

        profiles = [
            {
                "profile": "broad-pii",
                "available": True,
                "gate_promise": self._gate_promise("broad-pii"),
                "detection_metrics": {
                    "benign_specificity": 0.94,
                    "per_corpus": [
                        {"name": "piece_b_replay", "value_recall": 0.90},
                        {"name": "medical_phi_replay", "value_recall": 0.91},
                        {"name": "br_agentic_pii", "value_recall": 0.92},
                    ],
                },
            },
            {
                "profile": "broad-pii-ml",
                "available": True,
                "gate_promise": self._gate_promise("broad-pii-ml"),
                "detection_metrics": {
                    "benign_specificity": 0.95,
                    "per_corpus": [
                        {"name": "piece_b_replay", "value_recall": 0.89},
                        {"name": "medical_phi_replay", "value_recall": 0.91},
                        {"name": "br_agentic_pii", "value_recall": 0.92},
                    ],
                },
            },
        ]

        gate = _release_gate(profiles)

        self.assertFalse(gate["passed"])
        failures = " ".join(" ".join(row["failures"]) for row in gate["profiles"])
        self.assertIn("specificity", failures)
        self.assertIn("piece_b_replay recall", failures)

    def test_entity_recall_is_robust_to_cases_missing_an_id(self):
        # Two id-less cases must not collide into a single by_id[None]
        # slot. We feed `_accumulate_entity_recall` directly with a
        # synthetic pair: case A's expected entity is detected, case B
        # is not. The accumulator should advance `expected` by 2 and
        # `detected` by exactly 1 (whichever case actually matched).
        from lsdf.release_eval import _accumulate_entity_recall

        accumulator: dict[str, dict[str, int]] = {}
        cases = [
            {"id": None, "expected_entities": ["EMAIL"]},
            {"id": None, "expected_entities": ["EMAIL"]},
        ]
        case_results = [
            {"id": None, "finding_entities": ["EMAIL"]},
            {"id": None, "finding_entities": []},
        ]
        _accumulate_entity_recall(accumulator, cases, case_results)
        # Both cases skipped — the function refuses to silently crosswire
        # id-less rows. Accumulator stays empty rather than reporting a
        # spurious 2-of-2 hit.
        self.assertEqual(accumulator, {})

    def test_entity_recall_splits_containment_from_exact_tagging(self):
        from lsdf.release_eval import _accumulate_entity_recall

        accumulator: dict[str, dict[str, int]] = {}
        cases = [
            {"id": "blocked-broad", "expected_entities": ["MRN", "DATE_OF_BIRTH"]},
            {"id": "redacted-broad", "expected_entities": ["BANK_ACCOUNT"]},
            {"id": "tagged-but-leaked", "expected_entities": ["EMAIL"]},
        ]
        case_results = [
            {
                "id": "blocked-broad",
                "blocked": True,
                "finding_entities": ["OTHER_PHI"],
                "sensitive_values_leaked_before_count": 2,
                "sensitive_values_leaked_after_count": 0,
            },
            {
                "id": "redacted-broad",
                "blocked": False,
                "finding_entities": ["OTHER_PHI"],
                "sensitive_values_leaked_before_count": 1,
                "sensitive_values_leaked_after_count": 0,
            },
            {
                "id": "tagged-but-leaked",
                "blocked": False,
                "finding_entities": ["EMAIL"],
                "sensitive_values_leaked_before_count": 1,
                "sensitive_values_leaked_after_count": 1,
            },
        ]

        _accumulate_entity_recall(accumulator, cases, case_results)

        self.assertEqual(
            accumulator["MRN"], {"expected": 1, "contained": 1, "exact_tag": 0}
        )
        self.assertEqual(
            accumulator["DATE_OF_BIRTH"],
            {"expected": 1, "contained": 1, "exact_tag": 0},
        )
        self.assertEqual(
            accumulator["BANK_ACCOUNT"],
            {"expected": 1, "contained": 1, "exact_tag": 0},
        )
        self.assertEqual(
            accumulator["EMAIL"], {"expected": 1, "contained": 0, "exact_tag": 1}
        )


class BrAgenticPIICorpusShapeTests(unittest.TestCase):
    """Pin the on-disk Brazilian Portuguese agentic PII corpus shape."""

    @classmethod
    def setUpClass(cls):
        cls.payload = json.loads(
            Path("evals/br_agentic_pii.json").read_text(encoding="utf-8")
        )

    def test_corpus_metadata_carries_source_attribution_and_selection_note(self):
        self.assertEqual(self.payload["name"], "br_agentic_pii")
        self.assertEqual(self.payload["source"], "guardion/BR-Agentic-PII-Benchmark")
        self.assertEqual(self.payload["source_license"], "MIT")
        self.assertEqual(
            self.payload["source_url"],
            "https://huggingface.co/datasets/guardion/BR-Agentic-PII-Benchmark",
        )
        self.assertIn("PIIBench", self.payload["selection_note"])
        self.assertIn("agent tool arguments/results", self.payload["selection_note"])

    def test_sample_uses_customer_registration_slice(self):
        self.assertEqual(self.payload["case_count"], 8)
        self.assertEqual(self.payload["scenarios"], ["atualizacao_cadastral"])
        self.assertEqual(self.payload["language"], "Portuguese")
        self.assertEqual(self.payload["locale"], "pt_BR")
        for case in self.payload["cases"]:
            self.assertEqual(case["scenario"], "atualizacao_cadastral")
            self.assertEqual(case["language"], "Portuguese")
            self.assertEqual(case["locale"], "pt_BR")

    def test_case_shape_preserves_lsdf_fields_and_strips_source_spans(self):
        required = {
            "id",
            "category",
            "surface",
            "payload",
            "sensitive_values",
            "expected_entities",
            "expected_surfaces",
            "expected_absent",
            "br_agentic_labels",
            "scenario",
            "language",
            "locale",
        }
        for case in self.payload["cases"]:
            missing = required - case.keys()
            self.assertFalse(missing, f"{case.get('id')} missing {missing}")
            for message in case["payload"]["messages"]:
                self.assertNotIn("pii_spans", message)

    def test_labels_and_surfaces_cover_agentic_pii_gap(self):
        labels = self.payload["by_source_label_count"]
        self.assertGreaterEqual(labels.get("CPF", 0), 1)
        self.assertGreaterEqual(labels.get("PERSON_NAME", 0), 1)
        self.assertGreaterEqual(labels.get("PHONE_NUMBER", 0), 1)
        self.assertGreaterEqual(labels.get("STREET_ADDRESS", 0), 1)
        self.assertGreaterEqual(labels.get("EMAIL", 0), 1)
        surfaces = self.payload["by_surface_count"]
        self.assertGreaterEqual(surfaces.get("input.messages", 0), 1)
        self.assertGreaterEqual(surfaces.get("input.tool_results", 0), 1)
        self.assertGreaterEqual(surfaces.get("output.tool_calls.arguments", 0), 1)

    def test_known_gap_labels_only_appear_when_unmapped_label_present(self):
        from scripts.build_br_agentic_pii_corpus import BR_AGENTIC_TO_LSDF

        for case in self.payload["cases"]:
            for label in case.get("known_gap_labels", []):
                self.assertNotIn(
                    label,
                    BR_AGENTIC_TO_LSDF,
                    f"{case['id']} marks {label!r} as gap but it is mapped",
                )

    def test_builder_defaults_to_committed_snapshot_without_network(self):
        from scripts import build_br_agentic_pii_corpus as builder

        with tempfile.TemporaryDirectory() as tempdir:
            output_path = Path(tempdir) / "br_agentic_pii.json"
            with mock.patch.object(
                builder.urllib.request,
                "urlopen",
                side_effect=AssertionError("network should be opt-in"),
            ):
                status = builder.main(["--output", str(output_path)])

            self.assertEqual(status, 0)
            copied = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(copied["name"], "br_agentic_pii")
            self.assertEqual(copied["case_count"], self.payload["case_count"])


class Ai4PrivacyLocalBuilderTests(unittest.TestCase):
    """Exercise conversion with independently authored miniature source files."""

    @staticmethod
    def _source_row(index=0):
        return {
            "id": f"owned-example-{index}",
            "source_text": "Fixture contact: Zenvora; favorite color: violet.",
            "privacy_mask": [
                {"label": "GIVENNAME1", "value": "Zenvora"},
                {"label": "OWNED_UNMAPPED", "value": "violet"},
            ],
        }

    def test_local_conversion_preserves_known_and_unknown_annotations(self):
        from scripts import build_ai4privacy_multilingual_corpus as builder

        for literal_string in (False, True):
            with self.subTest(literal_string=literal_string):
                source = self._source_row()
                if literal_string:
                    source["privacy_mask"] = repr(source["privacy_mask"])
                case = builder.to_case(source, "Dutch")
                self.assertEqual(case["language"], "Dutch")
                self.assertEqual(case["expected_entities"], ["PERSON"])
                self.assertEqual(case["known_gap_labels"], ["OWNED_UNMAPPED"])
                self.assertEqual(case["sensitive_values"], ["Zenvora", "violet"])

    def test_sampling_is_deterministic_and_obeys_local_scan_budget(self):
        from scripts import build_ai4privacy_multilingual_corpus as builder

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.jsonl"
            source.write_text(
                "\n".join(json.dumps(self._source_row(i)) for i in range(6)),
                encoding="utf-8",
            )
            first = builder.sample_one_language(source, 2, 7, 3)
            self.assertEqual(first, builder.sample_one_language(source, 2, 7, 3))
        self.assertEqual(len(first), 2)
        self.assertTrue({row["id"] for row in first} <= {
            "owned-example-0", "owned-example-1", "owned-example-2",
        })

    def test_builder_reads_supplied_languages_and_defaults_to_local_output(self):
        from scripts import build_ai4privacy_multilingual_corpus as builder

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = root / "supplied"
            for relative_path in builder.LANGUAGES.values():
                source = inputs / relative_path
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text(json.dumps(self._source_row()) + "\n", encoding="utf-8")
            output_root = root / ".lsdf" / "external-benchmarks"
            with mock.patch.object(builder, "OUTPUT_ROOT", output_root), mock.patch("builtins.print"):
                builder.main([
                    "--input-dir", str(inputs), "--cases-per-language", "1",
                    "--source-license", "Apache-2.0", "--source-revision", "owned-mini-v1",
                ])
            payload = json.loads((output_root / "ai4privacy_multilingual.json").read_text(encoding="utf-8"))
        self.assertEqual(len(payload["cases"]), len(builder.LANGUAGES))
        self.assertEqual(set(payload["by_language_count"]), set(builder.LANGUAGES))
        self.assertEqual(payload["source_license"], "Apache-2.0")
        self.assertEqual(payload["source_revision"], "owned-mini-v1")
        self.assertIn("grants no rights", payload["license_note"])

    def test_builder_requires_explicit_local_input(self):
        from scripts import build_ai4privacy_multilingual_corpus as builder

        with mock.patch("sys.stderr"), self.assertRaises(SystemExit) as raised:
            builder.main([
                "--source-license", "Apache-2.0", "--source-revision", "owned-mini-v1",
            ])
        self.assertEqual(raised.exception.code, 2)

    def test_builder_requires_each_source_provenance_field(self):
        from scripts import build_ai4privacy_multilingual_corpus as builder

        for missing, supplied in (
            ("--source-license", ["--source-revision", "owned-mini-v1"]),
            ("--source-revision", ["--source-license", "Apache-2.0"]),
        ):
            with self.subTest(missing=missing):
                stderr = io.StringIO()
                with mock.patch("sys.stderr", stderr), self.assertRaises(SystemExit) as raised:
                    builder.main(["--input-dir", ".lsdf/not-read", *supplied])
                self.assertEqual(raised.exception.code, 2)
                self.assertIn(missing, stderr.getvalue())

    def test_builder_rejects_blank_source_provenance(self):
        from scripts import build_ai4privacy_multilingual_corpus as builder

        for source_license, source_revision in (
            ("", "owned-mini-v1"), ("   ", "owned-mini-v1"),
            ("Apache-2.0", ""), ("Apache-2.0", "   "),
        ):
            with self.subTest(source_license=source_license, source_revision=source_revision):
                stderr = io.StringIO()
                with mock.patch("sys.stderr", stderr), self.assertRaises(SystemExit) as raised:
                    builder.main([
                        "--input-dir", ".lsdf/not-read", "--source-license", source_license,
                        "--source-revision", source_revision,
                    ])
                self.assertEqual(raised.exception.code, 2)
                self.assertIn("must not be blank", stderr.getvalue())

    def test_missing_local_source_does_not_create_output(self):
        from scripts import build_ai4privacy_multilingual_corpus as builder

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_root = root / ".lsdf" / "external-benchmarks"
            with mock.patch.object(builder, "OUTPUT_ROOT", output_root), mock.patch("sys.stderr"):
                with self.assertRaises(SystemExit) as raised:
                    builder.main([
                        "--input-dir", str(root / "missing"),
                        "--source-license", "Apache-2.0", "--source-revision", "owned-mini-v1",
                    ])
            self.assertEqual(raised.exception.code, 2)
            self.assertFalse(output_root.exists())

    def test_builder_refuses_output_outside_ignored_benchmark_directory(self):
        from scripts import build_ai4privacy_multilingual_corpus as builder

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_root = root / ".lsdf" / "external-benchmarks"
            with mock.patch.object(builder, "OUTPUT_ROOT", output_root), mock.patch("sys.stderr"):
                with self.assertRaises(SystemExit) as raised:
                    builder.main([
                        "--input-dir", str(root), "--output", str(root / "evals" / "restricted.json"),
                        "--source-license", "Apache-2.0", "--source-revision", "owned-mini-v1",
                    ])
            self.assertEqual(raised.exception.code, 2)
            self.assertFalse((root / "evals").exists())


class NemotronPIICorpusShapeTests(unittest.TestCase):
    """Pin the on-disk Nemotron-PII corpus shape so re-sampling stays stable."""

    @classmethod
    def setUpClass(cls):
        cls.payload = json.loads(
            Path("evals/nemotron_pii.json").read_text(encoding="utf-8")
        )

    def test_corpus_has_expected_top_level_metadata(self):
        self.assertEqual(self.payload["name"], "nemotron_pii")
        self.assertEqual(self.payload["source"], "nvidia/Nemotron-PII")
        self.assertEqual(self.payload["source_license"], "CC-BY-4.0")
        self.assertTrue(
            self.payload["source_url"].startswith("https://huggingface.co/")
        )

    def test_each_case_carries_lsdf_corpus_fields(self):
        cases = self.payload["cases"]
        self.assertGreater(len(cases), 50)
        required = {
            "id",
            "category",
            "surface",
            "payload",
            "sensitive_values",
            "expected_entities",
            "expected_surfaces",
            "expected_absent",
            "nemotron_labels",
            "domain",
            "document_format",
            "locale",
        }
        for case in cases:
            missing = required - case.keys()
            self.assertFalse(missing, f"{case.get('id')} missing {missing}")

    def test_categories_only_use_known_lsdf_buckets(self):
        allowed = {"credentials", "phi", "financial", "pii", "other"}
        for case in self.payload["cases"]:
            self.assertIn(case["category"], allowed)

    def test_known_gap_labels_only_appear_when_unmapped_label_present(self):
        # If `known_gap_labels` is present, every label in it must be
        # absent from the LSDF entity-vocabulary mapping. This catches
        # mapping-table drift before it silently shrinks coverage.
        from scripts.build_nemotron_pii_corpus import NEMOTRON_TO_LSDF

        for case in self.payload["cases"]:
            for label in case.get("known_gap_labels", []):
                self.assertNotIn(
                    label,
                    NEMOTRON_TO_LSDF,
                    f"{case['id']} marks {label!r} as gap but it is mapped",
                )


if __name__ == "__main__":
    unittest.main()
