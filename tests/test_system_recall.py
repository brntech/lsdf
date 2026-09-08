import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from lsdf.system_recall import (
    FoundationResult,
    _gliner_label,
    _mock_spans_by_text,
    append_system_recall_history,
    current_commit_sha,
    evaluate_foundation_fixtures,
    format_system_recall_markdown,
    regenerate_system_recall,
)


class SystemRecallTests(unittest.TestCase):
    def test_format_system_recall_markdown_renders_summary_and_full_matrix(self):
        markdown = format_system_recall_markdown(
            [
                FoundationResult(
                    detector="regex.jwt",
                    corpus="foundation",
                    entity="JWT",
                    recall=1.0,
                    specificity=0.75,
                    tp=2,
                    fn=0,
                    fp=1,
                    tn=3,
                )
            ],
            generated_at="2026-05-07T00:00:00Z",
            commit_sha="abc1234",
        )

        self.assertIn("# LSDF System Recall", markdown)
        self.assertIn("_Generated 2026-05-07T00:00:00Z. Commit abc1234._", markdown)
        self.assertIn("## Summary - active-profile detectors", markdown)
        self.assertIn("## Full matrix", markdown)
        self.assertIn(
            "## Gaps - gated profile entities without an in-scope foundation floor",
            markdown,
        )
        self.assertIn(
            "| regex.jwt | JWT | foundation | 1.000 | 0.750 | not declared | 2 | 0 | 1 | 3 |",
            markdown,
        )

    def test_format_system_recall_markdown_renders_out_of_scope_distinctly(self):
        markdown = format_system_recall_markdown(
            [
                FoundationResult(
                    detector="contextual.xml_identity",
                    corpus="foundation",
                    entity="PASSPORT",
                    recall=0.0,
                    specificity=1.0,
                    tp=0,
                    fn=4,
                    fp=0,
                    tn=3,
                )
            ],
            out_of_scope=[
                {
                    "detector": "contextual.xml_identity",
                    "corpus": "foundation",
                    "entity": "PASSPORT",
                    "out_of_scope": True,
                }
            ],
        )

        self.assertIn(
            "| contextual.xml_identity | PASSPORT | foundation | 0.000 | 1.000 | "
            "N/A - engine does not target | 0 | 4 | 0 | 3 |",
            markdown,
        )

    def test_format_system_recall_markdown_can_render_summary_only(self):
        markdown = format_system_recall_markdown(
            [
                FoundationResult(
                    detector="regex.jwt",
                    corpus="foundation",
                    entity="JWT",
                    recall=1.0,
                    specificity=1.0,
                    tp=2,
                    fn=0,
                    fp=0,
                    tn=2,
                ),
                FoundationResult(
                    detector="xpia.indirect_injection",
                    corpus="foundation",
                    entity="PROMPT_INJECTION",
                    recall=1.0,
                    specificity=1.0,
                    tp=2,
                    fn=0,
                    fp=0,
                    tn=2,
                ),
            ],
            coverage_gaps={
                "count": 0,
                "pairs": [],
                "active_pairs": [
                    {
                        "detector": "regex.jwt",
                        "entity": "JWT",
                        "profiles": ["broad-pii"],
                    }
                ],
            },
            include_full_matrix=False,
            include_gaps=False,
        )

        self.assertIn("## Summary - active-profile detectors", markdown)
        self.assertIn("| regex.jwt | JWT | foundation |", markdown)
        self.assertNotIn("| xpia.indirect_injection | PROMPT_INJECTION | foundation |", markdown)
        self.assertNotIn("## Full matrix", markdown)
        self.assertNotIn(
            "## Gaps - gated profile entities without an in-scope foundation floor",
            markdown,
        )

    def test_append_system_recall_history_writes_only_aggregate_schema(self):
        row = FoundationResult(
            detector="regex.jwt",
            corpus="foundation",
            entity="JWT",
            recall=1.0,
            specificity=1.0,
            tp=1,
            fn=0,
            fp=0,
            tn=1,
        )
        with TemporaryDirectory() as tmpdir:
            history_path = Path(tmpdir, "system-recall-history.jsonl")
            append_system_recall_history(
                [row],
                history_path=history_path,
                timestamp="2026-05-07T00:00:00Z",
                commit_sha="abc1234",
            )

            record = json.loads(history_path.read_text(encoding="utf-8"))

        self.assertEqual(
            set(record),
            {
                "timestamp",
                "commit_sha",
                "detector",
                "corpus",
                "entity",
                "recall",
                "specificity",
                "tp",
                "fn",
                "fp",
                "tn",
            },
        )
        self.assertEqual(record["detector"], "regex.jwt")
        self.assertEqual(record["entity"], "JWT")

    def test_current_commit_sha_fallback_uses_12_char_git_prefix(self):
        with patch.dict("os.environ", {}, clear=True), patch(
            "lsdf.system_recall.subprocess.run"
        ) as run:
            run.return_value.stdout = "abcdef123456\n"

            commit = current_commit_sha()

        self.assertEqual(commit, "abcdef123456")
        self.assertIn("--short=12", run.call_args.args[0])

    def test_regenerate_system_recall_writes_markdown_and_history(self):
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            fixture_root = root / "fixtures"
            fixture_dir = fixture_root / "regex.jwt"
            fixture_dir.mkdir(parents=True)
            (fixture_dir / "JWT.json").write_text(
                json.dumps(
                    {
                        "detector": "regex.jwt",
                        "entity": "JWT",
                        "description": "Small synthetic JWT fixture.",
                        "cases": [
                            {
                                "id": "jwt-positive",
                                "role": "positive",
                                "text": (
                                    "Authorization token "
                                    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                                    "eyJzdWIiOiJ0ZXN0In0."
                                    "c2lnbmF0dXJlLXBhZGRpbmctMTIz"
                                ),
                            },
                            {
                                "id": "jwt-negative",
                                "role": "negative",
                                "text": "Authorization token was rotated by the service account.",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            output_path = root / "docs" / "system-recall.md"
            history_path = root / "docs" / "system-recall-history.jsonl"

            report = regenerate_system_recall(
                output_path=output_path,
                history_path=history_path,
                fixture_root=fixture_root,
                generated_at="2026-05-07T00:00:00Z",
                commit_sha="abc1234",
            )

            markdown = output_path.read_text(encoding="utf-8")
            history_lines = history_path.read_text(encoding="utf-8").splitlines()

        self.assertEqual(len(report["results"]), 1)
        self.assertIn("regex.jwt", markdown)
        self.assertEqual(len(history_lines), 1)
        self.assertEqual(json.loads(history_lines[0])["commit_sha"], "abc1234")

    def test_foundation_fixture_evaluator_exercises_committed_fixture_tree(self):
        rows = evaluate_foundation_fixtures()
        self.assertGreater(len(rows), 100)
        self.assertTrue(any(row.detector == "regex.jwt" and row.entity == "JWT" for row in rows))

    def test_missing_fixture_root_fails_instead_of_rendering_empty_contract(self):
        with self.assertRaises(FileNotFoundError):
            evaluate_foundation_fixtures(fixture_root=Path("does/not/exist"))

    def test_empty_fixture_root_fails_instead_of_rendering_empty_contract(self):
        with TemporaryDirectory() as tmpdir:
            with self.assertRaisesRegex(ValueError, "no foundation fixtures"):
                evaluate_foundation_fixtures(fixture_root=Path(tmpdir))

    def test_mock_optional_adapter_spans_are_capability_aware(self):
        fixture = {
            "detector": "gliner.pii_phi",
            "entity": "PERSON",
            "description": "Capability-aware fake smoke fixture.",
            "cases": [
                {
                    "id": "positive-match",
                    "role": "positive",
                    "text": "Synthetic intake mentions Alice Rowan.",
                },
                {
                    "id": "positive-miss",
                    "role": "positive",
                    "text": "Synthetic intake mentions the assigned reviewer.",
                },
                {
                    "id": "negative-lookalike",
                    "role": "negative",
                    "text": "The test product codename Alice Rowan is not a person field.",
                },
                {
                    "id": "negative-clear",
                    "role": "negative",
                    "text": "The demo ticket was intentionally left blank.",
                },
            ],
        }

        spans = _mock_spans_by_text(fixture, _gliner_label)

        self.assertIn("Synthetic intake mentions Alice Rowan.", spans)
        self.assertNotIn("Synthetic intake mentions the assigned reviewer.", spans)
        self.assertIn(
            "The test product codename Alice Rowan is not a person field.",
            spans,
        )
        self.assertNotIn("The demo ticket was intentionally left blank.", spans)

    def test_committed_optional_adapter_rows_have_specificity_signal(self):
        rows = {
            (row.detector, row.entity): row
            for row in evaluate_foundation_fixtures()
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


if __name__ == "__main__":
    unittest.main()
