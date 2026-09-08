"""Audit retention sweeps over rotated JSONL backups.

Pins the contract for `purge_rotated_audit_files`:

  - Operates on rotated backups only (``<path>.<int>``); never the live
    audit file at ``path``.
  - Time comparison uses each file's mtime against an injectable ``now``.
  - ``dry_run=True`` classifies but never deletes, exercising the same
    code path so a preview-vs-real divergence cannot silently appear.
  - Per-file errors are collected in ``errors`` rather than aborting the
    sweep, so one permission-denied file does not block deletion of the
    rest.
  - Negative ``older_than_days`` raises ``ValueError`` (defensive — there
    is no honest interpretation of a negative retention window).
"""

import io
import json
import os
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from lsdf.audit import purge_rotated_audit_files
from lsdf.cli import main


def _touch(path: Path, *, age_days: float, content: str = "{}\n") -> None:
    path.write_text(content, encoding="utf-8")
    when = datetime.now(timezone.utc) - timedelta(days=age_days)
    timestamp = when.timestamp()
    os.utime(path, (timestamp, timestamp))


class PurgeRotatedAuditFilesTests(unittest.TestCase):
    def test_deletes_rotated_files_older_than_cutoff(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp) / "audit.jsonl"
            base.write_text("{}\n", encoding="utf-8")  # live file
            _touch(base.with_suffix(".jsonl.1"), age_days=10)
            _touch(base.with_suffix(".jsonl.2"), age_days=40)
            _touch(base.with_suffix(".jsonl.3"), age_days=90)

            report = purge_rotated_audit_files(base, older_than_days=30)

            deleted_paths = {entry["path"] for entry in report["deleted"]}
            kept_paths = {entry["path"] for entry in report["kept"]}
            self.assertEqual(
                deleted_paths,
                {str(base.with_suffix(".jsonl.2")), str(base.with_suffix(".jsonl.3"))},
            )
            self.assertEqual(kept_paths, {str(base.with_suffix(".jsonl.1"))})
            self.assertEqual(report["errors"], [])
            self.assertFalse(base.with_suffix(".jsonl.2").exists())
            self.assertFalse(base.with_suffix(".jsonl.3").exists())
            self.assertTrue(base.with_suffix(".jsonl.1").exists())

    def test_never_touches_the_live_audit_file_even_when_old(self):
        # The live file is the append-only contract anchor — retention sweeps
        # must never delete it, even if its mtime is far past the cutoff.
        with TemporaryDirectory() as tmp:
            base = Path(tmp) / "audit.jsonl"
            _touch(base, age_days=365)

            report = purge_rotated_audit_files(base, older_than_days=30)

            self.assertEqual(report["deleted"], [])
            self.assertEqual(report["kept"], [])
            self.assertTrue(base.exists())

    def test_dry_run_classifies_without_deleting(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp) / "audit.jsonl"
            base.write_text("{}\n", encoding="utf-8")
            _touch(base.with_suffix(".jsonl.1"), age_days=60)

            report = purge_rotated_audit_files(
                base, older_than_days=30, dry_run=True
            )

            self.assertTrue(report["dry_run"])
            self.assertEqual(len(report["deleted"]), 1)
            self.assertTrue(
                base.with_suffix(".jsonl.1").exists(),
                "dry_run must not actually delete files",
            )

    def test_negative_window_raises(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp) / "audit.jsonl"
            with self.assertRaises(ValueError):
                purge_rotated_audit_files(base, older_than_days=-1)

    def test_ignores_non_rotation_siblings(self):
        # The function must only match `<name>.<int>`. Sibling files with
        # mismatched suffixes or arbitrary names must not be considered.
        with TemporaryDirectory() as tmp:
            base = Path(tmp) / "audit.jsonl"
            base.write_text("{}\n", encoding="utf-8")
            _touch(base.with_suffix(".jsonl.bak"), age_days=90)
            _touch(Path(tmp) / "unrelated.log", age_days=90)
            _touch(Path(tmp) / "audit.jsonl.archive", age_days=90)

            report = purge_rotated_audit_files(base, older_than_days=30)

            self.assertEqual(report["deleted"], [])
            self.assertEqual(report["kept"], [])
            self.assertTrue(base.with_suffix(".jsonl.bak").exists())
            self.assertTrue((Path(tmp) / "unrelated.log").exists())
            self.assertTrue((Path(tmp) / "audit.jsonl.archive").exists())

    def test_zero_window_purges_anything_in_the_past(self):
        # `older_than_days=0` means "delete every rotated backup whose mtime
        # is in the past." Practically: clear all rotated backups.
        with TemporaryDirectory() as tmp:
            base = Path(tmp) / "audit.jsonl"
            base.write_text("{}\n", encoding="utf-8")
            _touch(base.with_suffix(".jsonl.1"), age_days=0.5)
            _touch(base.with_suffix(".jsonl.2"), age_days=2)

            report = purge_rotated_audit_files(base, older_than_days=0)

            self.assertEqual(len(report["deleted"]), 2)


class AuditPurgeCLITests(unittest.TestCase):
    def test_audit_purge_subcommand_prints_report_and_exits_zero_on_clean_run(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp) / "audit.jsonl"
            base.write_text("{}\n", encoding="utf-8")
            _touch(base.with_suffix(".jsonl.1"), age_days=60)

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                status = main(
                    [
                        "audit-purge",
                        str(base),
                        "--older-than-days",
                        "30",
                    ]
                )

            self.assertEqual(status, 0)
            report = json.loads(stdout.getvalue())
            self.assertEqual(len(report["deleted"]), 1)
            self.assertEqual(report["older_than_days"], 30)
            self.assertFalse(report["dry_run"])
            self.assertFalse(base.with_suffix(".jsonl.1").exists())

    def test_audit_purge_dry_run_does_not_delete(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp) / "audit.jsonl"
            base.write_text("{}\n", encoding="utf-8")
            _touch(base.with_suffix(".jsonl.1"), age_days=60)

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                status = main(
                    [
                        "audit-purge",
                        str(base),
                        "--older-than-days",
                        "30",
                        "--dry-run",
                    ]
                )

            self.assertEqual(status, 0)
            report = json.loads(stdout.getvalue())
            self.assertTrue(report["dry_run"])
            self.assertTrue(base.with_suffix(".jsonl.1").exists())

    def test_audit_purge_negative_window_returns_nonzero(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp) / "audit.jsonl"
            base.write_text("{}\n", encoding="utf-8")
            stderr = io.StringIO()
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                from contextlib import redirect_stderr

                with redirect_stderr(stderr):
                    status = main(
                        [
                            "audit-purge",
                            str(base),
                            "--older-than-days",
                            "-1",
                        ]
                    )
            self.assertEqual(status, 2)

    def test_audit_purge_zero_window_rejected_by_cli_guard(self):
        # --older-than-days 0 would purge every rotated backup. An empty
        # cron environment-variable expansion can produce this accidentally,
        # so the CLI gates it >= 1. The underlying Python function still
        # accepts 0 for programmatic callers — that is covered by
        # PurgeRotatedAuditFilesTests.test_zero_window_purges_anything_in_the_past.
        with TemporaryDirectory() as tmp:
            base = Path(tmp) / "audit.jsonl"
            base.write_text("{}\n", encoding="utf-8")
            from contextlib import redirect_stderr

            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = main(
                    [
                        "audit-purge",
                        str(base),
                        "--older-than-days",
                        "0",
                    ]
                )
            self.assertEqual(status, 2)
            self.assertIn(">= 1", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
