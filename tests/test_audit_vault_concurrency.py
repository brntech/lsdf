import json
import os
import sqlite3
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from lsdf.audit import JsonlAuditSink
from lsdf.vault import EncryptedSqliteTokenVault, backup_vault, check_vault, generate_vault_key, rotate_vault_key


class AuditConcurrencyTests(unittest.TestCase):
    def test_concurrent_writes_survive_repeated_rotations(self):
        workers, events_per_worker = 8, 20
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            sink = JsonlAuditSink(path, rotate_bytes=256, rotate_backups=workers * events_per_worker)
            start = threading.Barrier(workers)

            def write_events(worker):
                start.wait(timeout=10)
                for sequence in range(events_per_worker):
                    sink.write({"worker": worker, "sequence": sequence})

            with ThreadPoolExecutor(max_workers=workers) as pool:
                list(pool.map(write_events, range(workers)))
            files = list(Path(tmp).glob("audit.jsonl*"))
            records = [json.loads(line) for file in files for line in file.read_text().splitlines()]

            self.assertGreater(len(files), 3)
            self.assertEqual(len(records), workers * events_per_worker)
            self.assertEqual(
                {(record["worker"], record["sequence"]) for record in records},
                {(worker, sequence) for worker in range(workers) for sequence in range(events_per_worker)},
            )
            self.assertTrue(all(set(record) == {"timestamp", "worker", "sequence"} for record in records))

    def test_write_failure_does_not_leave_sink_locked(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            sink = JsonlAuditSink(path)
            with patch.object(Path, "open", side_effect=OSError("synthetic write failure")):
                with self.assertRaises(OSError):
                    sink.write({"sequence": 0})
            sink.write({"sequence": 1})
            self.assertEqual(json.loads(path.read_text())["sequence"], 1)


class VaultSnapshotTests(unittest.TestCase):
    def test_backup_includes_committed_wal_data_and_preserves_source(self):
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "vault.sqlite"
            target = Path(tmp) / "backup.sqlite"
            key = generate_vault_key()
            vault = EncryptedSqliteTokenVault(source, key)
            values = ("synthetic first record", "synthetic second record")
            first_token = vault.tokenize(values[0], entity="OTHER_SECRET")
            with closing(sqlite3.connect(source)) as keeper:
                self.assertEqual(keeper.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
                keeper.execute("PRAGMA wal_autocheckpoint=0")
                keeper.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                second_token = vault.tokenize(values[1], entity="OTHER_SECRET")
                wal = Path(str(source) + "-wal")
                self.assertGreater(wal.stat().st_size, 0)
                before = source.read_bytes(), wal.read_bytes()

                report = backup_vault(source, target)

                self.assertEqual((source.read_bytes(), wal.read_bytes()), before)
                self.assertEqual(check_vault(target)["token_count"], 2)
                restored = EncryptedSqliteTokenVault(target, key)
                self.assertEqual(restored.resolve(first_token), values[0])
                self.assertEqual(restored.resolve(second_token), values[1])
                self.assertEqual(check_vault(source)["token_count"], 2)
            self.assertTrue(report["backed_up"])
            self.assertGreater(report["bytes"], 0)
            for value in values:
                self.assertNotIn(value, json.dumps(report))
                self.assertNotIn(value.encode(), target.read_bytes())

    def test_backup_rejects_source_aliases_and_existing_output(self):
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "vault.sqlite"
            EncryptedSqliteTokenVault(source, generate_vault_key())
            original = source.read_bytes()
            hardlink = Path(tmp) / "alias.sqlite"
            os.link(source, hardlink)
            existing = Path(tmp) / "existing.sqlite"
            existing.write_bytes(b"existing backup")
            for target in (source, hardlink, existing):
                with self.subTest(target=target.name), self.assertRaises(ValueError):
                    backup_vault(source, target)
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(hardlink.read_bytes(), original)
            self.assertEqual(existing.read_bytes(), b"existing backup")

    def test_backup_does_not_follow_dangling_output_symlink(self):
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "vault.sqlite"
            EncryptedSqliteTokenVault(source, generate_vault_key())
            unrelated = Path(tmp) / "unrelated.sqlite"
            target = Path(tmp) / "backup.sqlite"
            target.symlink_to(unrelated)
            with self.assertRaises(ValueError):
                backup_vault(source, target)
            self.assertTrue(target.is_symlink())
            self.assertFalse(unrelated.exists())

    def test_backup_preserves_preexisting_output_sidecars(self):
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "vault.sqlite"
            EncryptedSqliteTokenVault(source, generate_vault_key())
            target = Path(tmp) / "backup.sqlite"
            for suffix in ("-wal", "-shm", "-journal"):
                with self.subTest(suffix=suffix):
                    sidecar = Path(str(target) + suffix)
                    sidecar.write_bytes(b"unrelated sidecar")
                    with self.assertRaises(ValueError):
                        backup_vault(source, target)
                    self.assertFalse(target.exists())
                    self.assertEqual(sidecar.read_bytes(), b"unrelated sidecar")
                    sidecar.unlink()
                    unrelated = Path(tmp) / "unrelated.sqlite"
                    sidecar.symlink_to(unrelated)
                    with self.assertRaises(ValueError):
                        backup_vault(source, target)
                    self.assertFalse(target.exists())
                    self.assertFalse(unrelated.exists())
                    self.assertTrue(sidecar.is_symlink())
                    sidecar.unlink()

    def test_failed_snapshot_removes_only_its_new_output(self):
        class FailingBackupConnection(sqlite3.Connection):
            def backup(self, destination, **kwargs):
                destination.execute("CREATE TABLE partial (n INTEGER)")
                destination.commit()
                raise sqlite3.OperationalError("synthetic backup failure")

        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "vault.sqlite"
            EncryptedSqliteTokenVault(source, generate_vault_key())
            original = source.read_bytes()
            target = Path(tmp) / "backup.sqlite"
            real_connect = sqlite3.connect

            def connect(database, *args, **kwargs):
                if kwargs.get("uri"):
                    kwargs["factory"] = FailingBackupConnection
                return real_connect(database, *args, **kwargs)

            with patch("lsdf.vault.sqlite3.connect", side_effect=connect):
                with self.assertRaises(sqlite3.OperationalError):
                    backup_vault(source, target)
            self.assertFalse(target.exists())
            self.assertEqual(source.read_bytes(), original)



class VaultRotationSafetyTests(unittest.TestCase):
    def setUp(self):
        import gc
        scratch = TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.source = self.root / "vault.sqlite"
        self.target = self.root / "rotated.sqlite"
        self.old_key = generate_vault_key()
        self.new_key = generate_vault_key()
        self.value = "synthetic rotation record"
        vault = EncryptedSqliteTokenVault(self.source, self.old_key)
        self.token = vault.tokenize(self.value, entity="OTHER_SECRET")
        gc.collect()
        self.original = self.source.read_bytes()

    def rotate(self, target=None, old_key=None):
        return rotate_vault_key(
            self.source, target or self.target,
            old_key=old_key or self.old_key, new_key=self.new_key,
        )

    def test_rotation_rejects_source_alias_existing_file_and_dangling_symlink(self):
        hardlink = self.root / "hardlink.sqlite"
        os.link(self.source, hardlink)
        source_link = self.root / "source-link.sqlite"
        source_link.symlink_to(self.source)
        existing = self.root / "existing.sqlite"
        existing.write_bytes(b"unrelated existing output")
        unrelated = self.root / "unrelated.sqlite"
        self.target.symlink_to(unrelated)
        for target in (self.source, hardlink, source_link, existing, self.target):
            with self.subTest(target=target.name), self.assertRaises(ValueError):
                self.rotate(target)
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertEqual(existing.read_bytes(), b"unrelated existing output")
        self.assertTrue(self.target.is_symlink())
        self.assertFalse(unrelated.exists())

    def test_rotation_rejects_existing_and_symlink_sidecars(self):
        unrelated = self.root / "unrelated.sqlite"
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(str(self.target) + suffix)
            for symlink in (False, True):
                with self.subTest(suffix=suffix, symlink=symlink):
                    if symlink:
                        sidecar.symlink_to(unrelated)
                    else:
                        sidecar.write_bytes(b"unrelated sidecar")
                    with self.assertRaises(ValueError):
                        self.rotate()
                    self.assertFalse(self.target.exists())
                    self.assertFalse(unrelated.exists())
                    if symlink:
                        self.assertTrue(sidecar.is_symlink())
                    else:
                        self.assertEqual(sidecar.read_bytes(), b"unrelated sidecar")
                    sidecar.unlink()
        self.assertEqual(self.source.read_bytes(), self.original)

    def test_rotation_creates_private_output_and_preserves_tokens_and_source(self):
        report = self.rotate()
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.source.read_bytes(), self.original)
        restored = EncryptedSqliteTokenVault(self.target, self.new_key)
        self.assertEqual(restored.resolve(self.token), self.value)
        self.assertEqual(EncryptedSqliteTokenVault(self.source, self.old_key).resolve(self.token), self.value)
        self.assertTrue(report["source_unchanged"])
        self.assertNotIn(self.value, json.dumps(report))
        self.assertNotIn(self.value.encode(), self.target.read_bytes())

    def test_rotation_exclusive_create_preserves_a_competing_output(self):
        real_open = os.open

        def create_competing_output(path, flags, mode=0o777, **kwargs):
            if Path(path) == self.target:
                self.target.write_bytes(b"competing output")
            return real_open(path, flags, mode, **kwargs)

        with patch("lsdf.vault.os.open", side_effect=create_competing_output):
            with self.assertRaises(ValueError):
                self.rotate()
        self.assertEqual(self.target.read_bytes(), b"competing output")
        self.assertEqual(self.source.read_bytes(), self.original)

    def test_rotation_wrong_key_removes_reserved_output(self):
        with self.assertRaisesRegex(ValueError, "Old vault key could not decrypt"):
            self.rotate(old_key=generate_vault_key())
        self.assertFalse(self.target.exists())
        self.assertEqual(self.source.read_bytes(), self.original)

    def test_rotation_write_failure_rolls_back_closes_and_removes_output(self):
        class FailingRotationConnection(sqlite3.Connection):
            def executemany(self, sql, parameters):
                super().executemany(sql, parameters)
                raise sqlite3.OperationalError("synthetic rotation failure")

        real_connect = sqlite3.connect

        def connect(database, *args, **kwargs):
            if not kwargs.get("uri") and Path(database) == self.target:
                kwargs["factory"] = FailingRotationConnection
            return real_connect(database, *args, **kwargs)

        with patch("lsdf.vault.sqlite3.connect", side_effect=connect):
            with self.assertRaises(sqlite3.OperationalError):
                self.rotate()
        self.assertFalse(self.target.exists())
        self.assertTrue(all(not Path(str(self.target) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")))
        self.assertEqual(self.source.read_bytes(), self.original)


class StandaloneWalBackupTests(unittest.TestCase):
    def test_backup_of_closed_wal_vault_without_existing_shared_memory(self):
        import gc
        with TemporaryDirectory() as scratch:
            source = Path(scratch, "vault.sqlite")
            target = Path(scratch, "backup.sqlite")
            key = generate_vault_key()
            vault = EncryptedSqliteTokenVault(source, key)
            token = vault.tokenize("synthetic closed WAL record", entity="OTHER_SECRET")
            gc.collect()
            with closing(sqlite3.connect(source)) as writer:
                self.assertEqual(writer.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
            self.assertFalse(Path(str(source) + "-wal").exists())
            self.assertFalse(Path(str(source) + "-shm").exists())
            before = source.read_bytes()
            report = backup_vault(source, target)
            self.assertTrue(report["backed_up"])
            self.assertEqual(source.read_bytes(), before)
            self.assertEqual(EncryptedSqliteTokenVault(target, key).resolve(token), "synthetic closed WAL record")

    def test_backup_recovers_committed_wal_after_writer_exit_without_shared_memory(self):
        import gc
        import subprocess
        import sys
        with TemporaryDirectory() as scratch:
            source = Path(scratch, "vault.sqlite")
            target = Path(scratch, "backup.sqlite")
            key = generate_vault_key()
            vault = EncryptedSqliteTokenVault(source, key)
            first = vault.tokenize("synthetic first WAL record", entity="OTHER_SECRET")
            second = vault._token_for("OTHER_SECRET", "synthetic second WAL record")
            gc.collect()
            writer_script = """
import json, os, sqlite3, sys
from lsdf.vault import EncryptedSqliteTokenVault
settings = json.load(sys.stdin)
keeper = sqlite3.connect(settings['source'])
keeper.execute('PRAGMA journal_mode=WAL')
keeper.execute('PRAGMA wal_autocheckpoint=0')
vault = EncryptedSqliteTokenVault(settings['source'], settings['key'])
vault.tokenize('synthetic second WAL record', entity='OTHER_SECRET')
os._exit(0)
"""
            writer = subprocess.run(
                [sys.executable, "-c", writer_script],
                input=json.dumps({"source": str(source), "key": key}),
                text=True, capture_output=True, timeout=10,
            )
            self.assertEqual(writer.returncode, 0)
            wal = Path(str(source) + "-wal")
            self.assertGreater(wal.stat().st_size, 0)
            Path(str(source) + "-shm").unlink(missing_ok=True)
            before = source.read_bytes(), wal.read_bytes()
            report = backup_vault(source, target)
            self.assertTrue(report["backed_up"])
            self.assertEqual((source.read_bytes(), wal.read_bytes()), before)
            restored = EncryptedSqliteTokenVault(target, key)
            self.assertEqual(restored.resolve(first), "synthetic first WAL record")
            self.assertEqual(restored.resolve(second), "synthetic second WAL record")
            self.assertEqual(check_vault(target)["token_count"], 2)



if __name__ == "__main__":
    unittest.main()
