# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import shutil
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from cryptography.fernet import Fernet, InvalidToken


class TokenVault(Protocol):
    def tokenize(self, value: str, *, entity: str, metadata: dict[str, Any] | None = None) -> str:
        ...

    def resolve(self, token: str) -> str:
        ...

    def status(self) -> dict[str, Any]:
        ...


@dataclass(frozen=True)
class VaultTokenRecord:
    token: str
    entity: str
    created_at: str
    metadata: dict[str, Any]


class EncryptedSqliteTokenVault:
    def __init__(self, path: str | Path, key: str):
        self.path = Path(path)
        self.key = key
        self._fernet = Fernet(key.encode("utf-8") if isinstance(key, str) else key)
        self._hmac_key = base64.urlsafe_b64decode(key.encode("utf-8") if isinstance(key, str) else key)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def tokenize(self, value: str, *, entity: str, metadata: dict[str, Any] | None = None) -> str:
        token = self._token_for(entity, value)
        safe_metadata = _safe_metadata(metadata or {})
        encrypted = self._fernet.encrypt(value.encode("utf-8")).decode("utf-8")
        created_at = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO vault_tokens
                  (token, entity, ciphertext, created_at, value_digest, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    token,
                    entity,
                    encrypted,
                    created_at,
                    _value_digest(value),
                    json.dumps(safe_metadata, sort_keys=True, separators=(",", ":")),
                ),
            )
        return token

    def resolve(self, token: str) -> str:
        with sqlite3.connect(self.path) as conn:
            row = conn.execute(
                "SELECT ciphertext FROM vault_tokens WHERE token = ?",
                (token,),
            ).fetchone()
        if row is None:
            raise KeyError(f"Token not found: {token}")
        try:
            return self._fernet.decrypt(row[0].encode("utf-8")).decode("utf-8")
        except InvalidToken as exc:
            raise ValueError("Vault key could not decrypt this token") from exc

    def status(self) -> dict[str, Any]:
        with sqlite3.connect(self.path) as conn:
            count = conn.execute("SELECT COUNT(*) FROM vault_tokens").fetchone()[0]
            by_entity = dict(conn.execute("SELECT entity, COUNT(*) FROM vault_tokens GROUP BY entity"))
        return {
            "path": str(self.path),
            "exists": self.path.exists(),
            "token_count": count,
            "by_entity": by_entity,
            "encrypted": True,
        }

    def record(self, token: str) -> VaultTokenRecord:
        with sqlite3.connect(self.path) as conn:
            row = conn.execute(
                "SELECT token, entity, created_at, metadata_json FROM vault_tokens WHERE token = ?",
                (token,),
            ).fetchone()
        if row is None:
            raise KeyError(f"Token not found: {token}")
        return VaultTokenRecord(
            token=row[0],
            entity=row[1],
            created_at=row[2],
            metadata=json.loads(row[3] or "{}"),
        )

    def _token_for(self, entity: str, value: str) -> str:
        digest = hmac.new(
            self._hmac_key,
            f"{entity}\0{value}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()[:20]
        return f"lsdf_tok_{entity.lower()}_{digest}"

    def _init_db(self) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS vault_tokens (
                  token TEXT PRIMARY KEY,
                  entity TEXT NOT NULL,
                  ciphertext TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  value_digest TEXT NOT NULL,
                  metadata_json TEXT NOT NULL
                )
                """
            )


def generate_vault_key() -> str:
    return Fernet.generate_key().decode("utf-8")


def vault_status(path: str | Path) -> dict[str, Any]:
    vault_path = Path(path)
    if not vault_path.exists():
        return {"path": str(vault_path), "exists": False, "token_count": 0, "by_entity": {}, "encrypted": True}
    with sqlite3.connect(vault_path) as conn:
        try:
            count = conn.execute("SELECT COUNT(*) FROM vault_tokens").fetchone()[0]
            by_entity = dict(conn.execute("SELECT entity, COUNT(*) FROM vault_tokens GROUP BY entity"))
        except sqlite3.DatabaseError:
            return {"path": str(vault_path), "exists": True, "token_count": 0, "by_entity": {}, "encrypted": True, "valid": False}
    return {"path": str(vault_path), "exists": True, "token_count": count, "by_entity": by_entity, "encrypted": True, "valid": True}


def check_vault(path: str | Path) -> dict[str, Any]:
    vault_path = Path(path)
    if not vault_path.exists():
        return {
            "path": str(vault_path),
            "exists": False,
            "valid": False,
            "reason": "missing",
        }
    try:
        with sqlite3.connect(vault_path) as conn:
            columns = {
                row[1]
                for row in conn.execute("PRAGMA table_info(vault_tokens)").fetchall()
            }
            required = {"token", "entity", "ciphertext", "created_at", "value_digest", "metadata_json"}
            if not required.issubset(columns):
                return {
                    "path": str(vault_path),
                    "exists": True,
                    "valid": False,
                    "reason": "missing required columns",
                }
            count = conn.execute("SELECT COUNT(*) FROM vault_tokens").fetchone()[0]
    except sqlite3.DatabaseError as exc:
        return {
            "path": str(vault_path),
            "exists": True,
            "valid": False,
            "reason": type(exc).__name__,
        }
    return {
        "path": str(vault_path),
        "exists": True,
        "valid": True,
        "token_count": count,
        "encrypted": True,
    }


def backup_vault(path: str | Path, output: str | Path) -> dict[str, Any]:
    source = Path(path)
    target = Path(output)
    status = check_vault(source)
    if not status["valid"]:
        raise ValueError(f"Cannot back up invalid vault: {status.get('reason', 'invalid')}")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    return {
        "backed_up": True,
        "vault_path": str(source),
        "output": str(target),
        "bytes": target.stat().st_size,
    }


def rotate_vault_key(
    path: str | Path,
    output: str | Path,
    *,
    old_key: str,
    new_key: str,
) -> dict[str, Any]:
    source = Path(path)
    target = Path(output)
    if source.resolve() == target.resolve():
        raise ValueError("rotate-key output must be a different path")
    status = check_vault(source)
    if not status["valid"]:
        raise ValueError(f"Cannot rotate invalid vault: {status.get('reason', 'invalid')}")
    if target.exists():
        raise ValueError("rotate-key output already exists")
    old_fernet = Fernet(old_key.encode("utf-8") if isinstance(old_key, str) else old_key)
    new_fernet = Fernet(new_key.encode("utf-8") if isinstance(new_key, str) else new_key)
    target.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    with sqlite3.connect(source) as conn:
        for row in conn.execute(
            """
            SELECT token, entity, ciphertext, created_at, value_digest, metadata_json
            FROM vault_tokens
            ORDER BY token
            """
        ):
            try:
                plaintext = old_fernet.decrypt(row[2].encode("utf-8"))
            except InvalidToken as exc:
                raise ValueError("Old vault key could not decrypt one or more tokens") from exc
            rows.append((row[0], row[1], new_fernet.encrypt(plaintext).decode("utf-8"), row[3], row[4], row[5]))
    with sqlite3.connect(target) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS vault_tokens (
              token TEXT PRIMARY KEY,
              entity TEXT NOT NULL,
              ciphertext TEXT NOT NULL,
              created_at TEXT NOT NULL,
              value_digest TEXT NOT NULL,
              metadata_json TEXT NOT NULL
            )
            """
        )
        conn.executemany(
            """
            INSERT INTO vault_tokens
              (token, entity, ciphertext, created_at, value_digest, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
    return {
        "rotated": True,
        "source": str(source),
        "output": str(target),
        "token_count": len(rows),
        "source_unchanged": True,
    }


def load_vault_from_env(env: dict[str, str]) -> EncryptedSqliteTokenVault | None:
    if env.get("LSDF_TOKENIZATION_MODE", "irreversible") != "vault":
        return None
    path = env.get("LSDF_VAULT_PATH")
    key = env.get("LSDF_VAULT_KEY")
    if not path or not key:
        raise ValueError("Vault mode requires LSDF_VAULT_PATH and LSDF_VAULT_KEY")
    return EncryptedSqliteTokenVault(path, key)


def _value_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _safe_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key, value in metadata.items():
        if isinstance(value, (int, float, bool)) or value is None:
            safe[key] = value
        elif isinstance(value, str):
            safe[key] = f"[REDACTED len={len(value)}]"
        elif isinstance(value, dict):
            safe[key] = _safe_metadata(value)
        else:
            safe[key] = str(type(value).__name__)
    return safe
