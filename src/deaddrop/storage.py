"""SQLite-backed store for encrypted drops awaiting retrieval."""

from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


SCHEMA = """
CREATE TABLE IF NOT EXISTS drops (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_hash  BLOB    NOT NULL,
    ciphertext      BLOB    NOT NULL,
    size            INTEGER NOT NULL,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    sender_hint     BLOB
);
CREATE INDEX IF NOT EXISTS idx_drops_recipient
    ON drops(recipient_hash, id);
CREATE INDEX IF NOT EXISTS idx_drops_expiry
    ON drops(expires_at);
"""


@dataclass(frozen=True)
class DropRecord:
    id: int
    recipient_hash: bytes
    ciphertext: bytes
    size: int
    created_at: int
    expires_at: int
    sender_hint: bytes | None


@dataclass(frozen=True)
class DropSummary:
    id: int
    size: int
    created_at: int
    expires_at: int


class DropStore:
    """Thread-safe SQLite drop store.

    A single Reticulum node runs callbacks on its internal thread pool, so
    every public method opens its own connection with a short busy_timeout.
    """

    def __init__(self, db_path: Path | str):
        self.db_path = str(db_path)
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=5.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
        finally:
            conn.close()

    # ---- writes ----------------------------------------------------------

    def put(
        self,
        recipient_hash: bytes,
        ciphertext: bytes,
        ttl_seconds: int,
        sender_hint: bytes | None = None,
        now: int | None = None,
    ) -> DropRecord:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        now = int(now if now is not None else time.time())
        expires = now + ttl_seconds
        size = len(ciphertext)
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO drops
                    (recipient_hash, ciphertext, size, created_at, expires_at, sender_hint)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (recipient_hash, ciphertext, size, now, expires, sender_hint),
            )
            drop_id = cur.lastrowid
        return DropRecord(
            id=drop_id,
            recipient_hash=recipient_hash,
            ciphertext=ciphertext,
            size=size,
            created_at=now,
            expires_at=expires,
            sender_hint=sender_hint,
        )

    def delete(self, drop_id: int, recipient_hash: bytes) -> bool:
        """Delete a drop, but only if it belongs to recipient_hash."""
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM drops WHERE id = ? AND recipient_hash = ?",
                (drop_id, recipient_hash),
            )
            return cur.rowcount > 0

    def sweep_expired(self, now: int | None = None) -> int:
        now = int(now if now is not None else time.time())
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM drops WHERE expires_at <= ?", (now,))
            return cur.rowcount

    # ---- reads -----------------------------------------------------------

    def list_for(
        self, recipient_hash: bytes, now: int | None = None
    ) -> list[DropSummary]:
        now = int(now if now is not None else time.time())
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, size, created_at, expires_at
                FROM drops
                WHERE recipient_hash = ? AND expires_at > ?
                ORDER BY id ASC
                """,
                (recipient_hash, now),
            ).fetchall()
        return [DropSummary(*row) for row in rows]

    def fetch(
        self, drop_id: int, recipient_hash: bytes, now: int | None = None
    ) -> DropRecord | None:
        now = int(now if now is not None else time.time())
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, recipient_hash, ciphertext, size, created_at, expires_at, sender_hint
                FROM drops
                WHERE id = ? AND recipient_hash = ? AND expires_at > ?
                """,
                (drop_id, recipient_hash, now),
            ).fetchone()
        if row is None:
            return None
        return DropRecord(*row)

    def stats(self, now: int | None = None) -> dict:
        now = int(now if now is not None else time.time())
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*), COALESCE(SUM(size), 0)
                FROM drops
                WHERE expires_at > ?
                """,
                (now,),
            ).fetchone()
        return {"drops": int(row[0]), "bytes": int(row[1])}
