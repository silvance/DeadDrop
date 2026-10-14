"""Tests for the SQLite drop store."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from deaddrop.storage import DropStore


@pytest.fixture
def store(tmp_path: Path) -> DropStore:
    return DropStore(tmp_path / "drops.sqlite")


HASH_A = b"A" * 16
HASH_B = b"B" * 16


def test_put_and_fetch(store: DropStore) -> None:
    record = store.put(HASH_A, b"ciphertext", ttl_seconds=60)
    assert record.size == len(b"ciphertext")
    got = store.fetch(record.id, HASH_A)
    assert got is not None
    assert got.ciphertext == b"ciphertext"


def test_fetch_rejects_wrong_recipient(store: DropStore) -> None:
    record = store.put(HASH_A, b"secret", ttl_seconds=60)
    assert store.fetch(record.id, HASH_B) is None


def test_list_scopes_to_recipient(store: DropStore) -> None:
    store.put(HASH_A, b"one", ttl_seconds=60)
    store.put(HASH_A, b"two", ttl_seconds=60)
    store.put(HASH_B, b"three", ttl_seconds=60)
    a_drops = store.list_for(HASH_A)
    b_drops = store.list_for(HASH_B)
    assert len(a_drops) == 2
    assert len(b_drops) == 1
    assert {d.size for d in a_drops} == {3}


def test_delete_only_for_owner(store: DropStore) -> None:
    record = store.put(HASH_A, b"x", ttl_seconds=60)
    assert store.delete(record.id, HASH_B) is False
    assert store.fetch(record.id, HASH_A) is not None
    assert store.delete(record.id, HASH_A) is True
    assert store.fetch(record.id, HASH_A) is None


def test_sweep_expired(store: DropStore) -> None:
    now = int(time.time())
    store.put(HASH_A, b"old", ttl_seconds=1, now=now - 10)
    store.put(HASH_A, b"new", ttl_seconds=3600, now=now)
    removed = store.sweep_expired(now=now)
    assert removed == 1
    remaining = store.list_for(HASH_A, now=now)
    assert len(remaining) == 1
    assert remaining[0].size == 3


def test_list_skips_expired_without_sweep(store: DropStore) -> None:
    now = int(time.time())
    store.put(HASH_A, b"old", ttl_seconds=1, now=now - 10)
    store.put(HASH_A, b"new", ttl_seconds=3600, now=now)
    assert len(store.list_for(HASH_A, now=now)) == 1


def test_stats(store: DropStore) -> None:
    store.put(HASH_A, b"x" * 10, ttl_seconds=60)
    store.put(HASH_B, b"y" * 20, ttl_seconds=60)
    stats = store.stats()
    assert stats["drops"] == 2
    assert stats["bytes"] == 30


def test_ttl_must_be_positive(store: DropStore) -> None:
    with pytest.raises(ValueError):
        store.put(HASH_A, b"x", ttl_seconds=0)


def _create_v010_db(path: Path, hint: bytes) -> None:
    """Create a database the way deaddrop 0.1.0 did, with sender_hint."""
    import sqlite3

    conn = sqlite3.connect(path, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(
        """
        CREATE TABLE drops (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_hash  BLOB    NOT NULL,
            ciphertext      BLOB    NOT NULL,
            size            INTEGER NOT NULL,
            created_at      INTEGER NOT NULL,
            expires_at      INTEGER NOT NULL,
            sender_hint     BLOB
        );
        CREATE INDEX idx_drops_recipient ON drops(recipient_hash, id);
        CREATE INDEX idx_drops_expiry ON drops(expires_at);
        """
    )
    now = int(time.time())
    for i in range(1, 4):
        conn.execute(
            "INSERT INTO drops (recipient_hash, ciphertext, size, created_at, expires_at, sender_hint)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (HASH_A, b"c" * i, i, now, now + 3600, hint),
        )
    conn.close()


def test_migration_drops_sender_hint_and_keeps_drops(tmp_path: Path) -> None:
    import sqlite3

    db = tmp_path / "old.sqlite"
    hint = b"\xde\xad\xbe\xef" * 4
    _create_v010_db(db, hint)

    store = DropStore(db)

    conn = sqlite3.connect(db)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(drops)")}
    indexes = {row[1] for row in conn.execute("PRAGMA index_list(drops)")}
    conn.close()
    assert "sender_hint" not in columns
    assert {"idx_drops_recipient", "idx_drops_expiry"} <= indexes

    drops = store.list_for(HASH_A)
    assert [d.size for d in drops] == [1, 2, 3]
    assert store.fetch(drops[0].id, HASH_A).ciphertext == b"c"

    # New ids continue after the migrated ones.
    assert store.put(HASH_A, b"new", ttl_seconds=60).id > drops[-1].id

    # The old sender hashes must not survive anywhere in the files on disk.
    for f in tmp_path.iterdir():
        assert hint not in f.read_bytes(), f"sender hint left in {f.name}"


def test_migration_is_noop_on_current_schema(tmp_path: Path) -> None:
    db = tmp_path / "drops.sqlite"
    store = DropStore(db)
    record = store.put(HASH_A, b"x", ttl_seconds=60)
    reopened = DropStore(db)
    assert reopened.fetch(record.id, HASH_A) is not None
