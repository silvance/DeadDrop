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
