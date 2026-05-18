"""Wire-format and handler-logic tests."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

RNS = pytest.importorskip("RNS")

from deaddrop import protocol  # noqa: E402
from deaddrop.config import NodeConfig  # noqa: E402
from deaddrop.node import DeadDropNode  # noqa: E402


def test_encode_decode_round_trip() -> None:
    payload = {
        "recipient_hash": b"R" * 16,
        "ciphertext": b"\x00\x01\x02",
        "ttl_seconds": 60,
    }
    assert protocol.decode(protocol.encode(payload)) == payload


def test_ok_helper_marks_status() -> None:
    blob = protocol.ok(drop_id=7, expires_at=99)
    decoded = protocol.decode(blob)
    assert decoded["status"] == protocol.OK
    assert decoded["drop_id"] == 7


def test_err_helper_includes_message() -> None:
    decoded = protocol.decode(protocol.err(protocol.ERR_BAD_REQUEST, "no good"))
    assert decoded["status"] == protocol.ERR_BAD_REQUEST
    assert decoded["error"] == "no good"


@pytest.fixture
def node(tmp_path: Path) -> DeadDropNode:
    """Build a DeadDropNode without starting Reticulum."""
    config = NodeConfig(
        data_dir=tmp_path,
        identity_path=tmp_path / "id",
        db_path=tmp_path / "drops.sqlite",
        reticulum_configdir=None,
        max_drop_bytes=1024,
        max_total_bytes=4096,
        default_ttl_seconds=60,
        max_ttl_seconds=120,
    )
    return DeadDropNode(config)


def _identity_stub(hash_bytes: bytes):
    stub = MagicMock()
    stub.hash = hash_bytes
    return stub


def test_handle_put_stores_drop(node: DeadDropNode) -> None:
    sender = _identity_stub(b"S" * 16)
    payload = protocol.encode({
        "recipient_hash": b"R" * 16,
        "ciphertext": b"opaque",
        "ttl_seconds": 60,
    })
    resp = protocol.decode(node._handle_put("put", payload, 1, sender, 0))
    assert resp["status"] == protocol.OK
    assert resp["drop_id"] > 0


def test_handle_put_rejects_oversize(node: DeadDropNode) -> None:
    sender = _identity_stub(b"S" * 16)
    payload = protocol.encode({
        "recipient_hash": b"R" * 16,
        "ciphertext": b"x" * 2048,
        "ttl_seconds": 60,
    })
    resp = protocol.decode(node._handle_put("put", payload, 1, sender, 0))
    assert resp["status"] == protocol.ERR_TOO_LARGE


def test_handle_put_rejects_bad_ttl(node: DeadDropNode) -> None:
    sender = _identity_stub(b"S" * 16)
    payload = protocol.encode({
        "recipient_hash": b"R" * 16,
        "ciphertext": b"opaque",
        "ttl_seconds": 999_999,
    })
    resp = protocol.decode(node._handle_put("put", payload, 1, sender, 0))
    assert resp["status"] == protocol.ERR_BAD_REQUEST


def test_handle_list_returns_only_recipient_drops(node: DeadDropNode) -> None:
    alice = _identity_stub(b"A" * 16)
    bob = _identity_stub(b"B" * 16)
    # Two drops for Alice, one for Bob.
    for body in (b"a1", b"a2"):
        node._handle_put(
            "put",
            protocol.encode({"recipient_hash": alice.hash, "ciphertext": body, "ttl_seconds": 60}),
            1,
            bob,
            0,
        )
    node._handle_put(
        "put",
        protocol.encode({"recipient_hash": bob.hash, "ciphertext": b"b1", "ttl_seconds": 60}),
        1,
        alice,
        0,
    )
    resp = protocol.decode(node._handle_list("list", b"", 1, alice, 0))
    assert resp["status"] == protocol.OK
    assert len(resp["drops"]) == 2
    bob_resp = protocol.decode(node._handle_list("list", b"", 1, bob, 0))
    assert len(bob_resp["drops"]) == 1


def test_handle_fetch_requires_matching_identity(node: DeadDropNode) -> None:
    alice = _identity_stub(b"A" * 16)
    bob = _identity_stub(b"B" * 16)
    put_resp = protocol.decode(node._handle_put(
        "put",
        protocol.encode({"recipient_hash": alice.hash, "ciphertext": b"hush", "ttl_seconds": 60}),
        1,
        bob,
        0,
    ))
    drop_id = put_resp["drop_id"]

    # Bob (the sender) cannot fetch what was addressed to Alice.
    resp = protocol.decode(node._handle_fetch(
        "fetch", protocol.encode({"drop_id": drop_id}), 1, bob, 0
    ))
    assert resp["status"] == protocol.ERR_NOT_FOUND

    # Alice can.
    resp = protocol.decode(node._handle_fetch(
        "fetch", protocol.encode({"drop_id": drop_id}), 1, alice, 0
    ))
    assert resp["status"] == protocol.OK
    assert bytes(resp["ciphertext"]) == b"hush"

    # And the drop is gone after fetch.
    resp = protocol.decode(node._handle_fetch(
        "fetch", protocol.encode({"drop_id": drop_id}), 1, alice, 0
    ))
    assert resp["status"] == protocol.ERR_NOT_FOUND


def test_handle_list_requires_identity(node: DeadDropNode) -> None:
    resp = protocol.decode(node._handle_list("list", b"", 1, None, 0))
    assert resp["status"] == protocol.ERR_UNAUTHORIZED


def test_handle_info_reports_stats(node: DeadDropNode) -> None:
    alice = _identity_stub(b"A" * 16)
    node._handle_put(
        "put",
        protocol.encode({"recipient_hash": alice.hash, "ciphertext": b"x" * 10, "ttl_seconds": 60}),
        1,
        alice,
        0,
    )
    resp = protocol.decode(node._handle_info("info", b"", 1, alice, 0))
    assert resp["status"] == protocol.OK
    assert resp["drops"] == 1
    assert resp["bytes"] == 10
    assert resp["max_drop_bytes"] == 1024


def test_node_fills_up(node: DeadDropNode) -> None:
    alice = _identity_stub(b"A" * 16)
    # Fill the node to capacity (4096 bytes, 1024 per drop = 4 drops).
    for _ in range(4):
        resp = protocol.decode(node._handle_put(
            "put",
            protocol.encode({"recipient_hash": alice.hash, "ciphertext": b"x" * 1024, "ttl_seconds": 60}),
            1,
            alice,
            0,
        ))
        assert resp["status"] == protocol.OK
    # Next drop should be rejected as full.
    resp = protocol.decode(node._handle_put(
        "put",
        protocol.encode({"recipient_hash": alice.hash, "ciphertext": b"x" * 100, "ttl_seconds": 60}),
        1,
        alice,
        0,
    ))
    assert resp["status"] == protocol.ERR_FULL
