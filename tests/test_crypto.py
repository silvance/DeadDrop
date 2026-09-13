"""Tests for the envelope format and end-to-end encryption."""

from __future__ import annotations

import pytest

RNS = pytest.importorskip("RNS")

from deaddrop.crypto import (  # noqa: E402
    Envelope,
    decrypt_with,
    encrypt_for,
    pack_envelope,
    unpack_envelope,
)


def test_envelope_round_trip() -> None:
    recipient = b"R" * 16
    sender = b"S" * 16
    packed = pack_envelope(recipient, b"hello", sender_hash=sender, mime="text/plain")
    env = unpack_envelope(packed)
    assert env == Envelope(
        recipient_hash=recipient,
        sender_hash=sender,
        mime="text/plain",
        body=b"hello",
    )


def test_envelope_anonymous_sender() -> None:
    recipient = b"R" * 16
    packed = pack_envelope(recipient, b"hi")
    env = unpack_envelope(packed)
    assert env.sender_hash is None
    assert env.body == b"hi"
    assert env.mime == "application/octet-stream"


def test_envelope_rejects_wrong_hash_length() -> None:
    with pytest.raises(ValueError):
        pack_envelope(b"short", b"x")
    with pytest.raises(ValueError):
        pack_envelope(b"R" * 16, b"x", sender_hash=b"too short")


def test_envelope_rejects_truncated_input() -> None:
    with pytest.raises(ValueError):
        unpack_envelope(b"\x01\x00")


def test_encrypt_for_and_decrypt_with_round_trip() -> None:
    recipient = RNS.Identity()
    sender = RNS.Identity()
    ciphertext = encrypt_for(
        recipient,
        b"top secret payload",
        sender_hash=sender.hash,
        mime="text/plain",
    )
    env = decrypt_with(recipient, ciphertext)
    assert env.body == b"top secret payload"
    assert env.sender_hash == sender.hash
    assert env.recipient_hash == recipient.hash


def test_decrypt_with_wrong_identity_fails() -> None:
    recipient = RNS.Identity()
    wrong = RNS.Identity()
    ciphertext = encrypt_for(recipient, b"x")
    with pytest.raises(ValueError):
        decrypt_with(wrong, ciphertext)


def test_envelope_recipient_mismatch_detected() -> None:
    # Hand-craft a payload whose internal recipient_hash doesn't match the
    # decrypting identity, then encrypt it for that identity. decrypt_with
    # should refuse it.
    target = RNS.Identity()
    bogus = pack_envelope(b"Z" * 16, b"x")
    ciphertext = target.encrypt(bogus)
    with pytest.raises(ValueError, match="recipient"):
        decrypt_with(target, ciphertext)
