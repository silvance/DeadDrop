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


# ---- padding (envelope v2) --------------------------------------------------

from deaddrop.crypto import (  # noqa: E402
    CIPHER_OVERHEAD,
    CIPHERTEXT_BUCKETS,
    PayloadTooLarge,
    max_body_bytes,
)


@pytest.mark.parametrize("body_len", [0, 1, 100, 1000, 5000, 20000, 60000])
def test_ciphertext_length_is_always_a_bucket(body_len: int) -> None:
    recipient = RNS.Identity()
    ciphertext = encrypt_for(recipient, b"\xaa" * body_len, sender_hash=b"S" * 16)
    assert len(ciphertext) in CIPHERTEXT_BUCKETS
    assert decrypt_with(recipient, ciphertext).body == b"\xaa" * body_len


def test_bucket_boundary() -> None:
    """A body that exactly fills a bucket stays in it; one more byte moves up."""
    recipient = RNS.Identity()
    mime = "text/plain"
    header_and_mime = 40 + len(mime)  # v2 header is 40 bytes
    fits =CIPHERTEXT_BUCKETS[0] - CIPHER_OVERHEAD - header_and_mime
    assert len(encrypt_for(recipient, b"x" * fits, mime=mime)) == CIPHERTEXT_BUCKETS[0]
    assert len(encrypt_for(recipient, b"x" * (fits + 1), mime=mime)) == CIPHERTEXT_BUCKETS[1]


def test_largest_body_fits_and_one_more_byte_does_not() -> None:
    recipient = RNS.Identity()
    limit = max_body_bytes()
    ciphertext = encrypt_for(recipient, b"x" * limit)
    assert len(ciphertext) == CIPHERTEXT_BUCKETS[-1]
    with pytest.raises(PayloadTooLarge):
        encrypt_for(recipient, b"x" * (limit + 1))


def test_padding_keeps_trailing_zero_bytes_in_body() -> None:
    body = b"data\x00\x00\x00"
    env = unpack_envelope(pack_envelope(b"R" * 16, body))
    assert env.body == body


def test_unpack_rejects_body_length_past_end() -> None:
    packed = bytearray(pack_envelope(b"R" * 16, b"hello", mime=""))
    # body_len lives at bytes 36..40 of the v2 header.
    packed[36:40] = (len(packed) + 1).to_bytes(4, "big")
    with pytest.raises(ValueError, match="truncated"):
        unpack_envelope(bytes(packed))


def test_version_1_envelope_still_decodes() -> None:
    """Drops written by deaddrop 0.1.0 (unpadded v1) remain readable."""
    import struct

    recipient = RNS.Identity()
    mime = b"text/plain"
    v1 = (
        struct.pack("!BB16s16sH", 1, 1, recipient.hash, b"S" * 16, len(mime))
        + mime
        + b"old drop"
    )
    env = decrypt_with(recipient, recipient.encrypt(v1))
    assert env.body == b"old drop"
    assert env.sender_hash == b"S" * 16
    assert env.mime == "text/plain"


def test_unknown_version_rejected() -> None:
    with pytest.raises(ValueError, match="version"):
        unpack_envelope(b"\x09" + b"\x00" * 64)
