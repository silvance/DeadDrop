"""End-to-end envelope for dead-drop payloads.

The dead-drop node only ever sees ciphertext. Each drop carries a small
header so the recipient can sanity-check the payload (version, recipient
identity hash, optional sender identity hash, mime hint) before passing the
plaintext to the application.

The actual asymmetric encryption is delegated to Reticulum's
``RNS.Identity.encrypt`` / ``decrypt``: an ephemeral X25519 key is agreed
against the recipient's *long-term* X25519 key, then the payload is sealed
with AES-CBC + HMAC-SHA256 (AES-256 in current Reticulum releases).

There is **no forward secrecy** for stored drops. The ephemeral key only
hides the sender side; anyone who later obtains the recipient's identity
private key can decrypt every drop they copied off a node beforehand.
Forward secrecy applies only to Reticulum Link traffic in transit.

The ``sender_hash`` inside the envelope is an unauthenticated claim: anyone
holding the recipient's public key can put any value there.

Version 2 envelopes are zero-padded so the ciphertext length is exactly one
of ``CIPHERTEXT_BUCKETS``; the node (and anyone who seizes it) learns only
which size bucket a drop falls into, not its real length.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

import RNS

ENVELOPE_VERSION = 2
_HEADER_V1_FMT = "!BB16s16sH"  # version, flags, recipient_hash, sender_hash, mime_len
_HEADER_V2_FMT = "!BB16s16sHI"  # ... + body_len
_HEADER_V1_LEN = struct.calcsize(_HEADER_V1_FMT)
_HEADER_V2_LEN = struct.calcsize(_HEADER_V2_FMT)
_FLAG_HAS_SENDER = 0b0001

EMPTY_HASH = b"\x00" * 16

# Bytes RNS.Identity.encrypt adds to a plaintext whose length is a multiple
# of the AES block size: ephemeral X25519 pubkey (32) + IV (16) + one full
# PKCS7 padding block (16) + HMAC-SHA256 (32).
CIPHER_OVERHEAD = 96

# Allowed ciphertext sizes. The largest equals the node's default
# max_drop_bytes, so every padded drop fits a default node.
CIPHERTEXT_BUCKETS = (256, 1024, 4096, 16384, 65536)


class PayloadTooLarge(ValueError):
    """Raised when a body does not fit in the largest padding bucket."""


@dataclass(frozen=True)
class Envelope:
    """Plaintext-side view of an encrypted drop payload."""

    recipient_hash: bytes
    sender_hash: bytes | None
    mime: str
    body: bytes


def max_body_bytes(mime: str = "application/octet-stream") -> int:
    """Largest body that fits in the largest bucket with this mime type."""
    return (
        CIPHERTEXT_BUCKETS[-1]
        - CIPHER_OVERHEAD
        - _HEADER_V2_LEN
        - len(mime.encode("utf-8"))
    )


def _padded_length(unpadded: int) -> int:
    for bucket in CIPHERTEXT_BUCKETS:
        target = bucket - CIPHER_OVERHEAD
        if unpadded <= target:
            return target
    raise PayloadTooLarge(
        f"envelope of {unpadded} bytes exceeds the largest bucket "
        f"({CIPHERTEXT_BUCKETS[-1]} bytes of ciphertext)"
    )


def pack_envelope(
    recipient_hash: bytes,
    body: bytes,
    *,
    sender_hash: bytes | None = None,
    mime: str = "application/octet-stream",
) -> bytes:
    """Build a padded version 2 envelope ready for encryption."""
    if len(recipient_hash) != 16:
        raise ValueError("recipient_hash must be 16 bytes (Reticulum truncated hash)")
    if sender_hash is not None and len(sender_hash) != 16:
        raise ValueError("sender_hash must be 16 bytes when provided")
    mime_bytes = mime.encode("utf-8")
    if len(mime_bytes) > 0xFFFF:
        raise ValueError("mime too long")
    flags = _FLAG_HAS_SENDER if sender_hash is not None else 0
    header = struct.pack(
        _HEADER_V2_FMT,
        ENVELOPE_VERSION,
        flags,
        recipient_hash,
        sender_hash or EMPTY_HASH,
        len(mime_bytes),
        len(body),
    )
    unpadded = header + mime_bytes + body
    return unpadded + b"\x00" * (_padded_length(len(unpadded)) - len(unpadded))


def unpack_envelope(plaintext: bytes) -> Envelope:
    """Parse a version 1 (unpadded) or version 2 (padded) envelope."""
    if len(plaintext) < 1:
        raise ValueError("plaintext too short for envelope header")
    version = plaintext[0]
    if version == 1:
        header_len = _HEADER_V1_LEN
        if len(plaintext) < header_len:
            raise ValueError("plaintext too short for envelope header")
        _, flags, recipient, sender, mime_len = struct.unpack(
            _HEADER_V1_FMT, plaintext[:header_len]
        )
        body_len = None
    elif version == 2:
        header_len = _HEADER_V2_LEN
        if len(plaintext) < header_len:
            raise ValueError("plaintext too short for envelope header")
        _, flags, recipient, sender, mime_len, body_len = struct.unpack(
            _HEADER_V2_FMT, plaintext[:header_len]
        )
    else:
        raise ValueError(f"unsupported envelope version {version}")

    body_start = header_len + mime_len
    if len(plaintext) < body_start:
        raise ValueError("plaintext truncated in mime field")
    mime = plaintext[header_len:body_start].decode("utf-8")
    if body_len is None:
        body = plaintext[body_start:]
    else:
        body_end = body_start + body_len
        if len(plaintext) < body_end:
            raise ValueError("plaintext truncated in body field")
        body = plaintext[body_start:body_end]
    sender_hash = sender if flags & _FLAG_HAS_SENDER else None
    return Envelope(
        recipient_hash=recipient,
        sender_hash=sender_hash,
        mime=mime,
        body=body,
    )


def encrypt_for(
    recipient_identity: "RNS.Identity",
    body: bytes,
    *,
    sender_hash: bytes | None = None,
    mime: str = "application/octet-stream",
) -> bytes:
    """Encrypt ``body`` to ``recipient_identity``'s public key.

    Returns the ciphertext blob that the dead-drop node stores opaquely. Its
    length is always one of ``CIPHERTEXT_BUCKETS``. Raises
    ``PayloadTooLarge`` if ``body`` does not fit the largest bucket.
    """
    plaintext = pack_envelope(
        recipient_hash=recipient_identity.hash,
        body=body,
        sender_hash=sender_hash,
        mime=mime,
    )
    return recipient_identity.encrypt(plaintext)


def decrypt_with(
    own_identity: "RNS.Identity", ciphertext: bytes
) -> Envelope:
    """Decrypt a drop and parse its envelope.

    Raises ``ValueError`` if decryption fails or the envelope is malformed,
    or if the embedded recipient hash does not match ``own_identity``.
    """
    plaintext = own_identity.decrypt(ciphertext)
    if plaintext is None:
        raise ValueError("decryption failed")
    env = unpack_envelope(plaintext)
    if env.recipient_hash != own_identity.hash:
        raise ValueError("envelope recipient does not match identity")
    return env
