"""End-to-end envelope for dead-drop payloads.

The dead-drop node only ever sees ciphertext. Each drop carries a small
header so the recipient can sanity-check the payload (version, recipient
identity hash, optional sender identity hash, mime hint) before passing the
plaintext to the application.

The actual asymmetric encryption is delegated to Reticulum's
``RNS.Identity.encrypt`` / ``decrypt``, which uses X25519 + AES-128-CBC +
HMAC-SHA256 with ephemeral keys (forward secrecy per message).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

import RNS

ENVELOPE_VERSION = 1
_HEADER_FMT = "!BB16s16sH"  # version, flags, recipient_hash, sender_hash, mime_len
_HEADER_LEN = struct.calcsize(_HEADER_FMT)
_FLAG_HAS_SENDER = 0b0001

EMPTY_HASH = b"\x00" * 16


@dataclass(frozen=True)
class Envelope:
    """Plaintext-side view of an encrypted drop payload."""

    recipient_hash: bytes
    sender_hash: bytes | None
    mime: str
    body: bytes


def pack_envelope(
    recipient_hash: bytes,
    body: bytes,
    *,
    sender_hash: bytes | None = None,
    mime: str = "application/octet-stream",
) -> bytes:
    if len(recipient_hash) != 16:
        raise ValueError("recipient_hash must be 16 bytes (Reticulum truncated hash)")
    if sender_hash is not None and len(sender_hash) != 16:
        raise ValueError("sender_hash must be 16 bytes when provided")
    mime_bytes = mime.encode("utf-8")
    if len(mime_bytes) > 0xFFFF:
        raise ValueError("mime too long")
    flags = _FLAG_HAS_SENDER if sender_hash is not None else 0
    header = struct.pack(
        _HEADER_FMT,
        ENVELOPE_VERSION,
        flags,
        recipient_hash,
        sender_hash or EMPTY_HASH,
        len(mime_bytes),
    )
    return header + mime_bytes + body


def unpack_envelope(plaintext: bytes) -> Envelope:
    if len(plaintext) < _HEADER_LEN:
        raise ValueError("plaintext too short for envelope header")
    version, flags, recipient, sender, mime_len = struct.unpack(
        _HEADER_FMT, plaintext[:_HEADER_LEN]
    )
    if version != ENVELOPE_VERSION:
        raise ValueError(f"unsupported envelope version {version}")
    body_start = _HEADER_LEN + mime_len
    if len(plaintext) < body_start:
        raise ValueError("plaintext truncated in mime field")
    mime = plaintext[_HEADER_LEN:body_start].decode("utf-8")
    body = plaintext[body_start:]
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

    Returns the ciphertext blob that the dead-drop node stores opaquely.
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
