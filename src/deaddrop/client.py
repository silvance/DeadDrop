"""DeadDrop client.

Talks to a remote node over a Reticulum Link. The link is set up on demand
and torn down after each request batch — appropriate for intermittent
LoRA contact.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import RNS

from . import APP_NAME, NODE_ASPECT
from .config import ClientConfig
from .crypto import Envelope, decrypt_with, encrypt_for
from .protocol import (
    OK,
    PATH_FETCH,
    PATH_INFO,
    PATH_LIST,
    PATH_PUT,
    decode,
    encode,
)

log = logging.getLogger(__name__)


class DeadDropError(Exception):
    """Raised for protocol-level failures."""


class PathNotFoundError(DeadDropError):
    """Raised when no Reticulum path to the node can be discovered."""


class RequestTimeout(DeadDropError):
    """Raised when a request to the node times out."""


@dataclass
class _Pending:
    event: threading.Event
    response: Any = None
    failed: bool = False
    error: str | None = None


class _LinkSession:
    """Single-shot Link wrapper with request/response helpers."""

    def __init__(self, link: RNS.Link, timeout: float):
        self.link = link
        self.timeout = timeout

    def request(self, path: str, payload: dict | None = None) -> dict:
        pending = _Pending(event=threading.Event())

        def on_response(receipt):
            try:
                resp = receipt.response
                pending.response = decode(resp) if isinstance(resp, (bytes, bytearray)) else resp
            except Exception as exc:
                pending.failed = True
                pending.error = f"decode error: {exc}"
            finally:
                pending.event.set()

        def on_failed(receipt):
            pending.failed = True
            pending.error = "request failed"
            pending.event.set()

        self.link.request(
            path,
            data=encode(payload or {}),
            response_callback=on_response,
            failed_callback=on_failed,
            timeout=self.timeout,
        )

        if not pending.event.wait(self.timeout + 1.0):
            raise RequestTimeout(f"no response to {path} within {self.timeout}s")
        if pending.failed:
            raise DeadDropError(pending.error or "request failed")
        if not isinstance(pending.response, dict):
            raise DeadDropError("malformed response payload")
        if pending.response.get("status") != OK:
            raise DeadDropError(
                pending.response.get("error") or f"node returned status {pending.response.get('status')}"
            )
        return pending.response

    def close(self) -> None:
        try:
            self.link.teardown()
        except Exception:
            pass


class DeadDropClient:
    def __init__(self, config: ClientConfig):
        self.config = config
        self._reticulum: RNS.Reticulum | None = None
        self._identity: RNS.Identity | None = None
        self._client_destination: RNS.Destination | None = None

    # ---- lifecycle ------------------------------------------------------

    def start(self) -> None:
        if self._reticulum is not None:
            return
        configdir = (
            str(self.config.reticulum_configdir)
            if self.config.reticulum_configdir
            else None
        )
        self._reticulum = RNS.Reticulum(configdir=configdir)
        self._identity = self._load_or_create_identity(self.config.identity_path)
        # OUT destination so transport authenticates our identity on the link.
        self._client_destination = RNS.Destination(
            self._identity,
            RNS.Destination.IN,
            RNS.Destination.SINGLE,
            APP_NAME,
            "client",
        )

    @property
    def identity(self) -> RNS.Identity:
        if self._identity is None:
            raise RuntimeError("client not started")
        return self._identity

    @property
    def identity_hash(self) -> bytes:
        return self.identity.hash

    # ---- core RPC -------------------------------------------------------

    def info(self, node_hash: bytes) -> dict:
        with self._open(node_hash) as session:
            return session.request(PATH_INFO)

    def put(
        self,
        node_hash: bytes,
        recipient_hash: bytes,
        ciphertext: bytes,
        ttl_seconds: int,
    ) -> dict:
        with self._open(node_hash) as session:
            return session.request(
                PATH_PUT,
                {
                    "recipient_hash": recipient_hash,
                    "ciphertext": ciphertext,
                    "ttl_seconds": ttl_seconds,
                },
            )

    def list_drops(self, node_hash: bytes) -> list[dict]:
        with self._open(node_hash) as session:
            resp = session.request(PATH_LIST)
        return resp.get("drops", [])

    def fetch_drop(self, node_hash: bytes, drop_id: int) -> bytes:
        with self._open(node_hash) as session:
            resp = session.request(PATH_FETCH, {"drop_id": drop_id})
        return bytes(resp["ciphertext"])

    # ---- higher-level helpers ------------------------------------------

    def send_message(
        self,
        node_hash: bytes,
        recipient_identity: RNS.Identity,
        body: bytes,
        *,
        mime: str = "application/octet-stream",
        ttl_seconds: int = 7 * 24 * 3600,
    ) -> dict:
        """Encrypt ``body`` to ``recipient_identity`` and drop it at ``node_hash``."""
        ciphertext = encrypt_for(
            recipient_identity,
            body,
            sender_hash=self.identity_hash,
            mime=mime,
        )
        return self.put(
            node_hash=node_hash,
            recipient_hash=recipient_identity.hash,
            ciphertext=ciphertext,
            ttl_seconds=ttl_seconds,
        )

    def fetch_all(self, node_hash: bytes) -> list[Envelope]:
        """Fetch every drop addressed to this client's identity, decrypt them."""
        envelopes: list[Envelope] = []
        for summary in self.list_drops(node_hash):
            ciphertext = self.fetch_drop(node_hash, summary["id"])
            try:
                envelopes.append(decrypt_with(self.identity, ciphertext))
            except ValueError as exc:
                log.warning("could not decrypt drop %s: %s", summary["id"], exc)
        return envelopes

    # ---- link plumbing --------------------------------------------------

    def _open(self, node_hash: bytes) -> "_LinkContext":
        self.start()
        return _LinkContext(self, node_hash)

    def _establish_link(self, node_hash: bytes) -> RNS.Link:
        if len(node_hash) != 16:
            raise ValueError("node_hash must be 16 bytes")
        if not RNS.Transport.has_path(node_hash):
            RNS.Transport.request_path(node_hash)
            deadline = time.time() + self.config.request_timeout
            while time.time() < deadline and not RNS.Transport.has_path(node_hash):
                time.sleep(0.1)
            if not RNS.Transport.has_path(node_hash):
                raise PathNotFoundError(
                    f"no path to {RNS.prettyhexrep(node_hash)} within {self.config.request_timeout}s"
                )
        node_identity = RNS.Identity.recall(node_hash)
        if node_identity is None:
            raise PathNotFoundError(
                f"identity for {RNS.prettyhexrep(node_hash)} not in announce cache"
            )
        destination = RNS.Destination(
            node_identity,
            RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            APP_NAME,
            NODE_ASPECT,
        )
        link = RNS.Link(destination)
        link.identify(self.identity)

        established = threading.Event()
        closed = threading.Event()

        def on_established(_link):
            established.set()

        def on_closed(_link):
            closed.set()
            established.set()  # unblock the waiter if we never got established

        link.set_link_established_callback(on_established)
        link.set_link_closed_callback(on_closed)

        if not established.wait(self.config.request_timeout):
            try:
                link.teardown()
            except Exception:
                pass
            raise RequestTimeout("link establishment timed out")
        if link.status != RNS.Link.ACTIVE:
            raise DeadDropError("link did not reach ACTIVE state")
        return link

    @staticmethod
    def _load_or_create_identity(path: Path) -> RNS.Identity:
        if path.exists():
            return RNS.Identity.from_file(str(path))
        identity = RNS.Identity()
        path.parent.mkdir(parents=True, exist_ok=True)
        identity.to_file(str(path))
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return identity


class _LinkContext:
    """Context manager that owns a Link for the duration of a request batch."""

    def __init__(self, client: DeadDropClient, node_hash: bytes):
        self._client = client
        self._node_hash = node_hash
        self._session: _LinkSession | None = None

    def __enter__(self) -> _LinkSession:
        link = self._client._establish_link(self._node_hash)
        self._session = _LinkSession(link, self._client.config.request_timeout)
        return self._session

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._session is not None:
            self._session.close()
