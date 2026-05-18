"""DeadDrop node daemon.

Runs a Reticulum destination that accepts encrypted drops and hands them
back to the authenticated recipient on request. The node never sees
plaintext: the ciphertext is opaque to it.
"""

from __future__ import annotations

import logging
import signal
import threading
import time
from pathlib import Path

import RNS

from . import APP_NAME, NODE_ASPECT, __version__
from .config import NodeConfig
from .protocol import (
    PATH_FETCH,
    PATH_INFO,
    PATH_LIST,
    PATH_PUT,
    decode,
    encode,
    err,
    ok,
    ERR_BAD_REQUEST,
    ERR_FULL,
    ERR_INTERNAL,
    ERR_NOT_FOUND,
    ERR_TOO_LARGE,
    ERR_UNAUTHORIZED,
)
from .storage import DropStore

log = logging.getLogger(__name__)


class DeadDropNode:
    def __init__(self, config: NodeConfig):
        self.config = config
        self.store = DropStore(config.db_path)
        self._stop = threading.Event()
        self._reticulum: RNS.Reticulum | None = None
        self._identity: RNS.Identity | None = None
        self._destination: RNS.Destination | None = None

    # ---- lifecycle ------------------------------------------------------

    def start(self) -> None:
        configdir = (
            str(self.config.reticulum_configdir)
            if self.config.reticulum_configdir
            else None
        )
        self._reticulum = RNS.Reticulum(configdir=configdir)
        self._identity = self._load_or_create_identity(self.config.identity_path)
        self._destination = RNS.Destination(
            self._identity,
            RNS.Destination.IN,
            RNS.Destination.SINGLE,
            APP_NAME,
            NODE_ASPECT,
        )
        self._destination.set_proof_strategy(RNS.Destination.PROVE_ALL)
        self._destination.register_request_handler(
            PATH_INFO, response_generator=self._handle_info, allow=RNS.Destination.ALLOW_ALL
        )
        self._destination.register_request_handler(
            PATH_PUT, response_generator=self._handle_put, allow=RNS.Destination.ALLOW_ALL
        )
        self._destination.register_request_handler(
            PATH_LIST, response_generator=self._handle_list, allow=RNS.Destination.ALLOW_ALL
        )
        self._destination.register_request_handler(
            PATH_FETCH, response_generator=self._handle_fetch, allow=RNS.Destination.ALLOW_ALL
        )

        self._destination.announce()
        log.info(
            "deaddrop-node %s up, destination %s",
            __version__,
            RNS.prettyhexrep(self._destination.hash),
        )

        self._spawn(self._announce_loop, name="announce")
        self._spawn(self._sweep_loop, name="sweep")

    def stop(self) -> None:
        self._stop.set()
        log.info("deaddrop-node shutting down")

    def run_forever(self) -> None:
        self.start()
        try:
            while not self._stop.wait(1.0):
                pass
        finally:
            self.stop()

    def install_signal_handlers(self) -> None:
        def _handler(signum, _frame):
            log.info("received signal %s", signum)
            self.stop()

        signal.signal(signal.SIGINT, _handler)
        signal.signal(signal.SIGTERM, _handler)

    # ---- request handlers ----------------------------------------------

    def _handle_info(self, path, data, request_id, remote_identity, requested_at):
        stats = self.store.stats()
        return ok(
            version=__version__,
            drops=stats["drops"],
            bytes=stats["bytes"],
            max_drop_bytes=self.config.max_drop_bytes,
            max_total_bytes=self.config.max_total_bytes,
            max_ttl_seconds=self.config.max_ttl_seconds,
            default_ttl_seconds=self.config.default_ttl_seconds,
        )

    def _handle_put(self, path, data, request_id, remote_identity, requested_at):
        try:
            req = decode(data) if data else {}
        except Exception:
            return err(ERR_BAD_REQUEST, "malformed request")
        recipient = req.get("recipient_hash")
        ciphertext = req.get("ciphertext")
        ttl = int(req.get("ttl_seconds", self.config.default_ttl_seconds))
        if not isinstance(recipient, (bytes, bytearray)) or len(recipient) != 16:
            return err(ERR_BAD_REQUEST, "recipient_hash must be 16 bytes")
        if not isinstance(ciphertext, (bytes, bytearray)) or len(ciphertext) == 0:
            return err(ERR_BAD_REQUEST, "ciphertext required")
        if len(ciphertext) > self.config.max_drop_bytes:
            return err(ERR_TOO_LARGE, "drop exceeds max_drop_bytes")
        if ttl <= 0 or ttl > self.config.max_ttl_seconds:
            return err(ERR_BAD_REQUEST, "ttl_seconds out of range")

        stats = self.store.stats()
        if stats["bytes"] + len(ciphertext) > self.config.max_total_bytes:
            return err(ERR_FULL, "node storage is full")

        sender_hint = remote_identity.hash if remote_identity is not None else None
        try:
            record = self.store.put(
                recipient_hash=bytes(recipient),
                ciphertext=bytes(ciphertext),
                ttl_seconds=ttl,
                sender_hint=sender_hint,
            )
        except Exception as exc:
            log.exception("put failed: %s", exc)
            return err(ERR_INTERNAL, "store error")
        return ok(drop_id=record.id, expires_at=record.expires_at)

    def _handle_list(self, path, data, request_id, remote_identity, requested_at):
        if remote_identity is None:
            return err(ERR_UNAUTHORIZED, "link identity required")
        try:
            summaries = self.store.list_for(remote_identity.hash)
        except Exception as exc:
            log.exception("list failed: %s", exc)
            return err(ERR_INTERNAL, "store error")
        return ok(
            drops=[
                {
                    "id": s.id,
                    "size": s.size,
                    "created_at": s.created_at,
                    "expires_at": s.expires_at,
                }
                for s in summaries
            ]
        )

    def _handle_fetch(self, path, data, request_id, remote_identity, requested_at):
        if remote_identity is None:
            return err(ERR_UNAUTHORIZED, "link identity required")
        try:
            req = decode(data) if data else {}
        except Exception:
            return err(ERR_BAD_REQUEST, "malformed request")
        drop_id = req.get("drop_id")
        if not isinstance(drop_id, int):
            return err(ERR_BAD_REQUEST, "drop_id required")
        record = self.store.fetch(drop_id, remote_identity.hash)
        if record is None:
            return err(ERR_NOT_FOUND, "no such drop for this identity")
        self.store.delete(record.id, remote_identity.hash)
        return ok(
            drop_id=record.id,
            ciphertext=record.ciphertext,
            created_at=record.created_at,
            expires_at=record.expires_at,
        )

    # ---- maintenance ----------------------------------------------------

    def _announce_loop(self) -> None:
        interval = self.config.announce_interval_seconds
        # Initial announce happened in start(); wait then loop.
        while not self._stop.wait(interval):
            if self._destination is not None:
                try:
                    self._destination.announce()
                    log.debug("announced destination")
                except Exception:
                    log.exception("announce failed")

    def _sweep_loop(self) -> None:
        interval = self.config.sweep_interval_seconds
        while not self._stop.wait(interval):
            try:
                removed = self.store.sweep_expired()
                if removed:
                    log.info("swept %d expired drops", removed)
            except Exception:
                log.exception("sweep failed")

    # ---- helpers --------------------------------------------------------

    def _spawn(self, target, name: str) -> None:
        t = threading.Thread(target=target, name=f"deaddrop-{name}", daemon=True)
        t.start()

    @staticmethod
    def _load_or_create_identity(path: Path) -> RNS.Identity:
        if path.exists():
            return RNS.Identity.from_file(str(path))
        identity = RNS.Identity()
        path.parent.mkdir(parents=True, exist_ok=True)
        identity.to_file(str(path))
        # Best-effort tight perms on the secret key.
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return identity

    @property
    def destination_hash(self) -> bytes | None:
        return self._destination.hash if self._destination else None
