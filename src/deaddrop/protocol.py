"""Wire protocol between client and dead-drop node.

Requests are dispatched on a Reticulum ``Link`` via named paths. All payloads
are encoded with the umsgpack implementation that ships with Reticulum, so we
take no extra dependency.
"""

from __future__ import annotations

from typing import Any

from RNS.vendor import umsgpack

# Reticulum Link request paths.
PATH_INFO = "info"
PATH_PUT = "put"
PATH_LIST = "list"
PATH_FETCH = "fetch"

# Status codes returned on responses.
OK = 0
ERR_RATE_LIMIT = 1
ERR_TOO_LARGE = 2
ERR_FULL = 3
ERR_NOT_FOUND = 4
ERR_BAD_REQUEST = 5
ERR_UNAUTHORIZED = 6
ERR_INTERNAL = 99


def encode(payload: Any) -> bytes:
    return umsgpack.packb(payload)


def decode(blob: bytes) -> Any:
    return umsgpack.unpackb(blob)


def ok(**fields: Any) -> bytes:
    return encode({"status": OK, **fields})


def err(code: int, message: str) -> bytes:
    return encode({"status": code, "error": message})
