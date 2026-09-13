"""Configuration paths and defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def default_data_dir() -> Path:
    env = os.environ.get("DEADDROP_HOME")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".deaddrop"


def default_reticulum_configdir() -> Path | None:
    env = os.environ.get("RETICULUM_CONFIGDIR")
    return Path(env).expanduser() if env else None


@dataclass(frozen=True)
class NodeConfig:
    data_dir: Path
    identity_path: Path
    db_path: Path
    reticulum_configdir: Path | None
    # Storage limits
    max_drop_bytes: int = 64 * 1024
    max_total_bytes: int = 256 * 1024 * 1024
    default_ttl_seconds: int = 7 * 24 * 3600
    max_ttl_seconds: int = 30 * 24 * 3600
    # Maintenance cadence
    sweep_interval_seconds: int = 300
    announce_interval_seconds: int = 1800

    @classmethod
    def from_env(cls, data_dir: Path | None = None) -> "NodeConfig":
        dd = (data_dir or default_data_dir()).resolve()
        dd.mkdir(parents=True, exist_ok=True)
        return cls(
            data_dir=dd,
            identity_path=dd / "node.identity",
            db_path=dd / "drops.sqlite",
            reticulum_configdir=default_reticulum_configdir(),
        )


@dataclass(frozen=True)
class ClientConfig:
    data_dir: Path
    identity_path: Path
    reticulum_configdir: Path | None
    request_timeout: float = 30.0

    @classmethod
    def from_env(cls, data_dir: Path | None = None) -> "ClientConfig":
        dd = (data_dir or default_data_dir()).resolve()
        dd.mkdir(parents=True, exist_ok=True)
        return cls(
            data_dir=dd,
            identity_path=dd / "client.identity",
            reticulum_configdir=default_reticulum_configdir(),
        )
