"""Argument parsing tests for the CLI entry points."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("RNS")

from deaddrop.cli import _build_client_parser, _build_node_parser  # noqa: E402

NODE_HEX = "00" * 16


def test_node_run_accepts_verbose_after_subcommand() -> None:
    """``deaddrop-node run -v`` is the systemd unit's ExecStart line."""
    args = _build_node_parser().parse_args(["run", "-v"])
    assert args.cmd == "run"
    assert args.verbose == 1


def test_node_options_before_subcommand_still_work() -> None:
    args = _build_node_parser().parse_args(["-vv", "--data-dir", "/srv/dd", "run"])
    assert args.verbose == 2
    assert args.data_dir == Path("/srv/dd")


def test_node_defaults_to_run() -> None:
    args = _build_node_parser().parse_args([])
    assert args.func.__name__ == "_cmd_node_run"
    assert args.verbose == 0
    assert args.data_dir is None


def test_client_accepts_options_after_subcommand() -> None:
    args = _build_client_parser().parse_args(
        ["list", "--node", NODE_HEX, "-v", "--data-dir", "/tmp/dd"]
    )
    assert args.verbose == 1
    assert args.data_dir == Path("/tmp/dd")
