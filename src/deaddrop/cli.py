"""Command-line entry points for ``deaddrop`` and ``deaddrop-node``."""

from __future__ import annotations

import argparse
import binascii
import logging
import sys
from pathlib import Path

import RNS

from . import __version__
from .client import DeadDropClient, DeadDropError, PathNotFoundError
from .config import ClientConfig, NodeConfig
from .node import DeadDropNode


def _parse_hash(value: str) -> bytes:
    cleaned = value.strip().lower().removeprefix("<").removesuffix(">").replace(":", "")
    try:
        data = binascii.unhexlify(cleaned)
    except (binascii.Error, ValueError) as exc:
        raise argparse.ArgumentTypeError(f"invalid hex hash: {value}") from exc
    if len(data) != 16:
        raise argparse.ArgumentTypeError("hash must be 16 bytes (32 hex chars)")
    return data


def _configure_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


# =====================================================================
# deaddrop-node entry point
# =====================================================================


def _build_node_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="deaddrop-node", description="DeadDrop message store daemon.")
    parser.add_argument("--data-dir", type=Path, default=None, help="Override data directory (default: ~/.deaddrop)")
    parser.add_argument("-v", "--verbose", action="count", default=0)
    parser.add_argument("--version", action="version", version=f"deaddrop-node {__version__}")
    sub = parser.add_subparsers(dest="cmd")

    p_run = sub.add_parser("run", help="Run the node (default)")
    p_run.set_defaults(func=_cmd_node_run)

    p_info = sub.add_parser("info", help="Print this node's destination hash")
    p_info.set_defaults(func=_cmd_node_info)

    parser.set_defaults(func=_cmd_node_run)
    return parser


def _cmd_node_run(args) -> int:
    config = NodeConfig.from_env(args.data_dir)
    node = DeadDropNode(config)
    node.install_signal_handlers()
    node.run_forever()
    return 0


def _cmd_node_info(args) -> int:
    config = NodeConfig.from_env(args.data_dir)
    node = DeadDropNode(config)
    node.start()
    print(f"destination: {RNS.prettyhexrep(node.destination_hash)}")
    stats = node.store.stats()
    print(f"drops held:  {stats['drops']}")
    print(f"bytes held:  {stats['bytes']}")
    node.stop()
    return 0


def node_main(argv: list[str] | None = None) -> int:
    parser = _build_node_parser()
    args = parser.parse_args(argv)
    _configure_logging(args.verbose)
    return args.func(args)


# =====================================================================
# deaddrop client entry point
# =====================================================================


def _build_client_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="deaddrop", description="DeadDrop client.")
    parser.add_argument("--data-dir", type=Path, default=None)
    parser.add_argument("-v", "--verbose", action="count", default=0)
    parser.add_argument("--version", action="version", version=f"deaddrop {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_whoami = sub.add_parser("whoami", help="Print this client's identity hash")
    p_whoami.set_defaults(func=_cmd_whoami)

    p_pub = sub.add_parser("pubkey", help="Export this client's public key for out-of-band sharing")
    p_pub.add_argument("path", type=Path)
    p_pub.set_defaults(func=_cmd_pubkey)

    p_info = sub.add_parser("info", help="Query a dead-drop node for its info")
    p_info.add_argument("--node", type=_parse_hash, required=True)
    p_info.set_defaults(func=_cmd_info)

    p_send = sub.add_parser("send", help="Send a text message via a dead-drop node")
    p_send.add_argument("--node", type=_parse_hash, required=True)
    g = p_send.add_mutually_exclusive_group(required=True)
    g.add_argument("--to", type=_parse_hash, help="Recipient identity hash (must be in announce cache)")
    g.add_argument("--to-pubkey", type=Path, help="Path to recipient's exported public key file")
    p_send.add_argument("--message", required=True, help="Message text (UTF-8)")
    p_send.add_argument("--ttl", type=int, default=7 * 24 * 3600, help="Time-to-live in seconds")
    p_send.add_argument("--mime", default="text/plain; charset=utf-8")
    p_send.set_defaults(func=_cmd_send)

    p_send_file = sub.add_parser("send-file", help="Send a file via a dead-drop node")
    p_send_file.add_argument("--node", type=_parse_hash, required=True)
    g2 = p_send_file.add_mutually_exclusive_group(required=True)
    g2.add_argument("--to", type=_parse_hash)
    g2.add_argument("--to-pubkey", type=Path)
    p_send_file.add_argument("--file", type=Path, required=True)
    p_send_file.add_argument("--ttl", type=int, default=7 * 24 * 3600)
    p_send_file.add_argument("--mime", default="application/octet-stream")
    p_send_file.set_defaults(func=_cmd_send_file)

    p_list = sub.add_parser("list", help="List drops addressed to this client at a node")
    p_list.add_argument("--node", type=_parse_hash, required=True)
    p_list.set_defaults(func=_cmd_list)

    p_fetch = sub.add_parser("fetch", help="Fetch all drops addressed to this client (deletes them on the node)")
    p_fetch.add_argument("--node", type=_parse_hash, required=True)
    p_fetch.add_argument("--out-dir", type=Path, default=None, help="If set, write each drop's body to this directory")
    p_fetch.set_defaults(func=_cmd_fetch)

    return parser


def _resolve_recipient(args, client: DeadDropClient) -> RNS.Identity:
    if getattr(args, "to_pubkey", None):
        path = Path(args.to_pubkey)
        if not path.exists():
            raise SystemExit(f"pubkey file not found: {path}")
        identity = RNS.Identity(create_keys=False)
        with open(path, "rb") as fh:
            identity.load_public_key(fh.read())
        return identity
    recall = RNS.Identity.recall(args.to)
    if recall is None:
        raise SystemExit(
            f"no cached identity for {RNS.prettyhexrep(args.to)}; "
            "wait for an announce or use --to-pubkey"
        )
    return recall


def _cmd_whoami(args) -> int:
    config = ClientConfig.from_env(args.data_dir)
    client = DeadDropClient(config)
    client.start()
    print(RNS.prettyhexrep(client.identity_hash))
    return 0


def _cmd_pubkey(args) -> int:
    config = ClientConfig.from_env(args.data_dir)
    client = DeadDropClient(config)
    client.start()
    args.path.parent.mkdir(parents=True, exist_ok=True)
    client.identity.pub_to_file(str(args.path))
    print(f"wrote public key to {args.path}")
    print(f"identity hash: {RNS.prettyhexrep(client.identity_hash)}")
    return 0


def _cmd_info(args) -> int:
    config = ClientConfig.from_env(args.data_dir)
    client = DeadDropClient(config)
    try:
        info = client.info(args.node)
    except (DeadDropError, PathNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for k, v in info.items():
        if k == "status":
            continue
        print(f"{k}: {v}")
    return 0


def _cmd_send(args) -> int:
    config = ClientConfig.from_env(args.data_dir)
    client = DeadDropClient(config)
    client.start()
    recipient = _resolve_recipient(args, client)
    try:
        resp = client.send_message(
            node_hash=args.node,
            recipient_identity=recipient,
            body=args.message.encode("utf-8"),
            mime=args.mime,
            ttl_seconds=args.ttl,
        )
    except (DeadDropError, PathNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"dropped as id={resp['drop_id']}, expires_at={resp['expires_at']}")
    return 0


def _cmd_send_file(args) -> int:
    config = ClientConfig.from_env(args.data_dir)
    client = DeadDropClient(config)
    client.start()
    recipient = _resolve_recipient(args, client)
    body = args.file.read_bytes()
    try:
        resp = client.send_message(
            node_hash=args.node,
            recipient_identity=recipient,
            body=body,
            mime=args.mime,
            ttl_seconds=args.ttl,
        )
    except (DeadDropError, PathNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"dropped {len(body)} bytes as id={resp['drop_id']}, expires_at={resp['expires_at']}")
    return 0


def _cmd_list(args) -> int:
    config = ClientConfig.from_env(args.data_dir)
    client = DeadDropClient(config)
    try:
        drops = client.list_drops(args.node)
    except (DeadDropError, PathNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if not drops:
        print("(no drops)")
        return 0
    print(f"{'ID':>6}  {'SIZE':>8}  CREATED            EXPIRES")
    for d in drops:
        print(
            f"{d['id']:>6}  {d['size']:>8}  {d['created_at']}  {d['expires_at']}"
        )
    return 0


def _cmd_fetch(args) -> int:
    config = ClientConfig.from_env(args.data_dir)
    client = DeadDropClient(config)
    client.start()
    try:
        envelopes = client.fetch_all(args.node)
    except (DeadDropError, PathNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if not envelopes:
        print("(no drops)")
        return 0
    if args.out_dir:
        args.out_dir.mkdir(parents=True, exist_ok=True)
    for i, env in enumerate(envelopes, start=1):
        sender = (
            RNS.prettyhexrep(env.sender_hash) if env.sender_hash else "<anonymous>"
        )
        print(f"--- drop {i} from {sender} ({env.mime}, {len(env.body)} bytes) ---")
        if args.out_dir:
            target = args.out_dir / f"drop-{i:04d}.bin"
            target.write_bytes(env.body)
            print(f"  saved to {target}")
        elif env.mime.startswith("text/"):
            try:
                print(env.body.decode("utf-8"))
            except UnicodeDecodeError:
                print("(binary body; use --out-dir to save)")
        else:
            print("(binary body; use --out-dir to save)")
    return 0


def client_main(argv: list[str] | None = None) -> int:
    parser = _build_client_parser()
    args = parser.parse_args(argv)
    _configure_logging(args.verbose)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(client_main())
