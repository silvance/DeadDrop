# DeadDrop

A Reticulum-native **dead-drop message store** for LoRA mesh networks.

DeadDrop is a tiny daemon (and matching CLI client) that holds **end-to-end
encrypted** messages addressed to recipients — keyed by their Reticulum
identity hash — until those recipients come within radio range to retrieve
them. The node itself never sees plaintext, and only the addressed recipient
can list or fetch a drop, because every request rides an authenticated
Reticulum `Link`.

It's designed for the kind of intermittent, low-bandwidth, asynchronous
contact you get over LoRa: a relay sits in a fixed location, senders and
receivers wander past, leaving and picking up envelopes.

> Intended for legal use cases — amateur radio, emergency / disaster mesh,
> field journalism, off-grid coordination, research and CTFs. The cryptography
> protects messages, not operators; comply with the laws of your jurisdiction.

## How it works

```
   sender                  dead-drop node                 recipient
   ──────                  ──────────────                 ─────────
1. pad body to a size
   bucket, encrypt to
   recipient's RNS
   identity public key
2. anonymous Link →
   node, "put" ────────► store ciphertext in
                            SQLite, keyed by
                            recipient_hash
                                                ◄── 3. Link → node, "list"
                                                        (Link authenticates
                                                         recipient identity)
                                                ◄── 4. Link → node, "fetch"
                                                        node verifies
                                                        recipient_hash ==
                                                        Link.remote_identity.hash
                                                        before releasing,
                                                        then deletes.
                                                5. recipient decrypts
                                                   with their identity
```

The node holds **opaque ciphertext**. It has no decryption key. The
authorization check is fundamental: a request handler is invoked with the
Link's authenticated `remote_identity`, and `list` / `fetch` only return
drops where `recipient_hash == remote_identity.hash`.

Senders never identify themselves to the node: `put` runs over an
anonymous Link, and the node stores nothing about who made a drop.

## Install

```bash
pip install -e '.[dev]'
```

Python 3.10+ and the [Reticulum Network Stack](https://reticulum.network/)
(`rns`) are required. The Python package ships an `rnsd` daemon and the
interface drivers (TCP, RNode/LoRa, I2P, etc.); DeadDrop just sits on top
of `RNS.Destination` / `RNS.Link`.

## Quick start (one host, TCP transport)

Two terminals, same machine, two Reticulum config dirs.

### 1. Configure Reticulum

Create two config dirs and drop the example config into each:

```bash
mkdir -p /tmp/dd-node/reticulum /tmp/dd-alice/reticulum /tmp/dd-bob/reticulum
cp deploy/reticulum.conf.example /tmp/dd-node/reticulum/config
# Bob/Alice should run TCPClientInterface pointing at the node; edit accordingly:
sed -e 's/TCPServerInterface/TCPClientInterface/' \
    -e 's/listen_ip = 0.0.0.0/target_host = 127.0.0.1/' \
    -e 's/listen_port = 4242/target_port = 4242/' \
    deploy/reticulum.conf.example > /tmp/dd-alice/reticulum/config
cp /tmp/dd-alice/reticulum/config /tmp/dd-bob/reticulum/config
```

### 2. Start the dead-drop node

```bash
DEADDROP_HOME=/tmp/dd-node \
RETICULUM_CONFIGDIR=/tmp/dd-node/reticulum \
deaddrop-node run -v
```

It will print its **destination hash** — copy it; senders and receivers
need it. Example:

```
deaddrop-node 0.2.0 up, destination <1c4b…7e9a>
```

### 3. Bob (recipient) publishes his identity

In a third terminal:

```bash
export DEADDROP_HOME=/tmp/dd-bob RETICULUM_CONFIGDIR=/tmp/dd-bob/reticulum
deaddrop whoami                  # prints Bob's identity hash
deaddrop pubkey /tmp/bob.pub     # exports Bob's public key for out-of-band share
```

Send `bob.pub` (and his hash) to Alice through any other channel.

### 4. Alice sends Bob a message

```bash
export DEADDROP_HOME=/tmp/dd-alice RETICULUM_CONFIGDIR=/tmp/dd-alice/reticulum
deaddrop send \
  --node <NODE_HASH_FROM_STEP_2> \
  --to-pubkey /tmp/bob.pub \
  --message "meet at the bench, sundown"
```

Output:
```
dropped as id=1, expires_at=1716123456
```

### 5. Bob picks it up

```bash
export DEADDROP_HOME=/tmp/dd-bob RETICULUM_CONFIGDIR=/tmp/dd-bob/reticulum
deaddrop list  --node <NODE_HASH>
deaddrop fetch --node <NODE_HASH>
```

`fetch` decrypts each drop with Bob's identity and removes it from the node.

## Switching to LoRa

Edit your Reticulum config and replace the `TCP*Interface` block with
`RNodeInterface` (see `deploy/reticulum.conf.example`). No DeadDrop code
changes are needed — the transport is entirely Reticulum's concern.

Every drop is padded to one of five ciphertext sizes: 256 B, 1 KiB,
4 KiB, 16 KiB or 64 KiB. A short text message costs 256 bytes on air. The
largest body you can send is a little under 64 KiB (`deaddrop send` tells
you the exact limit if you go over). On LoRa, keep messages in the small
buckets; Reticulum handles fragmentation automatically, but a 64 KiB drop
takes a long time at LoRa data rates.

## Production deployment

A hardened systemd unit lives in `deploy/deaddrop-node.service`. Quick
install:

```bash
sudo useradd --system --create-home --home /var/lib/deaddrop --shell /usr/sbin/nologin deaddrop
sudo cp deploy/deaddrop-node.service /etc/systemd/system/
sudo mkdir -p /var/lib/deaddrop/reticulum
sudo cp deploy/reticulum.conf.example /var/lib/deaddrop/reticulum/config
sudo chown -R deaddrop:deaddrop /var/lib/deaddrop
sudo systemctl daemon-reload
sudo systemctl enable --now deaddrop-node
```

If you're running over a serial RNode, remove `PrivateDevices=true` from
the unit and add `SupplementaryGroups=dialout`.

## Configuration

Two environment variables drive everything:

| variable             | default          | meaning                                       |
|----------------------|------------------|-----------------------------------------------|
| `DEADDROP_HOME`      | `~/.deaddrop`    | Identity + SQLite store live here             |
| `RETICULUM_CONFIGDIR`| `~/.reticulum`   | Passed to `RNS.Reticulum(configdir=...)`      |

Node defaults (edit in `deaddrop/config.py` or wrap with your own runner):

| setting                   | default   |
|---------------------------|-----------|
| `max_drop_bytes`          | 64 KiB    |
| `max_total_bytes`         | 256 MiB   |
| `default_ttl_seconds`     | 7 days    |
| `max_ttl_seconds`         | 30 days   |
| `sweep_interval_seconds`  | 5 min     |
| `announce_interval_seconds` | 30 min  |

## Protocol

Every client→node request is a Reticulum `Link.request(path, data)`. Data
is msgpack-encoded (using `RNS.vendor.umsgpack`, so no extra dep).

| path    | request                                                                  | response                                                           | auth?             |
|---------|--------------------------------------------------------------------------|--------------------------------------------------------------------|-------------------|
| `info`  | `{}`                                                                     | `{status, version, drops, bytes, max_drop_bytes, max_ttl_seconds}` | not required      |
| `put`   | `{recipient_hash: bytes(16), ciphertext: bytes, ttl_seconds: int}`       | `{status, drop_id, expires_at}`                                    | none — client does not identify, node records no sender |
| `list`  | `{}`                                                                     | `{status, drops: [{id, size, created_at, expires_at}]}`            | **must match recipient** |
| `fetch` | `{drop_id: int}`                                                         | `{status, drop_id, ciphertext, created_at, expires_at}`            | **must match recipient** |

Status `0` is OK; non-zero codes are defined in `deaddrop/protocol.py`.

The envelope inside `ciphertext` (after asymmetric decryption with the
recipient's RNS identity) is:

```
+--------+--------+----------------+-----------------+----------+----------+-------+------+---------+
| ver(2) | flags  | recipient_hash | sender_hash     | mime_len | body_len | mime  | body | padding |
| u8     | u8     | 16 bytes       | 16 bytes (or 0) | u16 BE   | u32 BE   | utf-8 | ...  | zeros   |
+--------+--------+----------------+-----------------+----------+----------+-------+------+---------+
```

`flags & 1` indicates the sender hash is present. The zero padding brings
the plaintext to `bucket − 96` bytes, so after encryption the ciphertext is
exactly 256, 1024, 4096, 16384 or 65536 bytes (96 bytes is what
`Identity.encrypt` adds: ephemeral key, IV, one padding block and HMAC).

Version 1 envelopes (deaddrop 0.1.0: same header without `body_len`, no
padding) are still accepted when decrypting.

## Threat model

**The node is not trusted with message contents.** Drops are encrypted
to the recipient's long-term X25519 public key by Reticulum's
`Identity.encrypt`: a fresh ephemeral X25519 key per message, HKDF, then
AES-CBC + HMAC-SHA256 (AES-256 in current Reticulum releases).

**Stored drops have no forward secrecy.** The ephemeral key only protects
the sender's side. Anyone who copies drops off a node and *later* obtains
the recipient's identity private key can decrypt all of them. Forward
secrecy applies only to Reticulum Link traffic in transit. Keep recipient
identity files safe, fetch promptly, and use short TTLs.

Someone who seizes or controls a node can:

- Drop, delay, or duplicate messages.
- See which recipient hashes have drops waiting, when they were made and
  when they expire.
- See each drop's size bucket (256 B … 64 KiB), but not its real length.
- See which recipient fetched when, since `list`/`fetch` require the
  recipient to identify.
- Forge drops, if they have the recipient's public key (it is handed out
  so people can send, and any Reticulum announce by the recipient
  reveals it). Anyone holding it can encrypt a message to the recipient
  and write any `sender_hash` into it, which is why the client shows a
  *claimed* sender.

They **cannot**:

- Read message contents without the recipient's private key.
- Impersonate a recipient (the Link's identity proof is required to
  `list` or `fetch`).
- Learn who made a drop from the node's database or its requests: senders
  never identify, and the store has no sender column. (Reticulum transport
  details, such as which interface a packet arrived on, are still visible
  to whoever runs the node.)

On disk, the node turns on SQLite `secure_delete`, so fetched and expired
drops are overwritten with zeros rather than left in free pages. Older
copies of pages can still survive in the SQLite write-ahead log
(`drops.sqlite-wal`) until it is checkpointed and reused, and flash
storage can keep old blocks after an overwrite, so run the node on an
encrypted filesystem if seizure is a concern.

Upgrading from 0.1.0: the node removes the old `sender_hint` column on
first start and vacuums the database so the stored sender hashes are
erased, not just hidden.

If sender authenticity matters, sign your `body` with the sender's
Reticulum identity (`Identity.sign`, Ed25519) before encrypting, and have
the recipient verify it.

## Development

```bash
pip install -e '.[dev]'
pytest
```

Tests cover the storage layer and schema migration (no RNS needed), the
envelope and padding, the protocol handlers and CLI argument parsing
(these need `rns` installed, but no live network). There is no automated
end-to-end test against a running Reticulum stack yet; run a TCP loopback
as in the quick start to validate.

## License

MIT — see `LICENSE`.
