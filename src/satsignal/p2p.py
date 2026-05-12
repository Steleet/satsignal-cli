"""Minimal Bitcoin P2P client for BSV mainnet.

Stdlib-only (socket + struct + hashlib). Implements the subset of the
Bitcoin wire protocol needed to sync block headers from a peer:

- Message framing (24-byte header + payload, double-sha256 checksum)
- version / verack / ping / pong
- getheaders / headers (added in a follow-up commit)

Wire format references:
- https://en.bitcoin.it/wiki/Protocol_documentation
- https://reference.cash/protocol/blockchain/messages

BSV mainnet magic is 0xe3e1f3e8 (inherited from BCH after the
2017 fork; BTC kept 0xf9beb4d9). Transmitted as
b"\\xe3\\xe1\\xf3\\xe8". Default port 8333.
"""

from __future__ import annotations

import hashlib
import secrets
import socket
import struct
import time
from dataclasses import dataclass
from typing import Optional


MAGIC_BSV_MAIN = b"\xe3\xe1\xf3\xe8"
PROTOCOL_VERSION = 70015
SERVICES_NONE = 0
DEFAULT_PORT = 8333

USER_AGENT = "/satsignal-cli:0.3.0/"


# ─────────────────────────── helpers ───────────────────────────

def _dsha256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _checksum(payload: bytes) -> bytes:
    return _dsha256(payload)[:4]


def _encode_varint(n: int) -> bytes:
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def _decode_varint(b: bytes, off: int = 0) -> tuple[int, int]:
    """Returns (value, new_offset)."""
    first = b[off]
    if first < 0xfd:
        return first, off + 1
    if first == 0xfd:
        return struct.unpack_from("<H", b, off + 1)[0], off + 3
    if first == 0xfe:
        return struct.unpack_from("<I", b, off + 1)[0], off + 5
    return struct.unpack_from("<Q", b, off + 1)[0], off + 9


def _encode_varstr(s: str) -> bytes:
    data = s.encode("ascii")
    return _encode_varint(len(data)) + data


def _encode_netaddr(services: int, ip: str, port: int) -> bytes:
    """26-byte net_addr without timestamp (used inside version)."""
    # IPv4-mapped IPv6: ::ffff:a.b.c.d
    parts = ip.split(".")
    if len(parts) == 4:
        ipv6 = b"\x00" * 10 + b"\xff\xff" + bytes(int(p) for p in parts)
    else:
        ipv6 = b"\x00" * 16  # IPv6 not supported; placeholder
    return struct.pack("<Q", services) + ipv6 + struct.pack(">H", port)


# ─────────────────────────── framing ───────────────────────────

@dataclass
class Message:
    command: str
    payload: bytes


class P2PError(Exception):
    pass


def _frame_message(magic: bytes, command: str, payload: bytes) -> bytes:
    cmd_bytes = command.encode("ascii").ljust(12, b"\x00")
    if len(cmd_bytes) > 12:
        raise P2PError(f"command name {command!r} exceeds 12 bytes")
    return (
        magic
        + cmd_bytes
        + struct.pack("<I", len(payload))
        + _checksum(payload)
        + payload
    )


def _recvall(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes; raise P2PError on short read."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise P2PError(
                f"peer closed mid-message (got {len(buf)} of {n} bytes)"
            )
        buf += chunk
    return bytes(buf)


def recv_message(sock: socket.socket, magic: bytes = MAGIC_BSV_MAIN) -> Message:
    """Read one framed message from the socket. Raises P2PError on
    magic mismatch or checksum failure."""
    header = _recvall(sock, 24)
    if header[:4] != magic:
        raise P2PError(
            f"bad magic: got {header[:4].hex()}, expected {magic.hex()}"
        )
    command = header[4:16].rstrip(b"\x00").decode("ascii", errors="replace")
    length = struct.unpack("<I", header[16:20])[0]
    expected_checksum = header[20:24]
    if length > 32 * 1024 * 1024:
        raise P2PError(f"payload length {length} exceeds 32 MiB cap")
    payload = _recvall(sock, length) if length else b""
    if _checksum(payload) != expected_checksum:
        raise P2PError(f"checksum mismatch on {command!r}")
    return Message(command=command, payload=payload)


def send_message(sock: socket.socket, command: str, payload: bytes,
                 magic: bytes = MAGIC_BSV_MAIN) -> None:
    sock.sendall(_frame_message(magic, command, payload))


# ─────────────────────────── version / verack ───────────────────────────

def _build_version_payload(remote_ip: str, remote_port: int,
                           local_height: int = 0) -> bytes:
    return (
        struct.pack("<i", PROTOCOL_VERSION)
        + struct.pack("<Q", SERVICES_NONE)
        + struct.pack("<q", int(time.time()))
        + _encode_netaddr(SERVICES_NONE, remote_ip, remote_port)
        + _encode_netaddr(SERVICES_NONE, "0.0.0.0", 0)
        + struct.pack("<Q", secrets.randbits(64))
        + _encode_varstr(USER_AGENT)
        + struct.pack("<i", local_height)
        + b"\x00"  # relay = false
    )


# ─────────────────────────── ping / pong ───────────────────────────

def _handle_ping(sock: socket.socket, payload: bytes) -> None:
    """Reply to a peer's ping with a pong echoing the nonce."""
    send_message(sock, "pong", payload)


# ─────────────────────────── handshake ───────────────────────────

@dataclass
class PeerInfo:
    version: int
    services: int
    user_agent: str
    start_height: int


def _parse_version_payload(payload: bytes) -> PeerInfo:
    version = struct.unpack_from("<i", payload, 0)[0]
    services = struct.unpack_from("<Q", payload, 4)[0]
    # skip timestamp(8) + addr_recv(26) + addr_from(26) + nonce(8) = 68
    off = 4 + 8 + 8 + 26 + 26 + 8
    ua_len, off = _decode_varint(payload, off)
    user_agent = payload[off:off + ua_len].decode("ascii", errors="replace")
    off += ua_len
    start_height = struct.unpack_from("<i", payload, off)[0]
    return PeerInfo(
        version=version,
        services=services,
        user_agent=user_agent,
        start_height=start_height,
    )


def handshake(host: str, port: int = DEFAULT_PORT, *,
              timeout: float = 15.0,
              local_height: int = 0) -> tuple[socket.socket, PeerInfo]:
    """Open a TCP connection to (host, port) and complete the Bitcoin
    protocol handshake. Returns the connected socket + parsed peer
    info. Caller is responsible for closing the socket.

    Sequence (per protocol):
      → version
      ← version
      ← verack
      → verack

    Peers commonly interleave ping/sendheaders/sendcmpct frames during
    handshake; we tolerate them and ignore non-version/verack frames
    until both expected frames arrive."""
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        remote_ip = sock.getpeername()[0]
        send_message(sock, "version",
                     _build_version_payload(remote_ip, port,
                                            local_height=local_height))

        got_version: Optional[PeerInfo] = None
        got_verack = False
        deadline = time.monotonic() + timeout
        while not (got_version and got_verack):
            if time.monotonic() > deadline:
                raise P2PError("handshake timed out waiting for version+verack")
            msg = recv_message(sock)
            if msg.command == "version":
                got_version = _parse_version_payload(msg.payload)
            elif msg.command == "verack":
                got_verack = True
            elif msg.command == "ping":
                _handle_ping(sock, msg.payload)
            # ignore sendheaders, sendcmpct, addr, etc. during handshake

        send_message(sock, "verack", b"")
        return sock, got_version
    except Exception:
        sock.close()
        raise
