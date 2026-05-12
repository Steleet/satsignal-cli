"""Persistent BSV block-header store with chain validation.

Two parallel append-only files under ~/.cache/satsignal/:

- headers.bin     — raw 80-byte headers, index == height (genesis at
                    offset 0). File size = (tip_height + 1) * 80.
- chainwork.bin   — 32 bytes per height, big-endian uint256 cumulative
                    chainwork up to and including that block.

In-memory: a hash->height dict, built from headers.bin on load.
~30 MB at full sync (~950K blocks); we don't persist it because rebuild
from headers.bin is ~1 s.

Validation rules per appended header (in order):
  1. height 0: must equal hardcoded genesis (block hash + raw 80 bytes).
  2. height > 0:
     a. prev_block links to the previous header's block_hash.
     b. PoW: double-sha256(raw_80) as uint256-LE <= target_from_bits(bits).
     c. DAA: for height >= CW144_FORK_HEIGHT (504032 — Nov 13 2017),
        the `bits` field MUST equal cw-144's expected value computed
        from the suitable-block window. For height < CW144_FORK_HEIGHT
        we accept whatever the peer's chain claims, because forging
        a deep historical BSV chain at any difficulty is infeasible
        given the accumulated PoW depth (~10^29 work below the fork).

cw-144 reference: Bitcoin Cash Difficulty Adjustment Algorithm v2,
activated Nov 13 2017. BSV inherited cw-144 from BCH and never
adopted ASERT, so all BSV blocks at height >= 504032 use this rule.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from .p2p import (
    BlockHeader,
    GENESIS_HASH_LE,
    P2PError,
    _parse_block_header,
    handshake,
    request_headers,
)


DEFAULT_PEERS = (
    ("seed.bitcoinsv.io", 8333),
    ("api.gorillapool.io", 8333),
)


# ─────────────────────────── constants ───────────────────────────

CACHE_DIR = Path(
    os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache"))
) / "satsignal"
HEADERS_PATH = CACHE_DIR / "headers.bin"
CHAINWORK_PATH = CACHE_DIR / "chainwork.bin"

HEADER_SIZE = 80
CHAINWORK_SIZE = 32

TARGET_BLOCK_TIME = 600       # seconds
CW144_WINDOW = 144
CW144_FORK_HEIGHT = 504032    # Nov 13 2017 BCH/BSV DAA activation

POW_LIMIT_BITS = 0x1d00ffff   # genesis difficulty = max target

# Hardcoded genesis header (matches mainnet block 0 — same on BTC,
# BCH, and BSV since they share pre-2017 history).
GENESIS_RAW_80 = bytes.fromhex(
    "01000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
    "29ab5f49"
    "ffff001d"
    "1dac2b7c"
)


# ─────────────────────────── exceptions ───────────────────────────

class HeadersError(Exception):
    pass


class ValidationError(HeadersError):
    pass


# ─────────────────────────── PoW + bits ───────────────────────────

def target_from_bits(bits: int) -> int:
    """Decode the 4-byte compact `bits` field to a uint256 target."""
    exponent = (bits >> 24) & 0xff
    mantissa = bits & 0x00ffffff
    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    return mantissa << (8 * (exponent - 3))


def bits_from_target(target: int) -> int:
    """Encode a uint256 target into 4-byte compact `bits`. Follows the
    Bitcoin compact-int rules including the sign-bit avoidance shift."""
    if target <= 0:
        return 0
    nbytes = (target.bit_length() + 7) // 8
    if nbytes <= 3:
        compact = target << (8 * (3 - nbytes))
    else:
        compact = target >> (8 * (nbytes - 3))
    # If the top bit of mantissa would be set, shift right and bump
    # the exponent to keep `bits` interpreted as positive.
    if compact & 0x00800000:
        compact >>= 8
        nbytes += 1
    return (compact & 0x007fffff) | (nbytes << 24)


def work_of_target(bits: int) -> int:
    """Block work = 2^256 / (target + 1). 0 for an invalid bits."""
    target = target_from_bits(bits)
    if target <= 0:
        return 0
    return (1 << 256) // (target + 1)


def _hash_int_le(b32: bytes) -> int:
    """Interpret a 32-byte block hash (wire LE) as an integer for PoW
    comparison."""
    return int.from_bytes(b32, "little")


def header_meets_pow(header: BlockHeader) -> bool:
    return _hash_int_le(header.block_hash) <= target_from_bits(header.bits)


# ─────────────────────────── cw-144 DAA ───────────────────────────

def _suitable_block(store: "HeaderStore", height: int) -> tuple[BlockHeader, int]:
    """Median-of-three by timestamp across (height-2, height-1, height).
    Returns (header, that_block_height)."""
    triples = [(store.get(h).timestamp, h) for h in (height - 2, height - 1, height)]
    triples.sort()
    _, median_h = triples[1]
    return store.get(median_h), median_h


def _cw144_expected_bits(store: "HeaderStore", parent_height: int) -> int:
    """Expected `bits` for the block whose parent is at `parent_height`.
    Requires parent_height + 1 >= CW144_FORK_HEIGHT and enough history
    for the 144-block window (i.e., parent_height >= CW144_WINDOW + 2)."""
    last, last_h = _suitable_block(store, parent_height)
    first, first_h = _suitable_block(store, parent_height - CW144_WINDOW)

    work_in_window = store.chainwork(last_h) - store.chainwork(first_h)

    timespan = last.timestamp - first.timestamp
    timespan = max(72 * TARGET_BLOCK_TIME,
                   min(timespan, 288 * TARGET_BLOCK_TIME))

    if work_in_window <= 0:
        return POW_LIMIT_BITS

    projected_work_per_target = work_in_window * TARGET_BLOCK_TIME // timespan
    if projected_work_per_target <= 0:
        return POW_LIMIT_BITS

    new_target = ((1 << 256) // projected_work_per_target) - 1
    pow_limit = target_from_bits(POW_LIMIT_BITS)
    new_target = min(new_target, pow_limit)
    return bits_from_target(new_target)


# ─────────────────────────── HeaderStore ───────────────────────────

@dataclass
class StoreStats:
    tip_height: int
    tip_hash_be: str
    file_size: int
    chainwork_size: int


class HeaderStore:
    """File-backed append-only header store + chain validator."""

    def __init__(self, headers_path: Path = HEADERS_PATH,
                 chainwork_path: Path = CHAINWORK_PATH) -> None:
        self.headers_path = headers_path
        self.chainwork_path = chainwork_path
        self.headers_path.parent.mkdir(parents=True, exist_ok=True)
        self._hash_to_height: dict[bytes, int] = {}
        self._load_index()

    # ─── basics ───

    @property
    def tip_height(self) -> int:
        """-1 if the store is empty."""
        if not self.headers_path.exists():
            return -1
        return (self.headers_path.stat().st_size // HEADER_SIZE) - 1

    def stats(self) -> StoreStats:
        if self.tip_height < 0:
            return StoreStats(-1, "", 0, 0)
        tip = self.get(self.tip_height)
        return StoreStats(
            tip_height=self.tip_height,
            tip_hash_be=tip.block_hash[::-1].hex(),
            file_size=self.headers_path.stat().st_size,
            chainwork_size=self.chainwork_path.stat().st_size,
        )

    def get(self, height: int) -> BlockHeader:
        if height < 0 or height > self.tip_height:
            raise HeadersError(f"height {height} out of range (tip={self.tip_height})")
        with open(self.headers_path, "rb") as f:
            f.seek(height * HEADER_SIZE)
            raw = f.read(HEADER_SIZE)
        return _parse_block_header(raw)

    def chainwork(self, height: int) -> int:
        if height < 0 or height > self.tip_height:
            raise HeadersError(f"height {height} out of range")
        with open(self.chainwork_path, "rb") as f:
            f.seek(height * CHAINWORK_SIZE)
            return int.from_bytes(f.read(CHAINWORK_SIZE), "big")

    def height_of(self, block_hash_le: bytes) -> Optional[int]:
        return self._hash_to_height.get(block_hash_le)

    # ─── validation + append ───

    def append_validated(self, header: BlockHeader) -> int:
        """Validate `header` as the next block after current tip and
        append it. Returns the new height. Raises ValidationError
        without mutating state on any failed check."""
        new_height = self.tip_height + 1

        if new_height == 0:
            if header.raw != GENESIS_RAW_80:
                raise ValidationError(
                    "first header is not the expected mainnet genesis"
                )
            cumulative_work = work_of_target(header.bits)
        else:
            prev = self.get(new_height - 1)
            if header.prev_block != prev.block_hash:
                raise ValidationError(
                    f"prev_block linkage broken at height {new_height}: "
                    f"got {header.prev_block[::-1].hex()[:16]}..., "
                    f"expected {prev.block_hash[::-1].hex()[:16]}..."
                )

            if not header_meets_pow(header):
                raise ValidationError(
                    f"PoW fails at height {new_height}: "
                    f"hash={header.block_hash[::-1].hex()[:16]}... "
                    f"target_bits={header.bits:#010x}"
                )

            # cw-144 enforcement (height >= 504032). The first ~146
            # blocks of the new era can't be window-validated without
            # pre-fork history, so cw-144 actually engages at
            # CW144_FORK_HEIGHT + CW144_WINDOW + 2 to ensure both
            # suitable-block windows lie entirely in stored history.
            if new_height >= CW144_FORK_HEIGHT + CW144_WINDOW + 2:
                expected_bits = _cw144_expected_bits(self, new_height - 1)
                if header.bits != expected_bits:
                    raise ValidationError(
                        f"cw-144 bits mismatch at height {new_height}: "
                        f"got {header.bits:#010x}, "
                        f"expected {expected_bits:#010x}"
                    )

            cumulative_work = self.chainwork(new_height - 1) + work_of_target(header.bits)

        # All checks passed — commit to disk.
        with open(self.headers_path, "ab") as fh, \
                open(self.chainwork_path, "ab") as fc:
            fh.write(header.raw)
            fc.write(cumulative_work.to_bytes(CHAINWORK_SIZE, "big"))
        self._hash_to_height[header.block_hash] = new_height
        return new_height

    # ─── locator (for getheaders) ───

    def locator(self) -> list[bytes]:
        """Build a block locator: hashes from tip going back, sparsely,
        ending at genesis. Per Bitcoin protocol convention: dense near
        the tip (10 most-recent), then exponential step-back."""
        if self.tip_height < 0:
            return [GENESIS_HASH_LE]
        out: list[bytes] = []
        h = self.tip_height
        step = 1
        while h > 0:
            out.append(self.get(h).block_hash)
            if len(out) >= 10:
                step *= 2
            h -= step
        out.append(self.get(0).block_hash)
        return out

    # ─── internal ───

    def ensure_genesis(self) -> None:
        """Append the hardcoded genesis if the store is empty. No-op
        if the store already has at least block 0."""
        if self.tip_height >= 0:
            return
        self.append_validated(_parse_block_header(GENESIS_RAW_80))

    def _load_index(self) -> None:
        if not self.headers_path.exists():
            return
        size = self.headers_path.stat().st_size
        if size % HEADER_SIZE != 0:
            raise HeadersError(
                f"headers.bin size {size} is not a multiple of {HEADER_SIZE}; "
                f"file is corrupt"
            )
        cw_size = self.chainwork_path.stat().st_size if self.chainwork_path.exists() else 0
        expected_cw = (size // HEADER_SIZE) * CHAINWORK_SIZE
        if cw_size != expected_cw:
            raise HeadersError(
                f"chainwork.bin size {cw_size} doesn't match headers.bin "
                f"(expected {expected_cw}); store out of sync"
            )
        with open(self.headers_path, "rb") as f:
            height = 0
            while True:
                raw = f.read(HEADER_SIZE)
                if not raw:
                    break
                if len(raw) != HEADER_SIZE:
                    raise HeadersError(
                        f"truncated read at height {height} "
                        f"(got {len(raw)} bytes)"
                    )
                # double-sha256 inline to skip the BlockHeader allocation
                block_hash = hashlib.sha256(hashlib.sha256(raw).digest()).digest()
                self._hash_to_height[block_hash] = height
                height += 1


# ─────────────────────────── peer sync ───────────────────────────

def sync_against_peer(store: HeaderStore, host: str, port: int = 8333, *,
                      on_progress: Optional[Callable[[int, int, float], None]] = None,
                      on_reconnect: Optional[Callable[[int, str], None]] = None,
                      timeout: float = 30.0,
                      max_reconnects: int = 3) -> int:
    """Sync the store up to the connected peer's tip. Returns the new
    tip height. on_progress is called with (batches_done, current_tip,
    elapsed_seconds) after each batch.

    Reconnects up to max_reconnects times on P2PError mid-sync. Progress
    is resumable across reconnects because append_validated commits
    each header immediately and the next handshake re-locates from
    store.tip_height. on_reconnect(attempt, err_msg) fires per attempt.

    Genesis is appended automatically if the store is empty. Raises
    P2PError after exhausting reconnects, and ValidationError on chain
    integrity failures (which are NOT retried — bad bits is a hard fail)."""
    store.ensure_genesis()

    t0 = time.monotonic()
    batches = 0
    reconnect_attempt = 0
    while True:
        try:
            sock, _ = handshake(host, port, timeout=timeout)
        except (P2PError, OSError) as e:
            reconnect_attempt += 1
            if reconnect_attempt > max_reconnects:
                raise P2PError(f"handshake failed {max_reconnects + 1}x: {e}") from None
            if on_reconnect is not None:
                on_reconnect(reconnect_attempt, str(e))
            time.sleep(1.0)
            continue
        try:
            while True:
                batch = request_headers(sock, locator=store.locator(),
                                        timeout=timeout)
                if not batch:
                    return store.tip_height
                for h in batch:
                    store.append_validated(h)
                batches += 1
                if on_progress is not None:
                    on_progress(batches, store.tip_height,
                                time.monotonic() - t0)
                if len(batch) < 2000:
                    return store.tip_height
        except P2PError as e:
            reconnect_attempt += 1
            if reconnect_attempt > max_reconnects:
                raise P2PError(
                    f"sync failed mid-stream after {max_reconnects} "
                    f"reconnects at tip={store.tip_height}: {e}"
                ) from None
            if on_reconnect is not None:
                on_reconnect(reconnect_attempt, str(e))
            time.sleep(1.0)
            continue
        finally:
            try:
                sock.close()
            except OSError:
                pass


def sync_with_fallback(store: HeaderStore,
                       peers: tuple = DEFAULT_PEERS,
                       on_progress: Optional[Callable[[int, int, float], None]] = None,
                       on_reconnect: Optional[Callable[[int, str], None]] = None,
                       on_peer_switch: Optional[Callable[[str, str], None]] = None,
                       timeout: float = 30.0) -> int:
    """Try each peer in turn until one syncs us to its tip. Returns the
    final tip height. Within a single peer, sync_against_peer handles
    its own reconnect retries — on_reconnect fires there, on_peer_switch
    fires when we abandon a peer entirely. Raises HeadersError if all
    peers fail."""
    last_err: Optional[Exception] = None
    for host, port in peers:
        try:
            return sync_against_peer(
                store, host, port,
                on_progress=on_progress, on_reconnect=on_reconnect,
                timeout=timeout,
            )
        except (P2PError, OSError) as e:
            last_err = e
            if on_peer_switch is not None:
                on_peer_switch(host, str(e))
            continue
    raise HeadersError(
        f"all peers failed; last error: {last_err}"
    )
