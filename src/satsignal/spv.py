"""TSC merkle proof verification against the local headers store.

Given a txid and a sync'd HeaderStore, fetch the BRFC-0072 (TSC)
merkle proof from WhatsOnChain and verify it locally. The block's
merkleroot comes from our validated chain, never from the explorer
— so the explorer can only ever provide the witness path, not the
authoritative target.

Failure modes returned to the caller:
- network/parse error fetching the TSC proof
- target block not in local chain (sync stale OR alt-chain block)
- merkle path doesn't reproduce the local merkleroot from txid
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

import requests

from .headers import HeaderStore
from .p2p import be_hex_to_hash, hash_to_be_hex


WOC_TSC_PROOF_URL = (
    "https://api.whatsonchain.com/v1/bsv/main/tx/{txid}/proof/tsc"
)

DUP_MARKER = b"*"  # TSC node value meaning "duplicate self"


class SpvError(Exception):
    pass


@dataclass
class MerkleProof:
    """A parsed BRFC-0072 TSC merkle proof. All hash fields are raw
    LE bytes (wire format) — be_hex_to_hash already inverted the BE
    display hex from WoC."""
    index: int
    txid: bytes              # 32 bytes LE
    target_block: bytes      # 32 bytes LE — block hash containing this tx
    nodes: list[bytes]       # each 32 bytes LE, OR the DUP_MARKER sentinel


# ─────────────────────────── fetch ───────────────────────────

def fetch_tsc_proof(txid_be_hex: str, *, timeout: int = 15) -> MerkleProof:
    """GET the proof from WhatsOnChain and parse it into MerkleProof.
    Raises SpvError on HTTP / shape / parse failures."""
    url = WOC_TSC_PROOF_URL.format(txid=txid_be_hex)
    try:
        r = requests.get(url, timeout=timeout)
    except requests.RequestException as e:
        raise SpvError(f"WoC TSC fetch failed: {e}") from None

    if r.status_code != 200:
        raise SpvError(
            f"WoC TSC returned HTTP {r.status_code} for {txid_be_hex}"
        )
    try:
        body = r.json()
    except ValueError as e:
        raise SpvError(f"WoC TSC response not JSON: {e}") from None

    if not isinstance(body, list) or not body:
        raise SpvError(f"WoC TSC response not a non-empty list: {body!r}")
    p = body[0]
    if not isinstance(p, dict):
        raise SpvError(f"WoC TSC proof entry is not an object: {p!r}")

    try:
        index = int(p["index"])
        tx_or_id = p["txOrId"]
        target = p["target"]
        nodes_hex = p["nodes"]
    except KeyError as e:
        raise SpvError(f"WoC TSC proof missing field: {e}") from None

    if not isinstance(nodes_hex, list):
        raise SpvError("WoC TSC `nodes` is not a list")

    return MerkleProof(
        index=index,
        txid=be_hex_to_hash(tx_or_id),
        target_block=be_hex_to_hash(target),
        nodes=[
            DUP_MARKER if n == "*" else be_hex_to_hash(n)
            for n in nodes_hex
        ],
    )


# ─────────────────────────── verify ───────────────────────────

def _dsha256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def verify_merkle_proof(proof: MerkleProof, merkleroot_le: bytes) -> bool:
    """Walk the merkle branch from leaf (txid) up to the computed root.
    The bit at position i of `index` says whether `proof.nodes[i]` is
    our LEFT sibling (bit=1, we're the right child) or RIGHT sibling
    (bit=0, we're the left child). LSB of index = lowest tree level."""
    if len(proof.txid) != 32:
        raise SpvError("txid must be 32 bytes (LE)")
    if len(merkleroot_le) != 32:
        raise SpvError("merkleroot must be 32 bytes (LE)")

    current = proof.txid
    idx = proof.index
    for node in proof.nodes:
        sibling = current if node == DUP_MARKER else node
        if len(sibling) != 32:
            raise SpvError(f"merkle node must be 32 bytes, got {len(sibling)}")
        if idx & 1:
            current = _dsha256(sibling + current)
        else:
            current = _dsha256(current + sibling)
        idx >>= 1

    return current == merkleroot_le


# ─────────────────────────── glue ───────────────────────────

@dataclass
class SpvResult:
    ok: bool
    height: Optional[int] = None
    block_hash_be: Optional[str] = None
    error: Optional[str] = None


def verify_txid_in_chain(txid_be_hex: str,
                         store: HeaderStore) -> SpvResult:
    """End-to-end SPV check for a txid.

    1. Fetch the TSC proof from WoC.
    2. Look up the proof's target block in the local headers store.
       If absent → either our sync is stale (re-sync needed) or the
       block is on an alt chain we rejected. Either way, fail.
    3. Verify the merkle path computes the local block's merkleroot.

    Returns an SpvResult; `ok=True` means the txid is cryptographically
    proven to be in a block we've validated as part of the BSV chain
    (PoW + linkage + strict cw-144 DAA from the headers store).
    """
    try:
        proof = fetch_tsc_proof(txid_be_hex)
    except SpvError as e:
        return SpvResult(ok=False, error=str(e))

    height = store.height_of(proof.target_block)
    if height is None:
        return SpvResult(
            ok=False,
            block_hash_be=hash_to_be_hex(proof.target_block),
            error=(
                "proof's target block is not in local validated chain "
                "— either the headers store is behind the tx's block or "
                "the explorer claims a block on a fork we don't follow"
            ),
        )

    header = store.get(height)
    if not verify_merkle_proof(proof, header.merkle_root):
        return SpvResult(
            ok=False,
            height=height,
            block_hash_be=hash_to_be_hex(proof.target_block),
            error="merkle path does not reproduce the local block's merkleroot",
        )

    return SpvResult(
        ok=True,
        height=height,
        block_hash_be=hash_to_be_hex(proof.target_block),
    )
