"""Merkle proof verification tests. Network-free.

Tests verify_merkle_proof against constructed proofs. No HeaderStore
or WoC dependency — the merkle algorithm is purely mathematical and
can be exercised against synthetic blocks.
"""

import hashlib
import unittest

from satsignal.spv import (
    DUP_MARKER,
    MerkleProof,
    SpvError,
    verify_merkle_proof,
)


def _dsha256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _build_balanced_merkle_tree(leaves: list[bytes]) -> tuple[bytes, list[list[bytes]]]:
    """Build a Bitcoin merkle tree and return (root, levels) where
    levels[0] is the leaf row and levels[-1] = [root]. Used to compute
    a "real" merkle proof for a chosen leaf index."""
    levels = [leaves[:]]
    cur = leaves[:]
    while len(cur) > 1:
        if len(cur) % 2 == 1:
            cur.append(cur[-1])  # Bitcoin duplicates the last node
        nxt = [
            _dsha256(cur[i] + cur[i + 1])
            for i in range(0, len(cur), 2)
        ]
        levels.append(nxt)
        cur = nxt
    return cur[0], levels


def _proof_for_index(levels: list[list[bytes]], index: int) -> list[bytes]:
    """Walk up from leaf row, collecting the sibling at each level."""
    out = []
    idx = index
    for level in levels[:-1]:
        sibling_idx = idx ^ 1  # flip LSB
        if sibling_idx >= len(level):
            sibling_idx = idx  # duplicate-self (already handled in level build)
        out.append(level[sibling_idx])
        idx //= 2
    return out


class TestMerkleProof(unittest.TestCase):
    def test_single_leaf_block(self):
        # A block with one tx: root == txid, proof is empty.
        txid = b"\x42" * 32
        root, levels = _build_balanced_merkle_tree([txid])
        self.assertEqual(root, txid)
        proof = MerkleProof(index=0, txid=txid, target_block=b"\x00" * 32,
                            nodes=_proof_for_index(levels, 0))
        self.assertEqual(proof.nodes, [])
        self.assertTrue(verify_merkle_proof(proof, root))

    def test_four_tx_block_every_position(self):
        # Build a 4-leaf tree; verify proofs for all 4 leaf positions.
        leaves = [bytes([i]) * 32 for i in range(1, 5)]
        root, levels = _build_balanced_merkle_tree(leaves)
        for index in range(4):
            proof = MerkleProof(
                index=index, txid=leaves[index],
                target_block=b"\x00" * 32,
                nodes=_proof_for_index(levels, index),
            )
            self.assertTrue(verify_merkle_proof(proof, root),
                            f"verify failed for index {index}")

    def test_tampered_root_rejected(self):
        leaves = [bytes([i]) * 32 for i in range(1, 5)]
        root, levels = _build_balanced_merkle_tree(leaves)
        proof = MerkleProof(
            index=2, txid=leaves[2],
            target_block=b"\x00" * 32,
            nodes=_proof_for_index(levels, 2),
        )
        wrong_root = bytes([(b + 1) & 0xff for b in root])
        self.assertFalse(verify_merkle_proof(proof, wrong_root))

    def test_tampered_branch_rejected(self):
        leaves = [bytes([i]) * 32 for i in range(1, 5)]
        root, levels = _build_balanced_merkle_tree(leaves)
        nodes = _proof_for_index(levels, 1)
        # Flip one byte in the first sibling
        tampered = bytearray(nodes[0])
        tampered[0] ^= 0xff
        nodes[0] = bytes(tampered)
        proof = MerkleProof(index=1, txid=leaves[1],
                            target_block=b"\x00" * 32, nodes=nodes)
        self.assertFalse(verify_merkle_proof(proof, root))

    def test_tampered_index_rejected(self):
        # Same proof but with the wrong index bits → wrong sibling
        # ordering → wrong root.
        leaves = [bytes([i]) * 32 for i in range(1, 5)]
        root, levels = _build_balanced_merkle_tree(leaves)
        proof = MerkleProof(
            index=3,  # claim leaf 3 ...
            txid=leaves[1],  # ... but supply leaf 1's data
            target_block=b"\x00" * 32,
            nodes=_proof_for_index(levels, 1),  # ... and leaf 1's proof
        )
        self.assertFalse(verify_merkle_proof(proof, root))

    def test_duplicate_marker_handled(self):
        # Odd-leaf tree: Bitcoin duplicates the last leaf. TSC encodes
        # this by emitting "*" as a sibling that means "duplicate self".
        leaves = [bytes([i]) * 32 for i in range(1, 4)]  # 3 leaves
        root, levels = _build_balanced_merkle_tree(leaves)
        # Leaf index 2 (the odd-one-out) gets duplicated; its sibling
        # in the proof should equal itself — TSC may encode this as
        # DUP_MARKER or as the explicit hash. We test the marker path.
        proof = MerkleProof(
            index=2, txid=leaves[2],
            target_block=b"\x00" * 32,
            nodes=[DUP_MARKER] + _proof_for_index(levels, 2)[1:],
        )
        self.assertTrue(verify_merkle_proof(proof, root))

    def test_short_txid_raises(self):
        proof = MerkleProof(index=0, txid=b"\x42" * 31,  # 31 bytes, not 32
                            target_block=b"\x00" * 32, nodes=[])
        with self.assertRaises(SpvError):
            verify_merkle_proof(proof, b"\x00" * 32)


if __name__ == "__main__":
    unittest.main()
