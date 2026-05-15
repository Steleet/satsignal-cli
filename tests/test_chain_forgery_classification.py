"""Regression tests for the v0.3.2 chain-forgery misclassification fix.

Before v0.3.2, `_fetch_chain` raised `_NetworkError` whenever neither
explorer returned HTTP 200 — including the case where both WhatsOnChain
and Bitails reachably answered 404 for a txid that does not exist on
chain. A forged / tampered `.mbnt` (valid local crypto, bogus txid)
therefore verified as NETWORK (exit 3, "transient — retry") instead of
CHAIN (exit 2, "unrecoverable forgery"). A caller looping on the
documented retry-friendly NETWORK class would retry forever.

v0.3.2 distinguishes `r.status_code == 404` (definitive "not on chain")
from `r is None` / 5xx / 429 (genuinely transient). It declares a
forgery (CHAIN) only when BOTH explorers agree on 404, so a single
explorer outage can't manufacture a false "tampered" verdict.
"""

import hashlib
import hmac
import tempfile
import unittest
import unittest.mock as mock
import zipfile
from base64 import urlsafe_b64encode
from pathlib import Path
from typing import Optional

from satsignal.verify import (
    EXIT_CODES,
    VerifyClass,
    _ChainError,
    _fetch_chain,
    _jcs,
    _NetworkError,
    verify_file,
)


class _FakeResp:
    """Minimal stand-in for requests.Response — only the two attributes
    _fetch_chain touches."""

    def __init__(self, status_code: int, json_data: Optional[dict] = None):
        self.status_code = status_code
        self._json = json_data or {}

    def json(self) -> dict:
        return self._json


def _mbnt_woc_vout(doc_hash20: bytes) -> dict:
    """A WhatsOnChain tx JSON whose first output is a valid MBNT
    OP_RETURN. WoC strips the leading OP_FALSE in scriptPubKey.hex, so
    the script is OP_RETURN <push len> <payload>. payload[8:28] is the
    20-byte doc_hash per SPEC_mbnt.md."""
    payload = b"MBNT" + b"\x00\x00\x00\x00" + doc_hash20  # 4 + 4 + 20 = 28
    script = bytes([0x6A, len(payload)]) + payload
    return {
        "confirmations": 7,
        "vout": [{"scriptPubKey": {"hex": script.hex()}}],
    }


# ───────────────── _fetch_chain classification matrix ─────────────────

class FetchChainClassificationTest(unittest.TestCase):
    """_fetch_chain must map (woc_outcome, bitails_outcome) to the right
    exception class. The headline bug: (404, 404) was NETWORK, must be
    CHAIN."""

    def _run(self, woc, bitails):
        with mock.patch(
            "satsignal.verify._get_with_retry",
            side_effect=[woc, bitails],
        ):
            return _fetch_chain("f" * 64)

    def test_both_404_is_chain_error_not_network(self):
        """THE regression. Both explorers reachable, both say 'no such
        tx' → forged anchor → _ChainError (CHAIN, exit 2)."""
        with self.assertRaises(_ChainError) as ctx:
            self._run(_FakeResp(404), _FakeResp(404))
        self.assertIn("not found on chain", str(ctx.exception))

    def test_both_unreachable_stays_network(self):
        """Connection failures (r is None) are genuinely transient →
        _NetworkError (NETWORK, exit 3, retry-friendly)."""
        with self.assertRaises(_NetworkError):
            self._run(None, None)

    def test_woc_404_bitails_5xx_stays_network(self):
        """One explorer 404, the other degraded (500). We can't be
        certain the tx doesn't exist — stay retry-friendly."""
        with self.assertRaises(_NetworkError):
            self._run(_FakeResp(404), _FakeResp(500))

    def test_woc_404_bitails_unreachable_stays_network(self):
        """404 + connection failure: not both-confirmed → NETWORK."""
        with self.assertRaises(_NetworkError):
            self._run(_FakeResp(404), None)

    def test_woc_5xx_bitails_404_stays_network(self):
        """Order-independent: degraded WoC + 404 Bitails is still not a
        both-explorers-agree forgery verdict."""
        with self.assertRaises(_NetworkError):
            self._run(_FakeResp(503), _FakeResp(404))

    def test_woc_429_bitails_404_stays_network(self):
        """Rate-limit (429) is transient, not 'not found'."""
        with self.assertRaises(_NetworkError):
            self._run(_FakeResp(429), _FakeResp(404))

    def test_woc_200_with_mbnt_returns_confirmations_and_dochash(self):
        """Happy path unchanged: a real anchor still resolves."""
        doc20 = bytes(range(20))
        conf, doc_hash = self._run(
            _FakeResp(200, _mbnt_woc_vout(doc20)), None
        )
        self.assertEqual(conf, 7)
        self.assertEqual(doc_hash, doc20.hex())

    def test_woc_200_without_mbnt_is_chain_error(self):
        """tx fetched but carries no MBNT OP_RETURN — already CHAIN
        before this fix; must stay CHAIN, not regress to NETWORK."""
        with self.assertRaises(_ChainError) as ctx:
            self._run(_FakeResp(200, {"confirmations": 3, "vout": []}), None)
        self.assertIn("no MBNT OP_RETURN", str(ctx.exception))

    def test_woc_404_bitails_200_with_mbnt_returns(self):
        """WoC misses, Bitails fallback carries the anchor."""
        doc20 = bytes(range(20, 40))
        payload = b"MBNT" + b"\x00\x00\x00\x00" + doc20
        script = bytes([0x00, 0x6A, len(payload)]) + payload  # Bitails keeps OP_FALSE
        bitails = _FakeResp(200, {
            "confirmations": 12,
            "outputs": [{"scriptPubKey": script.hex()}],
        })
        conf, doc_hash = self._run(_FakeResp(404), bitails)
        self.assertEqual(conf, 12)
        self.assertEqual(doc_hash, doc20.hex())


# ───────────── end-to-end: forged sealed bundle → CHAIN ─────────────

class ForgedBundleEndToEndTest(unittest.TestCase):
    """A sealed .mbnt with intact crypto but a txid that does not exist
    on chain (the forge3b 'txid-only' tamper class from the
    2026-05-14 stress test) must verify as CHAIN (exit 2), not
    NETWORK (exit 3). Built self-contained so the test needs no network
    and no external fixture path."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        tp = Path(self.tmp.name)

        salt = bytes(range(32))
        self.file = tp / "doc.bin"
        file_bytes = b"end-to-end forgery fixture payload"
        self.file.write_bytes(file_bytes)
        commitment = hmac.new(salt, file_bytes, hashlib.sha256).hexdigest()

        canonical = {
            "schema_version": 2,
            "subject": {
                "kind": "file_anchor",
                "proofs": {
                    "byte_exact": {
                        "algo": "hmac-sha256",
                        "commitment": commitment,
                        "salt_version": "salt_v1",
                    }
                },
            },
        }
        # Write canonical.json as the exact JCS bytes the verifier will
        # re-encode and demand byte-equality against (§7.3).
        raw_canonical = _jcs(canonical)
        doc_hash_expected = hashlib.sha256(raw_canonical).hexdigest()[:40]

        manifest = {
            "mbnt_version": "2.1",
            "mode": "sealed",
            "network": "bsv-mainnet",
            "salt_b64": urlsafe_b64encode(salt).decode(),
            "salt_version": "salt_v1",
            "doc_hash_expected": doc_hash_expected,
            # Bogus txid — the tamper. Valid 64-hex shape, never broadcast.
            "txid": "dead" * 16,
        }

        self.bundle = tp / "doc.bin.mbnt"
        with zipfile.ZipFile(self.bundle, "w") as zf:
            zf.writestr("manifest.json", __import__("json").dumps(manifest))
            zf.writestr("canonical.json", raw_canonical)

    def tearDown(self):
        self.tmp.cleanup()

    def test_forged_txid_both_404_verifies_as_chain_exit_2(self):
        with mock.patch(
            "satsignal.verify._get_with_retry",
            side_effect=[_FakeResp(404), _FakeResp(404)],
        ):
            result = verify_file(self.file, self.bundle)
        self.assertEqual(result.cls, VerifyClass.CHAIN)
        self.assertEqual(EXIT_CODES[result.cls], 2)
        self.assertIn("not found on chain", result.message or "")

    def test_same_bundle_explorers_down_is_network_exit_3(self):
        """Guard against a blanket reclassify: identical bundle, but
        explorers unreachable → still NETWORK (exit 3). Proves the fix
        keys on the 404 signal, not on 'verify reached the chain step'."""
        with mock.patch(
            "satsignal.verify._get_with_retry",
            side_effect=[None, None],
        ):
            result = verify_file(self.file, self.bundle)
        self.assertEqual(result.cls, VerifyClass.NETWORK)
        self.assertEqual(EXIT_CODES[result.cls], 3)


if __name__ == "__main__":
    unittest.main()
