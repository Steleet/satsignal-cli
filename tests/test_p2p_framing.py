"""P2P wire-format unit tests. Network-free."""

import struct
import unittest

from satsignal.p2p import (
    GENESIS_HASH_BE_HEX,
    GENESIS_HASH_LE,
    MAGIC_BSV_MAIN,
    ZERO_HASH,
    _build_getheaders_payload,
    _checksum,
    _decode_varint,
    _encode_varint,
    _encode_varstr,
    _frame_message,
    _parse_block_header,
    be_hex_to_hash,
    hash_to_be_hex,
)
from satsignal.headers import GENESIS_RAW_80


class TestVarint(unittest.TestCase):
    def test_roundtrip_boundaries(self):
        # The boundary values where encoding shifts to a larger int width.
        for n in (0, 1, 0xfc, 0xfd, 0xfffe, 0xffff, 0x10000, 0xfffffffe,
                  0xffffffff, 0x100000000):
            encoded = _encode_varint(n)
            decoded, off = _decode_varint(encoded)
            self.assertEqual(decoded, n,
                             f"varint roundtrip failed for n={n}")
            self.assertEqual(off, len(encoded),
                             f"varint offset wrong for n={n}")

    def test_encoding_lengths(self):
        # Sanity: width follows the value range per spec.
        self.assertEqual(len(_encode_varint(0xfc)), 1)
        self.assertEqual(len(_encode_varint(0xfd)), 3)
        self.assertEqual(len(_encode_varint(0xffff)), 3)
        self.assertEqual(len(_encode_varint(0x10000)), 5)
        self.assertEqual(len(_encode_varint(0xffffffff)), 5)
        self.assertEqual(len(_encode_varint(0x100000000)), 9)


class TestVarstr(unittest.TestCase):
    def test_ascii_roundtrip(self):
        for s in ("", "/satsignal-cli:0.3/", "x" * 300):
            encoded = _encode_varstr(s)
            length, off = _decode_varint(encoded)
            self.assertEqual(length, len(s.encode("ascii")))
            self.assertEqual(encoded[off:].decode("ascii"), s)


class TestFraming(unittest.TestCase):
    def test_verack_frame(self):
        # Empty payload, real BSV magic, 12-byte command name padded with NUL.
        framed = _frame_message(MAGIC_BSV_MAIN, "verack", b"")
        self.assertEqual(framed[:4], MAGIC_BSV_MAIN)
        self.assertEqual(framed[4:16], b"verack" + b"\x00" * 6)
        # length = 0
        self.assertEqual(struct.unpack("<I", framed[16:20])[0], 0)
        # checksum of empty payload is dsha256(b"")[:4]
        self.assertEqual(framed[20:24], _checksum(b""))
        # no payload follows
        self.assertEqual(len(framed), 24)

    def test_payload_checksum_matches(self):
        payload = b"\x01\x02\x03"
        framed = _frame_message(MAGIC_BSV_MAIN, "ping", payload)
        self.assertEqual(framed[20:24], _checksum(payload))
        self.assertEqual(framed[24:], payload)
        self.assertEqual(struct.unpack("<I", framed[16:20])[0], 3)


class TestGetheaders(unittest.TestCase):
    def test_payload_structure(self):
        # Build a getheaders payload with locator=[genesis] and zero stop hash.
        payload = _build_getheaders_payload([GENESIS_HASH_LE])
        # 4 bytes protocol version
        # + 1 byte varint count (1)
        # + 32 bytes locator
        # + 32 bytes stop
        self.assertEqual(len(payload), 4 + 1 + 32 + 32)
        self.assertEqual(payload[4], 1)  # locator count varint
        self.assertEqual(payload[5:37], GENESIS_HASH_LE)
        self.assertEqual(payload[37:], ZERO_HASH)

    def test_bad_locator_rejected(self):
        from satsignal.p2p import P2PError
        with self.assertRaises(P2PError):
            _build_getheaders_payload([b"\x00" * 31])  # 31 bytes != 32


class TestHashByteOrder(unittest.TestCase):
    def test_genesis_be_to_le_roundtrip(self):
        le = be_hex_to_hash(GENESIS_HASH_BE_HEX)
        self.assertEqual(le, GENESIS_HASH_LE)
        self.assertEqual(hash_to_be_hex(le), GENESIS_HASH_BE_HEX)


class TestGenesisHeader(unittest.TestCase):
    def test_hardcoded_genesis_hashes_correctly(self):
        # Parsing the canonical 80-byte mainnet genesis must produce the
        # well-known hash; otherwise the entire chain would be rejected
        # at append_validated for height 0.
        h = _parse_block_header(GENESIS_RAW_80)
        self.assertEqual(hash_to_be_hex(h.block_hash), GENESIS_HASH_BE_HEX)
        # Genesis header field constants (Bitcoin protocol)
        self.assertEqual(h.version, 1)
        self.assertEqual(h.prev_block, ZERO_HASH)
        self.assertEqual(h.timestamp, 1231006505)  # 2009-01-03 18:15:05 UTC
        self.assertEqual(h.bits, 0x1d00ffff)
        self.assertEqual(h.nonce, 2083236893)


if __name__ == "__main__":
    unittest.main()
