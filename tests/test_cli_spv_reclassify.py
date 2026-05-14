"""Regression tests for the v0.3.1 --spv silent no-op fix.

Before v0.3.1, `satsignal verify --spv` only ran the SPV merkle branch
when the underlying verify reached VERIFIED. PENDING / OFFLINE / NETWORK
silently emitted `"spv": null` and exited with the underlying class's
exit code (PENDING/OFFLINE → 0). A caller chaining
`satsignal verify --spv … && publish_attestation` would treat a 0-conf
or offline anchor as SPV-verified.

v0.3.1 reclassifies those three classes to VerifyClass.SPV (exit 8) when
--spv was requested. CRYPTO / CHAIN / VERSION already exit non-zero on
their own merits and are NOT reclassified.
"""

import argparse
import io
import tempfile
import unittest
import unittest.mock as mock
import zipfile
from contextlib import redirect_stdout
from pathlib import Path

from satsignal.bundle import Bundle
from satsignal.cli import cmd_verify
from satsignal.verify import VerifyClass, VerifyResult


def _stub_bundle() -> Bundle:
    return Bundle(
        manifest={"mbnt_version": "2.0", "mode": "standard"},
        canonical={},
        proofs=None,
        raw_canonical_bytes=b"{}",
        path=None,
    )


def _make_args(file_path: Path, bundle_path: Path, *,
               spv: bool = True, offline: bool = False,
               as_json: bool = True) -> argparse.Namespace:
    return argparse.Namespace(
        file=file_path,
        bundle=bundle_path,
        offline=offline,
        spv=spv,
        min_confirmations=0,
        json=as_json,
        ascii=True,  # disable unicode glyphs in human render
        no_unicode=False,
    )


class SpvReclassifyTest(unittest.TestCase):
    """When --spv is requested but the underlying verify didn't reach
    VERIFIED, the three silent-success-ish classes must reclassify to
    SPV (exit 8)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.file = self.tmp_path / "doc.txt"
        self.file.write_bytes(b"hello")
        # cmd_verify checks bundle_path.is_file(), so the bundle path
        # must point at a real file. load_bundle is never called because
        # verify_file is mocked.
        self.bundle = self.tmp_path / "doc.txt.mbnt"
        with zipfile.ZipFile(self.bundle, "w") as zf:
            zf.writestr("manifest.json", "{}")
            zf.writestr("canonical.json", "{}")

    def tearDown(self):
        self.tmp.cleanup()

    def _run_with_mocked_class(self, underlying_cls: VerifyClass, *,
                               spv: bool = True, offline: bool = False) -> int:
        result = VerifyResult(
            cls=underlying_cls,
            bundle=_stub_bundle(),
            sha256_hex="a" * 64,
            txid="b" * 64,
            confirmations=0 if underlying_cls == VerifyClass.PENDING else None,
            message=None,
        )
        args = _make_args(self.file, self.bundle, spv=spv, offline=offline)
        # cmd_verify rejects --spv + --offline at the arg-parse level;
        # for OFFLINE we mock the result class but leave args.offline
        # False so we exercise the reclassify branch, not the rejection.
        with mock.patch("satsignal.cli.verify_file", return_value=result):
            buf = io.StringIO()
            with redirect_stdout(buf):
                exit_code = cmd_verify(args)
            self.json_out = buf.getvalue()
        return exit_code

    def test_pending_with_spv_reclassifies_to_spv_exit_8(self):
        code = self._run_with_mocked_class(VerifyClass.PENDING)
        self.assertEqual(code, 8)
        self.assertIn('"class": "spv"', self.json_out)
        self.assertIn("0-conf", self.json_out)

    def test_offline_with_spv_reclassifies_to_spv_exit_8(self):
        code = self._run_with_mocked_class(VerifyClass.OFFLINE)
        self.assertEqual(code, 8)
        self.assertIn('"class": "spv"', self.json_out)
        self.assertIn("--offline", self.json_out)

    def test_network_with_spv_reclassifies_to_spv_exit_8(self):
        code = self._run_with_mocked_class(VerifyClass.NETWORK)
        self.assertEqual(code, 8)
        self.assertIn('"class": "spv"', self.json_out)
        self.assertIn("network error", self.json_out)

    def test_pending_without_spv_keeps_exit_0(self):
        """--spv NOT requested → PENDING stays PENDING (exit 0).
        Guards against accidental reclassify-on-every-pending."""
        code = self._run_with_mocked_class(VerifyClass.PENDING, spv=False)
        self.assertEqual(code, 0)
        self.assertIn('"class": "pending"', self.json_out)

    def test_offline_without_spv_keeps_exit_0(self):
        code = self._run_with_mocked_class(
            VerifyClass.OFFLINE, spv=False, offline=True,
        )
        self.assertEqual(code, 0)
        self.assertIn('"class": "offline"', self.json_out)

    def test_crypto_with_spv_is_not_reclassified(self):
        """Hard failures already exit non-zero on their own. CRYPTO must
        keep exit 1, not be masked as SPV (which would lose the signal)."""
        code = self._run_with_mocked_class(VerifyClass.CRYPTO)
        self.assertEqual(code, 1)
        self.assertIn('"class": "crypto"', self.json_out)

    def test_chain_with_spv_is_not_reclassified(self):
        code = self._run_with_mocked_class(VerifyClass.CHAIN)
        self.assertEqual(code, 2)
        self.assertIn('"class": "chain"', self.json_out)

    def test_version_with_spv_is_not_reclassified(self):
        code = self._run_with_mocked_class(VerifyClass.VERSION)
        self.assertEqual(code, 6)
        self.assertIn('"class": "version"', self.json_out)

    def test_reclassified_spv_emits_null_spv_block_in_json(self):
        """JSON shape: when reclassified to SPV (didn't actually run
        merkle proof), the `spv` key must be null, not a stub object."""
        self._run_with_mocked_class(VerifyClass.PENDING)
        self.assertIn('"spv": null', self.json_out)


if __name__ == "__main__":
    unittest.main()
