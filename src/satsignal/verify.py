"""Conformant verifier per docs/notary_spec/bundle-v1.md §7.

Implements:
- Standard-mode + sealed-mode cryptographic checks (§7.2)
- doc_hash consistency via JCS-canonical SHA-256 (§7.3, §4.4)
- Chain confirmation by fetching the raw tx (§7.4, §6.2)
- Error classes: CRYPTO / CHAIN / VERSION / NETWORK / PENDING / OFFLINE

Stdlib + requests only. HKDF (RFC 5869) and HMAC-SHA256 are
implemented inline; no cryptography dep.
"""
import hashlib
import hmac
import json
import struct
import time
import unicodedata
from base64 import urlsafe_b64decode
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

import requests

from .bundle import Bundle, BundleError, SUPPORTED_MBNT_VERSIONS, load_bundle


class VerifyClass(Enum):
    VERIFIED = "verified"
    PENDING = "pending"   # crypto + chain OK, 0 confirmations
    OFFLINE = "offline"   # crypto OK, chain skipped
    CRYPTO = "crypto"
    CHAIN = "chain"
    VERSION = "version"
    NETWORK = "network"


# Exit codes per bundle-v1.md §8.
EXIT_CODES = {
    VerifyClass.VERIFIED: 0,
    VerifyClass.PENDING: 0,
    VerifyClass.OFFLINE: 0,
    VerifyClass.CRYPTO: 1,
    VerifyClass.CHAIN: 2,
    VerifyClass.NETWORK: 3,
    VerifyClass.VERSION: 6,
}


@dataclass
class VerifyResult:
    cls: VerifyClass
    bundle: Bundle
    sha256_hex: Optional[str] = None
    txid: Optional[str] = None
    confirmations: Optional[int] = None
    message: Optional[str] = None


def verify_file(
    file_path: Path,
    bundle_path: Path,
    *,
    offline: bool = False,
    min_confirmations: int = 0,
) -> VerifyResult:
    try:
        bundle = load_bundle(bundle_path)
    except BundleError as e:
        return VerifyResult(VerifyClass.CRYPTO, bundle=_empty_bundle(),
                            message=str(e))

    # §7.1 — supported version
    if bundle.mbnt_version not in SUPPORTED_MBNT_VERSIONS:
        return VerifyResult(
            VerifyClass.VERSION, bundle=bundle,
            message=f"unsupported mbnt_version: {bundle.mbnt_version!r}",
        )

    # §7.2 — cryptographic checks
    crypto_err = _verify_crypto(bundle, file_path)
    if crypto_err is not None:
        return VerifyResult(VerifyClass.CRYPTO, bundle=bundle,
                            message=crypto_err)

    # §7.3 — doc_hash consistency
    dh_err = _verify_doc_hash(bundle)
    if dh_err is not None:
        return VerifyResult(VerifyClass.CRYPTO, bundle=bundle,
                            message=dh_err)

    sha256_hex, _ = _sha256(file_path)
    if offline:
        return VerifyResult(VerifyClass.OFFLINE, bundle=bundle,
                            sha256_hex=sha256_hex, txid=bundle.txid)

    # §7.4 — chain confirmation
    try:
        confirmations, doc_hash_on_chain = _fetch_chain(bundle.txid)
    except _NetworkError as e:
        return VerifyResult(VerifyClass.NETWORK, bundle=bundle,
                            sha256_hex=sha256_hex, txid=bundle.txid,
                            message=str(e))

    if doc_hash_on_chain != bundle.doc_hash_expected:
        return VerifyResult(
            VerifyClass.CHAIN, bundle=bundle,
            sha256_hex=sha256_hex, txid=bundle.txid,
            message=(
                f"on-chain doc_hash {doc_hash_on_chain} does not match "
                f"bundle's {bundle.doc_hash_expected}"
            ),
        )

    if confirmations < min_confirmations:
        return VerifyResult(
            VerifyClass.PENDING, bundle=bundle,
            sha256_hex=sha256_hex, txid=bundle.txid,
            confirmations=confirmations,
            message=(
                f"only {confirmations} confirmation(s); "
                f"requested ≥ {min_confirmations}"
            ),
        )

    cls = VerifyClass.PENDING if confirmations == 0 else VerifyClass.VERIFIED
    return VerifyResult(cls, bundle=bundle, sha256_hex=sha256_hex,
                        txid=bundle.txid, confirmations=confirmations)


# ────────────────────────── §7.2 helpers ──────────────────────────

def _verify_crypto(bundle: Bundle, file_path: Path) -> Optional[str]:
    proofs = bundle.canonical.get("subject", {}).get("proofs")
    if bundle.mode != "sealed":
        # v1 bundles (schema_version 1) carry subject.document_sha256
        # instead of subject.proofs — let _verify_crypto_standard route
        # through its v1 fallback rather than bailing here.
        return _verify_crypto_standard(bundle, file_path, proofs or {})
    if proofs is None:
        return "sealed bundle missing subject.proofs"
    return _verify_crypto_sealed(bundle, file_path, proofs)


def _verify_crypto_standard(bundle: Bundle, file_path: Path,
                            proofs: dict) -> Optional[str]:
    # Required byte_exact check.
    if "byte_exact" not in proofs:
        # v1 fallback: subject.document_sha256
        v1_hash = bundle.canonical.get("subject", {}).get("document_sha256")
        if v1_hash:
            actual, _ = _sha256(file_path)
            if actual != v1_hash:
                return f"sha256 mismatch (v1): {actual} != {v1_hash}"
            return None
        return "byte_exact proof missing"

    expected_hash = proofs["byte_exact"].get("hash")
    if not expected_hash:
        return "byte_exact.hash missing"
    actual, _ = _sha256(file_path)
    if actual != expected_hash:
        return f"sha256 mismatch: {actual} != {expected_hash}"

    # content_canonical and chunk_merkle are out of scope for v0.1 (would
    # require porting verifier.html's per-scheme canonicalizers). Surface
    # this honestly rather than silently passing.
    if "content_canonical" in proofs:
        return ("content_canonical proofs are present but this CLI "
                "version (0.1) only validates byte_exact. Use the web "
                "verifier at /verify for a complete check.")
    if "chunk_merkle" in proofs:
        return ("chunk_merkle proofs are present but this CLI version "
                "(0.1) only validates byte_exact. Use the web verifier "
                "at /verify for a complete check.")
    return None


def _verify_crypto_sealed(bundle: Bundle, file_path: Path,
                          proofs: dict) -> Optional[str]:
    salt_b64 = bundle.manifest.get("salt_b64")
    if not salt_b64:
        return "sealed manifest missing salt_b64"
    try:
        master_salt = urlsafe_b64decode(_pad_b64(salt_b64))
    except Exception as e:  # noqa: BLE001
        return f"salt_b64 decode failed: {e}"
    if len(master_salt) != 32:
        return f"master_salt has {len(master_salt)} bytes; expected 32"

    if "byte_exact" not in proofs:
        return "byte_exact proof missing"
    expected = proofs["byte_exact"].get("commitment")
    if not expected:
        return "byte_exact.commitment missing"

    file_bytes = file_path.read_bytes()
    actual = hmac.new(master_salt, file_bytes, hashlib.sha256).hexdigest()
    if actual != expected:
        return f"sealed byte_exact mismatch: {actual} != {expected}"

    if "content_canonical" in proofs or "chunk_merkle" in proofs:
        return ("sealed content_canonical / chunk_merkle proofs are "
                "present but this CLI version (0.1) only validates "
                "sealed byte_exact. Use /verify for a complete check.")
    return None


# ────────────────────────── §7.3: doc_hash ──────────────────────────

def _verify_doc_hash(bundle: Bundle) -> Optional[str]:
    """Re-canonicalize canonical.json per JCS, sha256, slice to 20 bytes,
    compare to manifest.doc_hash_expected (bundle-v1.md §4.4, §7.3)."""
    # Per the spec, the bundle's canonical.json bytes-on-disk SHOULD
    # already be the JCS-canonical form. Re-encode and verify equality,
    # then derive the hash from those bytes. If the bundle was stored
    # pretty-printed we'd reject here.
    re_encoded = _jcs(bundle.canonical)
    if re_encoded != bundle.raw_canonical_bytes:
        return ("canonical.json is not in canonical JCS form "
                "(bytes differ on re-encode)")
    derived = hashlib.sha256(re_encoded).hexdigest()[:40]
    if derived != bundle.doc_hash_expected:
        return (f"doc_hash mismatch: derived {derived} != "
                f"manifest {bundle.doc_hash_expected}")
    return None


# ────────────────────────── §7.4: chain ──────────────────────────

class _NetworkError(Exception):
    pass


def _get_with_retry(url: str, timeout: int):
    """GET with one retry on RequestException (1s backoff). Returns the
    Response or None if both attempts raise. HTTP non-200 is NOT retried."""
    try:
        return requests.get(url, timeout=timeout)
    except requests.RequestException:
        time.sleep(1.0)
    try:
        return requests.get(url, timeout=timeout)
    except requests.RequestException:
        return None


def _fetch_chain(txid: str) -> tuple[int, str]:
    """Return (confirmations, doc_hash_hex). Tries WhatsOnChain, falls
    back to Bitails. Each explorer gets one retry on transient network
    failure. Raises _NetworkError on full failure."""
    r = _get_with_retry(
        f"https://api.whatsonchain.com/v1/bsv/main/tx/hash/{txid}",
        timeout=20,
    )
    if r is not None and r.status_code == 200:
        data = r.json()
        confirmations = int(data.get("confirmations", 0))
        doc_hash = _parse_mbnt_from_woc(data)
        if doc_hash is None:
            raise _NetworkError(
                f"no MBNT OP_RETURN found in tx {txid}"
            )
        return confirmations, doc_hash

    # Bitails fallback (returns raw hex; needs script parsing)
    r = _get_with_retry(
        f"https://api.bitails.io/tx/{txid}", timeout=20,
    )
    if r is not None and r.status_code == 200:
        data = r.json()
        confirmations = int(data.get("confirmations", 0))
        doc_hash = _parse_mbnt_from_bitails(data)
        if doc_hash is None:
            raise _NetworkError(
                f"no MBNT OP_RETURN found in tx {txid}"
            )
        return confirmations, doc_hash

    raise _NetworkError("could not reach WhatsOnChain or Bitails")


def _parse_mbnt_from_woc(tx_data: dict) -> Optional[str]:
    """WhatsOnChain returns vout[].scriptPubKey.hex. Walk outputs, find
    the first OP_FALSE OP_RETURN whose pushed bytes begin with the
    MBNT magic, slice doc_hash = payload[8:28]."""
    for vout in tx_data.get("vout", []):
        script_hex = vout.get("scriptPubKey", {}).get("hex")
        if not script_hex:
            continue
        doc_hash = _extract_mbnt_doc_hash(script_hex)
        if doc_hash:
            return doc_hash
    return None


def _parse_mbnt_from_bitails(tx_data: dict) -> Optional[str]:
    for out in tx_data.get("outputs", []):
        script_hex = out.get("scriptPubKey") or out.get("script", {}).get("hex")
        if not script_hex:
            continue
        doc_hash = _extract_mbnt_doc_hash(script_hex)
        if doc_hash:
            return doc_hash
    return None


def _extract_mbnt_doc_hash(script_hex: str) -> Optional[str]:
    """Parse OP_FALSE OP_RETURN <push N> <payload>. Returns the 40-hex
    doc_hash (payload[8:28]) if the payload's magic is MBNT, else None.
    bundle-v1.md §6.1 + SPEC_mbnt.md §1–§2 are the references."""
    try:
        b = bytes.fromhex(script_hex)
    except ValueError:
        return None
    if len(b) < 4 or b[0] != 0x00 or b[1] != 0x6a:
        return None
    idx = 2
    if idx >= len(b):
        return None
    op = b[idx]
    idx += 1
    if 0x01 <= op <= 0x4b:
        push_len = op
    elif op == 0x4c:  # OP_PUSHDATA1
        if idx >= len(b):
            return None
        push_len = b[idx]
        idx += 1
    else:
        return None  # MBNT does not use PUSHDATA2/4
    payload = b[idx:idx + push_len]
    if len(payload) < 28 or payload[:4] != b"MBNT":
        return None
    return payload[8:28].hex()


# ────────────────────────── JCS (RFC 8785) ──────────────────────────

def _jcs(obj) -> bytes:
    """Minimal JSON Canonicalization Scheme encoder. Sufficient for the
    canonical-doc shapes Satsignal emits (strings, ints, bools, nulls,
    arrays, dicts; no floats — Satsignal canonical docs don't use
    them). NFC-normalizes strings, sorts dict keys, no whitespace."""
    return _jcs_inner(obj).encode("utf-8")


def _jcs_inner(obj) -> str:
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, float):
        # Satsignal canonical docs don't use floats; raise rather than
        # emit a non-canonical form silently.
        raise ValueError(
            "JCS float encoding not implemented; Satsignal canonical "
            "docs are integer-only"
        )
    if isinstance(obj, str):
        return json.dumps(
            unicodedata.normalize("NFC", obj),
            ensure_ascii=False,
            separators=(",", ":"),
        )
    if isinstance(obj, list):
        return "[" + ",".join(_jcs_inner(x) for x in obj) + "]"
    if isinstance(obj, dict):
        items = sorted(
            obj.items(),
            key=lambda kv: unicodedata.normalize("NFC", kv[0]).encode("utf-16-be"),
        )
        return (
            "{"
            + ",".join(
                json.dumps(
                    unicodedata.normalize("NFC", k),
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + ":"
                + _jcs_inner(v)
                for k, v in items
            )
            + "}"
        )
    raise ValueError(f"unsupported type for JCS: {type(obj).__name__}")


# ────────────────────────── HKDF (RFC 5869) ──────────────────────────
# Reserved for sealed-mode chunk_merkle verification; not used in v0.1
# but present so v0.2 can drop in without adding a dependency.

def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    output = b""
    t = b""
    counter = 1
    while len(output) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        output += t
        counter += 1
    return output[:length]


def derive_leaf_salt(master_salt: bytes, leaf_index: int) -> bytes:
    """Per bundle-v1.md §5 / SPEC_v2_sealed.md §3.3."""
    info = b"chunk/" + struct.pack(">I", leaf_index)
    return hkdf(
        ikm=master_salt,
        salt=b"satsignal-sealed-v1/per-leaf",
        info=info,
        length=32,
    )


# ────────────────────────── utilities ──────────────────────────

def _sha256(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def _pad_b64(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def _empty_bundle() -> Bundle:
    return Bundle(manifest={}, canonical={}, proofs=None,
                  raw_canonical_bytes=b"")
