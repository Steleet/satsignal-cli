import json
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


SUPPORTED_MBNT_VERSIONS = {"1.1", "2.0", "2.1"}


class BundleError(Exception):
    """Raised when a .mbnt bundle is structurally malformed.
    Corresponds to verify error class CRYPTO per bundle-v1.md §8."""


@dataclass
class Bundle:
    """Parsed .mbnt bundle. See bundle-v1.md §2–§5 for field semantics."""

    manifest: dict
    canonical: dict
    proofs: Optional[dict]  # only when chunk_merkle is present
    raw_canonical_bytes: bytes  # bytes-on-disk for doc_hash verification
    path: Optional[Path] = None

    @property
    def mbnt_version(self) -> str:
        return str(self.manifest.get("mbnt_version", ""))

    @property
    def mode(self) -> str:
        # Standard mode is the absence of `mode` (bundle-v1.md §3.2).
        # Anything else explicit takes that string verbatim.
        m = self.manifest.get("mode")
        return m if m else "standard"

    @property
    def txid(self) -> str:
        return str(self.manifest.get("txid", ""))

    @property
    def doc_hash_expected(self) -> str:
        return str(self.manifest.get("doc_hash_expected", ""))


def load_bundle(path: Path) -> Bundle:
    if not zipfile.is_zipfile(path):
        raise BundleError(f"{path} is not a ZIP archive")

    manifest = None
    canonical = None
    proofs = None
    raw_canonical_bytes = b""

    with zipfile.ZipFile(path) as zf:
        names = set(zf.namelist())
        if "manifest.json" not in names:
            raise BundleError("manifest.json missing from bundle")
        if "canonical.json" not in names:
            raise BundleError("canonical.json missing from bundle")

        try:
            manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise BundleError(f"manifest.json not valid UTF-8 JSON: {e}")

        raw_canonical_bytes = zf.read("canonical.json")
        try:
            canonical = json.loads(raw_canonical_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise BundleError(f"canonical.json not valid UTF-8 JSON: {e}")

        if "proofs.json" in names:
            try:
                proofs = json.loads(zf.read("proofs.json").decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as e:
                raise BundleError(f"proofs.json not valid UTF-8 JSON: {e}")

    if "chunk_merkle" in canonical.get("subject", {}).get("proofs", {}):
        if proofs is None:
            raise BundleError(
                "canonical.json declares chunk_merkle but proofs.json is "
                "absent"
            )

    return Bundle(
        manifest=manifest,
        canonical=canonical,
        proofs=proofs,
        raw_canonical_bytes=raw_canonical_bytes,
        path=path,
    )


def find_sidecar(file_path: Path) -> Optional[Path]:
    """Locate the .mbnt sidecar for a given file. Tries (in order):
    <file>.mbnt next to the source, then .satsignal/<sha-prefix>.*.mbnt.
    Returns None if no candidate exists."""
    direct = file_path.with_name(file_path.name + ".mbnt")
    if direct.is_file():
        return direct

    dot_dir = file_path.parent / ".satsignal"
    if dot_dir.is_dir():
        # Don't compute the SHA here; fall back to "any .mbnt in
        # .satsignal/" only if there's exactly one — otherwise the
        # caller must disambiguate.
        candidates = list(dot_dir.glob("*.mbnt"))
        if len(candidates) == 1:
            return candidates[0]
    return None


def default_sidecar_path(file_path: Path) -> Path:
    """Where to write a sidecar for a freshly-anchored file."""
    return file_path.with_name(file_path.name + ".mbnt")
