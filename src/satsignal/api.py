import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import requests

from . import __version__
from .config import Config, resolve_folder_alias


# Identifying User-Agent so server logs can tell satsignal-cli traffic
# apart from raw curl / other clients. Mirrors the satsignal-mcp /
# satsignal-otel / satsignal-blob pattern.
_USER_AGENT = f"satsignal-cli/{__version__}"


def _auth_headers(cfg: Config) -> dict:
    return {
        "Authorization": f"Bearer {cfg.require_api_key()}",
        "User-Agent": _USER_AGENT,
    }


class APIError(Exception):
    """Raised on non-2xx responses from the Satsignal API. The caller
    decides whether to surface as exit code 4 (auth) or generic failure."""


@dataclass
class AnchorResult:
    bundle_id: str
    txid: str
    mode: str
    matter_slug: str
    receipt_url: str
    bundle_url: Optional[str]
    dry_run: bool

    # New public aliases. These mirror the legacy fields 1:1 so existing
    # code reading `.matter_slug` / `.receipt_url` / `.bundle_id` keeps
    # working byte-identically; new code may prefer the new names.
    @property
    def folder_slug(self) -> str:
        return self.matter_slug

    @property
    def proof_url(self) -> str:
        return self.receipt_url

    @property
    def proof_id(self) -> str:
        return self.bundle_id


def sha256_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def anchor_standard(
    cfg: Config,
    *,
    sha256_hex: str,
    file_size: int,
    matter: Optional[str] = None,
    folder: Optional[str] = None,
    label: Optional[str] = None,
    filename: Optional[str] = None,
) -> AnchorResult:
    # `folder` is the new public kwarg, `matter` the frozen legacy one.
    # Existing callers passing only `matter=` are unaffected. On
    # conflict (both set, different) raise loudly.
    slug = resolve_folder_alias(folder, matter,
                                source="anchor_standard folder/matter")
    # WIRE-TOKEN POLICY: the request body MUST still send the frozen
    # legacy key `matter_slug` so every Satsignal server (incl. older /
    # self-hosted) keeps accepting it. The new surface is folded in here.
    body = {
        "matter_slug": slug,
        "sha256_hex": sha256_hex,
        "file_size": file_size,
    }
    if label:
        body["label"] = label
    if filename:
        body["filename"] = filename

    r = requests.post(
        f"{cfg.base_url}/api/v1/anchors",
        json=body,
        headers=_auth_headers(cfg),
        timeout=30,
    )
    if r.status_code == 401 or r.status_code == 403:
        raise APIError(f"auth: {_extract_error(r)}")
    if r.status_code == 429:
        raise APIError(f"quota: {_extract_error(r)}")
    if r.status_code >= 400:
        raise APIError(_extract_error(r))
    data = r.json()
    # READING responses: prefer the new key if the server emits it,
    # else fall back to the legacy key (servers today send legacy).
    return AnchorResult(
        bundle_id=data.get("proof_id") or data["bundle_id"],
        txid=data["txid"],
        mode=data.get("mode", "standard"),
        matter_slug=data.get("folder_slug") or data["matter_slug"],
        receipt_url=data.get("proof_url") or data["receipt_url"],
        bundle_url=data.get("bundle_url"),
        dry_run=bool(data.get("dry_run", False)),
    )


def fetch_bundle(cfg: Config, bundle_url: str) -> bytes:
    r = requests.get(
        bundle_url,
        headers=_auth_headers(cfg),
        timeout=30,
    )
    if r.status_code >= 400:
        raise APIError(f"fetching bundle: HTTP {r.status_code}")
    return r.content


def list_matters(cfg: Config) -> list[dict]:
    r = requests.get(
        f"{cfg.base_url}/api/v1/matters",
        headers=_auth_headers(cfg),
        timeout=15,
    )
    if r.status_code >= 400:
        raise APIError(_extract_error(r))
    data = r.json()
    return data.get("matters", []) if isinstance(data, dict) else data


def lookup_hash(cfg: Config, sha256_hex: str) -> Optional[dict]:
    """Discovery-only helper: file SHA → txid. Standard-mode anchors
    only; sealed/manifest bundles are excluded by design. Returns None
    on miss; raises on network errors."""
    r = requests.get(
        f"{cfg.proof_url}/lookup_hash",
        params={"h": sha256_hex},
        headers={"User-Agent": _USER_AGENT},
        timeout=15,
    )
    if r.status_code == 404:
        return None
    if r.status_code >= 400:
        raise APIError(f"lookup_hash: HTTP {r.status_code}")
    return r.json()


def _extract_error(r: requests.Response) -> str:
    try:
        body = r.json()
        if isinstance(body, dict):
            err = body.get("error")
            if isinstance(err, dict):
                msg = err.get("message") or err.get("code")
                if msg:
                    return f"HTTP {r.status_code}: {msg}"
    except ValueError:
        pass
    return f"HTTP {r.status_code}: {r.text[:200]}"
