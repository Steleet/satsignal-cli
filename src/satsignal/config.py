import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

if sys.version_info >= (3, 11):
    import tomllib as _toml
else:
    try:
        import tomli as _toml
    except ImportError:
        _toml = None


CONFIG_DIR = Path.home() / ".config" / "satsignal"
CREDENTIALS_PATH = CONFIG_DIR / "credentials.toml"
STATE_DIR = Path.home() / ".local" / "state" / "satsignal"
LOG_PATH = STATE_DIR / "anchors.jsonl"


def resolve_folder_alias(folder, matter, *, source: str = "folder/matter"):
    """Reconcile the canonical ``folder`` surface with the legacy
    ``matter`` surface (library kwargs).

    Compat rule (mirrors the server's ``conflicting_alias`` error):

    * neither set      -> ``None`` (caller falls back to its own default)
    * only one set     -> use it
    * both set, equal  -> accept (use the value)
    * both set, differ -> raise ``ValueError`` loudly; never silently pick

    Precedence when both are equal / only-legacy-missing: the canonical
    ``folder`` value is preferred, ``matter`` is the fallback. Empty
    strings / ``None`` count as "not set" so ``folder=""`` can't mask a
    real ``matter=``.
    """
    f = folder if folder else None
    m = matter if matter else None
    if f is not None and m is not None and f != m:
        raise ValueError(
            f"folder and matter are aliases and must not be set to "
            f"different values; use folder ({source}: "
            f"folder={f!r}, matter={m!r})"
        )
    return f if f is not None else m

DEFAULT_BASE_URL = "https://app.satsignal.cloud"
DEFAULT_PROOF_URL = "https://proof.satsignal.cloud"
DEFAULT_FOLDER = "inbox"
# Legacy alias of DEFAULT_FOLDER (kept for library back-compat).
DEFAULT_MATTER = DEFAULT_FOLDER


@dataclass
class Config:
    api_key: Optional[str]
    base_url: str = DEFAULT_BASE_URL
    proof_url: str = DEFAULT_PROOF_URL
    folder: str = DEFAULT_FOLDER

    @classmethod
    def load(cls) -> "Config":
        env_key = os.environ.get("SATSIGNAL_API_KEY")
        file_data = _read_credentials_file()

        api_key = env_key or file_data.get("api_key")
        base_url = (
            os.environ.get("SATSIGNAL_BASE_URL")
            or file_data.get("base_url")
            or DEFAULT_BASE_URL
        ).rstrip("/")
        proof_url = (
            os.environ.get("SATSIGNAL_PROOF_URL")
            or file_data.get("proof_url")
            or DEFAULT_PROOF_URL
        ).rstrip("/")
        # `folder` is the canonical name. SATSIGNAL_FOLDER is read
        # first; SATSIGNAL_MATTER is the legacy fallback (still honored,
        # no longer documented). Same precedence for the config-file
        # keys, then chain env -> file -> default.
        env_folder = (
            os.environ.get("SATSIGNAL_FOLDER")
            or os.environ.get("SATSIGNAL_MATTER")  # legacy fallback
            or None
        )
        file_folder = (
            file_data.get("folder")
            or file_data.get("matter")  # legacy fallback
            or None
        )
        folder = env_folder or file_folder or DEFAULT_FOLDER
        return cls(api_key=api_key, base_url=base_url,
                   proof_url=proof_url, folder=folder)

    @property
    def matter(self) -> str:
        """Legacy read alias for the resolved folder slug (kept for
        library back-compat; new code reads ``.folder``)."""
        return self.folder

    def require_api_key(self) -> str:
        if not self.api_key:
            raise SystemExit(
                "satsignal: no API key found. Set SATSIGNAL_API_KEY or "
                "run `satsignal login`."
            )
        return self.api_key


def _read_credentials_file() -> dict:
    if not CREDENTIALS_PATH.exists():
        return {}
    if _toml is None:
        sys.stderr.write(
            "warning: credentials.toml present but tomli isn't installed; "
            "install satsignal-cli[toml-py39] on Python<3.11.\n"
        )
        return {}
    try:
        with CREDENTIALS_PATH.open("rb") as f:
            return _toml.load(f)
    except OSError:
        return {}


def write_credentials(api_key: str, base_url: Optional[str] = None,
                      matter: Optional[str] = None,
                      folder: Optional[str] = None) -> Path:
    # `folder` is the canonical arg; `matter` is the legacy alias. If
    # both are given they must agree. The file now stores the canonical
    # `folder` key (CLI >= 0.4.0 reads it; `matter` keys in existing
    # files keep being read as a legacy fallback).
    slug = resolve_folder_alias(folder, matter,
                                source="write_credentials folder/matter")
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    lines = [f'api_key = "{api_key}"']
    if base_url:
        lines.append(f'base_url = "{base_url}"')
    if slug:
        lines.append(f'folder = "{slug}"')
    CREDENTIALS_PATH.write_text("\n".join(lines) + "\n")
    CREDENTIALS_PATH.chmod(0o600)
    return CREDENTIALS_PATH
