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

DEFAULT_BASE_URL = "https://app.satsignal.cloud"
DEFAULT_PROOF_URL = "https://proof.satsignal.cloud"
DEFAULT_MATTER = "inbox"


@dataclass
class Config:
    api_key: Optional[str]
    base_url: str = DEFAULT_BASE_URL
    proof_url: str = DEFAULT_PROOF_URL
    matter: str = DEFAULT_MATTER

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
        matter = (
            os.environ.get("SATSIGNAL_MATTER")
            or file_data.get("matter")
            or DEFAULT_MATTER
        )
        return cls(api_key=api_key, base_url=base_url,
                   proof_url=proof_url, matter=matter)

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
                      matter: Optional[str] = None) -> Path:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    lines = [f'api_key = "{api_key}"']
    if base_url:
        lines.append(f'base_url = "{base_url}"')
    if matter:
        lines.append(f'matter = "{matter}"')
    CREDENTIALS_PATH.write_text("\n".join(lines) + "\n")
    CREDENTIALS_PATH.chmod(0o600)
    return CREDENTIALS_PATH
