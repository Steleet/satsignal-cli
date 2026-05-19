import json
import time
from pathlib import Path
from typing import Iterable, Optional

from .config import LOG_PATH, STATE_DIR


def record_anchor(
    *,
    sha256_hex: str,
    txid: str,
    bundle_id: str,
    mode: str,
    matter: str,
    receipt_url: str,
    bundle_url: Optional[str],
    label: Optional[str],
) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    # Local jsonl artifact: legacy keys kept byte-identical; new aliases
    # ADDED alongside (additive — not a wire call). Old `satsignal log`
    # readers ignore the extra keys; old rows without them still parse.
    row = {
        "ts": int(time.time()),
        "sha256": sha256_hex,
        "txid": txid,
        "bundle_id": bundle_id,
        "proof_id": bundle_id,
        "mode": mode,
        "matter": matter,
        "folder": matter,
        "receipt_url": receipt_url,
        "proof_url": receipt_url,
        "bundle_url": bundle_url,
        "label": label,
    }
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row) + "\n")


def read_log(limit: Optional[int] = None) -> list[dict]:
    if not LOG_PATH.exists():
        return []
    rows: list[dict] = []
    with LOG_PATH.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if limit is not None:
        rows = rows[-limit:]
    return rows
