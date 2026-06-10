import json
import time
from pathlib import Path
from typing import Iterable, Optional

from .config import LOG_PATH, STATE_DIR


def record_anchor(
    *,
    sha256_hex: str,
    txid: str,
    proof_id: str,
    mode: str,
    folder: str,
    proof_url: str,
    bundle_url: Optional[str],
    label: Optional[str],
) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    # Local jsonl artifact: canonical keys are primary; the legacy
    # `bundle_id` / `matter` / `receipt_url` keys are still WRITTEN
    # alongside (additive — not a wire call) so existing `anchors.jsonl`
    # consumers keep parsing. Old rows without the canonical keys still
    # render via the read-side fallback in `cmd_log`.
    row = {
        "ts": int(time.time()),
        "sha256": sha256_hex,
        "txid": txid,
        "proof_id": proof_id,
        "bundle_id": proof_id,
        "mode": mode,
        "folder": folder,
        "matter": folder,
        "proof_url": proof_url,
        "receipt_url": proof_url,
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
