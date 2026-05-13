"""Satsignal CLI entry point. Six verbs:

    satsignal anchor <file>          anchor a file; writes <file>.mbnt
    satsignal verify <file>          verify a receipt; chain-confirms by default
    satsignal show <bundle>          print bundle details
    satsignal log                    list local anchors
    satsignal login                  store API key
    satsignal matters                list workspace matters
"""
import argparse
import getpass
import json
import sys
from pathlib import Path
from typing import Optional

import requests

from . import __version__
from . import api, bundle, log
from .api import APIError
from .bundle import BundleError, default_sidecar_path, find_sidecar, load_bundle
from .config import Config, write_credentials
from .verify import EXIT_CODES, VerifyClass, verify_file


def _use_unicode(args: argparse.Namespace) -> bool:
    if getattr(args, "ascii", False):
        return False
    enc = (sys.stdout.encoding or "").lower()
    return "utf" in enc


def main(argv: Optional[list[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except APIError as e:
        msg = str(e)
        _err(f"satsignal: {msg}")
        if msg.startswith("auth:"):
            return 4
        return 1


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="satsignal",
        description="Anchor and verify files against the Satsignal BSV notary.",
    )
    p.add_argument("--version", action="version",
                   version=f"satsignal {__version__}")
    sub = p.add_subparsers(dest="cmd")

    pa = sub.add_parser("anchor", help="anchor a file (dry-run by default)")
    pa.add_argument("file", type=Path)
    pa.add_argument("--mode", choices=["standard", "sealed"],
                    default="standard")
    pa.add_argument("--matter", default=None,
                    help="matter slug (default from config / SATSIGNAL_MATTER)")
    pa.add_argument("--label", default=None)
    pa.add_argument("-o", "--out", type=Path, default=None,
                    help="override sidecar location")
    pa.add_argument("--broadcast", action="store_true",
                    help="actually anchor (default: dry-run)")
    pa.add_argument("--strict", action="store_true",
                    help="exit 7 if no local sidecar was written "
                         "(server returned no bundle_url)")
    pa.add_argument("--ascii", action="store_true",
                    help="force ASCII output (auto-on for non-UTF-8 stdouts)")
    pa.add_argument("--json", action="store_true",
                    help="machine-readable output")
    pa.set_defaults(func=cmd_anchor)

    pv = sub.add_parser("verify", help="verify a file against its .mbnt receipt")
    pv.add_argument("file", type=Path)
    pv.add_argument("--bundle", type=Path, default=None,
                    help="receipt path (default: <file>.mbnt)")
    pv.add_argument("--offline", action="store_true",
                    help="skip chain confirmation (loud warning)")
    pv.add_argument("--min-confirmations", type=int, default=0,
                    help="require at least N confirmations (default 0 = "
                         "PENDING is exit 0)")
    pv.add_argument("--spv", action="store_true",
                    help="additionally verify the tx via TSC merkle proof "
                         "against the local headers store (run `satsignal "
                         "headers sync` first). Exits 8 on SPV failure.")
    pv.add_argument("--ascii", action="store_true",
                    help="force ASCII output (auto-on for non-UTF-8 stdouts)")
    pv.add_argument("--json", action="store_true")
    pv.set_defaults(func=cmd_verify)

    ps = sub.add_parser("show", help="print bundle details")
    ps.add_argument("bundle", type=Path)
    ps.add_argument("--json", action="store_true")
    ps.set_defaults(func=cmd_show)

    pl = sub.add_parser("log", help="list recent local anchors")
    pl.add_argument("-n", "--limit", type=int, default=20)
    pl.add_argument("--json", action="store_true")
    pl.set_defaults(func=cmd_log)

    pli = sub.add_parser("login", help="store API key in ~/.config/satsignal/")
    pli.add_argument("--api-key", default=None,
                     help="API key (omit to prompt without echo)")
    pli.add_argument("--matter", default=None,
                     help="default matter slug")
    pli.add_argument("--base-url", default=None)
    pli.set_defaults(func=cmd_login)

    pm = sub.add_parser("matters", help="list workspace matters")
    pm.add_argument("--json", action="store_true")
    pm.set_defaults(func=cmd_matters)

    ph = sub.add_parser("headers", help="manage the local SPV headers store")
    ph_sub = ph.add_subparsers(dest="headers_cmd")
    phs = ph_sub.add_parser("sync", help="sync the local headers store to a BSV peer's tip")
    phs.add_argument("--peer", default=None,
                     help="peer host (default tries the seed list)")
    phs.add_argument("--port", type=int, default=8333)
    phs.set_defaults(func=cmd_headers_sync)
    phst = ph_sub.add_parser("status", help="print local headers store state")
    phst.add_argument("--json", action="store_true")
    phst.set_defaults(func=cmd_headers_status)

    return p


# ────────────────────────── anchor ──────────────────────────

def cmd_anchor(args: argparse.Namespace) -> int:
    cfg = Config.load()
    file_path: Path = args.file
    if not file_path.is_file():
        _err(f"satsignal: not a file: {file_path}")
        return 5

    if args.mode == "sealed":
        _err("satsignal: sealed mode not implemented in CLI v0.1; "
             "use https://sealed.satsignal.cloud or wait for v0.2.")
        return 1

    sha256_hex, file_size = api.sha256_file(file_path)
    matter = args.matter or cfg.matter
    sidecar = args.out or default_sidecar_path(file_path)

    if not args.broadcast:
        _print_anchor_dryrun(file_path, sha256_hex, file_size,
                             args.mode, matter, sidecar, args.label,
                             as_json=args.json)
        return 0

    result = api.anchor_standard(
        cfg,
        sha256_hex=sha256_hex,
        file_size=file_size,
        matter=matter,
        label=args.label,
        filename=file_path.name,
    )

    if result.bundle_url:
        bundle_bytes = api.fetch_bundle(cfg, result.bundle_url)
        sidecar.write_bytes(bundle_bytes)
    else:
        _err(f"satsignal: server returned no bundle_url; receipt is at "
             f"{result.receipt_url}")

    log.record_anchor(
        sha256_hex=sha256_hex,
        txid=result.txid,
        bundle_id=result.bundle_id,
        mode=result.mode,
        matter=result.matter_slug,
        receipt_url=result.receipt_url,
        bundle_url=result.bundle_url,
        label=args.label,
    )

    if args.json:
        print(json.dumps({
            "anchored": True,
            "file": str(file_path),
            "sha256": sha256_hex,
            "txid": result.txid,
            "bundle_id": result.bundle_id,
            "mode": result.mode,
            "matter": result.matter_slug,
            "receipt": result.receipt_url,
            "sidecar": str(sidecar) if result.bundle_url else None,
        }))
    else:
        ok = "✓" if _use_unicode(args) else "OK"
        print(f"{ok} anchored {file_path}")
        print(f"  txid:     {result.txid}")
        print(f"  bundle:   {result.bundle_id}")
        print(f"  matter:   {result.matter_slug}")
        if result.bundle_url:
            print(f"  receipt:  {sidecar} ({sidecar.stat().st_size:,} bytes)")
        print(f"  url:      {result.receipt_url}")
        print(f"  verify:   satsignal verify {file_path}")
    if args.strict and not result.bundle_url:
        return 7
    return 0


def _print_anchor_dryrun(file_path, sha256_hex, file_size, mode, matter,
                        sidecar, label, *, as_json: bool) -> None:
    if as_json:
        print(json.dumps({
            "dry_run": True,
            "file": str(file_path),
            "sha256": sha256_hex,
            "file_size": file_size,
            "mode": mode,
            "matter": matter,
            "sidecar": str(sidecar),
            "label": label,
        }))
        return
    print("DRY RUN — would anchor:")
    print(f"  file:    {file_path}")
    print(f"  sha256:  {sha256_hex}")
    print(f"  size:    {file_size:,} bytes")
    print(f"  mode:    {mode}")
    print(f"  matter:  {matter}")
    if label:
        print(f"  label:   {label}")
    print(f"  out:     {sidecar}")
    print()
    print("Re-run with --broadcast to send.")


# ────────────────────────── verify ──────────────────────────

def cmd_verify(args: argparse.Namespace) -> int:
    file_path: Path = args.file
    if not file_path.is_file():
        _err(f"satsignal: not a file: {file_path}")
        return 5

    bundle_path = args.bundle or find_sidecar(file_path)
    if bundle_path is None or not bundle_path.is_file():
        _err(f"satsignal: no .mbnt sidecar for {file_path}; pass --bundle "
             f"<path> or place one at {default_sidecar_path(file_path)}")
        return 5

    if args.offline:
        _err("warning: --offline skips chain confirmation. Locally-"
             "fabricated bundles pass crypto-only checks; only the chain "
             "check distinguishes a real anchor.")

    if args.spv and args.offline:
        _err("satsignal: --spv requires fetching a merkle proof; cannot "
             "combine with --offline")
        return 1

    result = verify_file(
        file_path, bundle_path,
        offline=args.offline,
        min_confirmations=args.min_confirmations,
    )

    spv_height: Optional[int] = None
    spv_block_hash_be: Optional[str] = None
    if args.spv and result.cls == VerifyClass.VERIFIED:
        from .headers import HeaderStore, HeadersError
        from .spv import verify_txid_in_chain
        try:
            store = HeaderStore()
        except HeadersError as e:
            result = type(result)(
                cls=VerifyClass.SPV, bundle=result.bundle,
                sha256_hex=result.sha256_hex, txid=result.txid,
                confirmations=result.confirmations,
                message=f"local headers store unreadable: {e}",
            )
        else:
            if store.tip_height < 0:
                result = type(result)(
                    cls=VerifyClass.SPV, bundle=result.bundle,
                    sha256_hex=result.sha256_hex, txid=result.txid,
                    confirmations=result.confirmations,
                    message=("local headers store empty — run `satsignal "
                             "headers sync` first"),
                )
            else:
                spv = verify_txid_in_chain(result.txid, store)
                if not spv.ok:
                    result = type(result)(
                        cls=VerifyClass.SPV, bundle=result.bundle,
                        sha256_hex=result.sha256_hex, txid=result.txid,
                        confirmations=result.confirmations,
                        message=f"SPV: {spv.error}",
                    )
                else:
                    spv_height = spv.height
                    spv_block_hash_be = spv.block_hash_be
    elif args.spv and result.cls in (
        VerifyClass.PENDING, VerifyClass.OFFLINE, VerifyClass.NETWORK,
    ):
        # User asked for SPV but the underlying verify didn't reach
        # VERIFIED. Previously this silently no-op'd: "spv": null was
        # emitted in JSON and the exit code followed the underlying
        # class (PENDING/OFFLINE → 0). A caller running
        # `satsignal verify --spv … && publish_attestation` would have
        # treated a 0-conf or offline result as SPV-verified. Reclassify
        # to VerifyClass.SPV with a reason so the request is honored
        # (exits 8) and the user knows SPV didn't run.
        reasons = {
            VerifyClass.PENDING:
                "SPV requires a confirmed tx; this anchor is 0-conf. "
                "Wait for a block, then re-run with --spv.",
            VerifyClass.OFFLINE:
                "--spv requires online chain verification; --offline "
                "skips it. Drop --offline to run SPV.",
            VerifyClass.NETWORK:
                "SPV depends on the chain-confirmation step that just "
                "failed (network error). Retry when the explorer is "
                "reachable.",
        }
        result = type(result)(
            cls=VerifyClass.SPV, bundle=result.bundle,
            sha256_hex=result.sha256_hex, txid=result.txid,
            confirmations=result.confirmations,
            message=reasons[result.cls],
        )

    if args.json:
        print(json.dumps({
            "class": result.cls.value,
            "file": str(file_path),
            "bundle": str(bundle_path),
            "sha256": result.sha256_hex,
            "txid": result.txid,
            "confirmations": result.confirmations,
            "message": result.message,
            "spv": {
                "block_height": spv_height,
                "block_hash": spv_block_hash_be,
            } if args.spv and result.cls == VerifyClass.VERIFIED else None,
        }))
    else:
        _render_verify_human(result, file_path, bundle_path,
                             unicode_ok=_use_unicode(args))

    return EXIT_CODES[result.cls]


def _render_verify_human(result, file_path: Path, bundle_path: Path,
                         *, unicode_ok: bool = True) -> None:
    if unicode_ok:
        label = {
            VerifyClass.VERIFIED: "✓ verified",
            VerifyClass.PENDING:  "⏳ pending (broadcast, awaiting confirmation)",
            VerifyClass.OFFLINE:  "✓ crypto OK (chain NOT verified)",
            VerifyClass.CRYPTO:   "✗ CRYPTO failure",
            VerifyClass.CHAIN:    "✗ CHAIN failure",
            VerifyClass.VERSION:  "✗ VERSION unsupported",
            VerifyClass.NETWORK:  "? NETWORK error",
            VerifyClass.SPV:      "✗ SPV failure",
        }[result.cls]
    else:
        label = {
            VerifyClass.VERIFIED: "OK verified",
            VerifyClass.PENDING:  "~  pending (broadcast, awaiting confirmation)",
            VerifyClass.OFFLINE:  "OK crypto OK (chain NOT verified)",
            VerifyClass.CRYPTO:   "X  CRYPTO failure",
            VerifyClass.CHAIN:    "X  CHAIN failure",
            VerifyClass.VERSION:  "X  VERSION unsupported",
            VerifyClass.NETWORK:  "?  NETWORK error",
            VerifyClass.SPV:      "X  SPV failure",
        }[result.cls]
    print(f"{label}: {file_path}")
    print(f"  bundle:    {bundle_path}")
    if result.sha256_hex:
        print(f"  sha256:    {result.sha256_hex}")
    if result.txid:
        print(f"  txid:      {result.txid}")
    print(f"  mode:      {result.bundle.mode}")
    if result.confirmations is not None:
        print(f"  chain:     {result.confirmations} confirmation(s)")
    if result.message:
        for line in result.message.splitlines():
            print(f"  note:      {line}")


# ────────────────────────── show ──────────────────────────

def cmd_show(args: argparse.Namespace) -> int:
    try:
        b = load_bundle(args.bundle)
    except BundleError as e:
        _err(f"satsignal: {e}")
        return 1
    if args.json:
        print(json.dumps({
            "manifest": b.manifest,
            "canonical": b.canonical,
            "has_proofs": b.proofs is not None,
        }, indent=2, sort_keys=True))
        return 0
    print(f"bundle:        {args.bundle}")
    print(f"mbnt_version:  {b.mbnt_version}")
    print(f"mode:          {b.mode}")
    print(f"txid:          {b.txid}")
    print(f"doc_hash:      {b.doc_hash_expected}")
    network = b.manifest.get("network", "")
    if network:
        print(f"network:       {network}")
    filename = b.manifest.get("filename")
    if filename:
        print(f"filename:      {filename}")
    proofs = b.canonical.get("subject", {}).get("proofs", {})
    if proofs:
        print(f"proofs:        {', '.join(sorted(proofs))}")
    if b.proofs:
        print(f"proofs.json:   {b.proofs.get('scheme', '?')} "
              f"({len(b.proofs.get('merkle_leaves', []))} leaves)")
    return 0


# ────────────────────────── log ──────────────────────────

def cmd_log(args: argparse.Namespace) -> int:
    rows = log.read_log(limit=args.limit)
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    if not rows:
        print("(no anchors logged yet — `satsignal anchor --broadcast` "
              "appends rows here)")
        return 0
    for row in rows:
        ts = row.get("ts")
        sha = row.get("sha256", "")[:12]
        txid = row.get("txid", "")[:12]
        mode = row.get("mode", "?")
        matter = row.get("matter", "?")
        label = row.get("label") or ""
        print(f"{ts}  {mode:<8} {matter:<14} {sha}  {txid}  {label}")
    return 0


# ────────────────────────── login ──────────────────────────

def cmd_login(args: argparse.Namespace) -> int:
    key = args.api_key
    if not key:
        try:
            key = getpass.getpass("API key: ")
        except (EOFError, KeyboardInterrupt):
            _err("\nsatsignal: aborted")
            return 1
    key = key.strip()
    if not key:
        _err("satsignal: empty API key")
        return 1

    existing = Config.load()
    probe_cfg = Config(
        api_key=key,
        base_url=(args.base_url or existing.base_url).rstrip("/"),
        matter=args.matter or existing.matter,
    )
    try:
        api.list_matters(probe_cfg)
    except APIError as e:
        _err(f"satsignal: API rejected the key ({e}); not writing "
             f"credentials. Re-check the key and try again.")
        return 1
    except requests.RequestException as e:
        _err(f"satsignal: warning — could not reach {probe_cfg.base_url} "
             f"to validate the key ({e}). Writing credentials anyway.")

    path = write_credentials(api_key=key,
                             base_url=args.base_url,
                             matter=args.matter)
    print(f"wrote {path} (mode 600)")
    return 0


# ────────────────────────── matters ──────────────────────────

def cmd_matters(args: argparse.Namespace) -> int:
    cfg = Config.load()
    matters = api.list_matters(cfg)
    if args.json:
        print(json.dumps(matters, indent=2))
        return 0
    if not matters:
        print("(no matters in this workspace)")
        return 0
    for m in matters:
        slug = m.get("slug", "?")
        name = m.get("name") or ""
        print(f"{slug:<24} {name}")
    return 0


# ────────────────────────── headers ──────────────────────────

def cmd_headers_sync(args: argparse.Namespace) -> int:
    from .headers import (
        HeaderStore, HeadersError, DEFAULT_PEERS,
        sync_against_peer, sync_with_fallback,
    )

    store = HeaderStore()
    initial_tip = store.tip_height
    _err(f"satsignal: local tip = {initial_tip:,} (genesis appended "
         f"automatically if empty)")

    def on_progress(batches: int, tip: int, elapsed: float) -> None:
        if batches % 20 == 0:
            _err(f"  batch {batches:>3}: tip={tip:>7,}  ({elapsed:.1f}s)")

    def on_reconnect(attempt: int, err: str) -> None:
        _err(f"  reconnect attempt {attempt}: {err}")

    def on_peer_switch(host: str, err: str) -> None:
        _err(f"satsignal: {host} failed ({err}); trying next peer...")

    try:
        if args.peer:
            new_tip = sync_against_peer(
                store, args.peer, args.port,
                on_progress=on_progress, on_reconnect=on_reconnect,
            )
        else:
            new_tip = sync_with_fallback(
                store, peers=DEFAULT_PEERS,
                on_progress=on_progress,
                on_reconnect=on_reconnect,
                on_peer_switch=on_peer_switch,
            )
    except HeadersError as e:
        _err(f"satsignal: headers sync failed: {e}")
        return 3

    added = new_tip - initial_tip if initial_tip >= 0 else new_tip + 1
    stats = store.stats()
    print(f"synced: tip={new_tip:,}  (+{added:,} headers)")
    print(f"  tip hash: {stats.tip_hash_be}")
    print(f"  on disk:  {stats.file_size + stats.chainwork_size:,} bytes "
          f"({(stats.file_size + stats.chainwork_size) / 1024 / 1024:.1f} MB)")
    return 0


def cmd_headers_status(args: argparse.Namespace) -> int:
    from .headers import HeaderStore, CW144_FORK_HEIGHT

    store = HeaderStore()
    stats = store.stats()
    if stats.tip_height < 0:
        if args.json:
            print(json.dumps({"tip_height": -1, "synced": False}))
        else:
            print("(headers store empty — run `satsignal headers sync`)")
        return 0

    cw_at_tip = store.chainwork(stats.tip_height)
    if args.json:
        print(json.dumps({
            "tip_height": stats.tip_height,
            "tip_hash_be": stats.tip_hash_be,
            "headers_bytes": stats.file_size,
            "chainwork_bytes": stats.chainwork_size,
            "cw144_engaged": stats.tip_height >= CW144_FORK_HEIGHT,
            "chainwork_at_tip_hex": hex(cw_at_tip),
        }))
    else:
        print(f"tip_height:    {stats.tip_height:,}")
        print(f"tip_hash (BE): {stats.tip_hash_be}")
        print(f"headers.bin:   {stats.file_size:,} bytes "
              f"({stats.file_size / 1024 / 1024:.1f} MB)")
        print(f"chainwork.bin: {stats.chainwork_size:,} bytes "
              f"({stats.chainwork_size / 1024 / 1024:.1f} MB)")
        print(f"cw-144 fork:   {CW144_FORK_HEIGHT:,} "
              f"({'engaged' if stats.tip_height >= CW144_FORK_HEIGHT else 'pre-fork'})")
    return 0


# ────────────────────────── utilities ──────────────────────────

def _err(msg: str) -> None:
    sys.stderr.write(msg + "\n")
