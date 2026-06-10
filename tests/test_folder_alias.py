"""Canonical folder/proof vocabulary (decision 0046) — compat tests.

Covers:
  * canonical `--folder` / `SATSIGNAL_FOLDER` / config `folder` /
    `folder=` are primary
  * legacy `--matter` (hidden alias, same dest) / `SATSIGNAL_MATTER`
    (fallback) / config `matter` (fallback) / `matter=` kwarg keep
    working
  * library-kwarg conflict rule: both supplied + different => raise
    (mirrors the server's `conflicting_alias`); CLI flags and env use
    simple precedence instead
  * WIRE-TOKEN POLICY: the HTTP body sends canonical `folder_slug`
  * response reads prefer canonical keys, legacy fallback kept for
    alias-window servers
  * JSON/jsonl output emits canonical AND legacy keys
"""
import json

import pytest

from satsignal import api, log
from satsignal.cli import main
from satsignal.config import Config, resolve_folder_alias


# ───────────────────── resolve_folder_alias core ─────────────────────

def test_resolve_neither():
    assert resolve_folder_alias(None, None) is None
    assert resolve_folder_alias("", "") is None


def test_resolve_legacy_only_unchanged():
    # An unchanged caller passing only the legacy value sees it returned
    # verbatim — no behavior change.
    assert resolve_folder_alias(None, "smith-v-jones") == "smith-v-jones"
    assert resolve_folder_alias("", "smith-v-jones") == "smith-v-jones"


def test_resolve_new_only():
    assert resolve_folder_alias("inbox", None) == "inbox"
    assert resolve_folder_alias("inbox", "") == "inbox"


def test_resolve_both_equal_ok():
    assert resolve_folder_alias("inbox", "inbox") == "inbox"


def test_resolve_both_differ_raises():
    with pytest.raises(ValueError) as ei:
        resolve_folder_alias("folderA", "matterB")
    msg = str(ei.value)
    assert "aliases" in msg and "must not be set to different" in msg
    assert "use folder" in msg


def test_resolve_precedence_prefers_new():
    # Equal -> value; the new name is the documented preference.
    assert resolve_folder_alias("x", "x") == "x"
    assert resolve_folder_alias("only-new", None) == "only-new"


# ───────────────────── Config.load env/file ─────────────────────

def _clear_env(monkeypatch):
    for k in ("SATSIGNAL_MATTER", "SATSIGNAL_FOLDER", "SATSIGNAL_API_KEY",
              "SATSIGNAL_BASE_URL", "SATSIGNAL_PROOF_URL"):
        monkeypatch.delenv(k, raising=False)


def test_config_legacy_env_unchanged(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setattr(Config, "_read_credentials_file",
                        staticmethod(lambda: {}), raising=False)
    monkeypatch.setenv("SATSIGNAL_MATTER", "legacy-matter")
    monkeypatch.setattr("satsignal.config._read_credentials_file",
                        lambda: {})
    cfg = Config.load()
    assert cfg.matter == "legacy-matter"
    assert cfg.folder == "legacy-matter"  # new read accessor mirrors it


def test_config_new_env(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("SATSIGNAL_FOLDER", "new-folder")
    monkeypatch.setattr("satsignal.config._read_credentials_file",
                        lambda: {})
    cfg = Config.load()
    assert cfg.matter == "new-folder"


def test_config_env_folder_wins_over_legacy_matter(monkeypatch):
    # 0.5.0: SATSIGNAL_FOLDER is read first; SATSIGNAL_MATTER is the
    # legacy fallback. Both set -> canonical wins (no conflict error).
    _clear_env(monkeypatch)
    monkeypatch.setenv("SATSIGNAL_FOLDER", "f1")
    monkeypatch.setenv("SATSIGNAL_MATTER", "m2")
    monkeypatch.setattr("satsignal.config._read_credentials_file",
                        lambda: {})
    assert Config.load().folder == "f1"


def test_config_file_legacy_matter_key(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setattr("satsignal.config._read_credentials_file",
                        lambda: {"matter": "from-file"})
    assert Config.load().matter == "from-file"


def test_config_file_new_folder_key(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setattr("satsignal.config._read_credentials_file",
                        lambda: {"folder": "from-file-folder"})
    assert Config.load().matter == "from-file-folder"


def test_config_env_folder_and_file_matter_no_false_conflict(monkeypatch):
    # env-source and file-source resolved independently, then env wins —
    # an env `folder` plus a file `matter` must NOT be a conflict.
    _clear_env(monkeypatch)
    monkeypatch.setenv("SATSIGNAL_FOLDER", "envf")
    monkeypatch.setattr("satsignal.config._read_credentials_file",
                        lambda: {"matter": "filem"})
    assert Config.load().matter == "envf"


def test_config_default_unchanged(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setattr("satsignal.config._read_credentials_file",
                        lambda: {})
    assert Config.load().matter == "inbox"


# ───────────────────── api.anchor_standard wire body ─────────────────────

class _Resp:
    status_code = 200

    def __init__(self, payload):
        self._p = payload

    def json(self):
        return self._p


def test_anchor_legacy_kwarg_wire_body(monkeypatch):
    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        captured["body"] = json
        return _Resp({
            "bundle_id": "b1", "txid": "t1", "matter_slug": "legacy",
            "receipt_url": "https://proof/x",
        })

    monkeypatch.setattr(api.requests, "post", fake_post)
    cfg = Config(api_key="k", base_url="https://app", proof_url="https://p")
    res = api.anchor_standard(cfg, sha256_hex="a" * 64, file_size=1,
                              matter="legacy")
    # WIRE: canonical key on the wire (0.5.0), even from the legacy
    # `matter=` kwarg; the legacy wire key is no longer emitted.
    assert captured["body"]["folder_slug"] == "legacy"
    assert "matter_slug" not in captured["body"]
    assert res.folder_slug == "legacy"
    assert res.matter_slug == "legacy"  # legacy read alias


def test_anchor_canonical_kwarg_sends_folder_slug_wire(monkeypatch):
    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        captured["body"] = json
        # Legacy-only response body (alias-window server) — the
        # fallback read must still work.
        return _Resp({
            "bundle_id": "b1", "txid": "t1", "matter_slug": "newf",
            "receipt_url": "https://proof/x",
        })

    monkeypatch.setattr(api.requests, "post", fake_post)
    cfg = Config(api_key="k", base_url="https://app", proof_url="https://p")
    res = api.anchor_standard(cfg, sha256_hex="a" * 64, file_size=1,
                              folder="newf")
    assert captured["body"]["folder_slug"] == "newf"
    assert "matter_slug" not in captured["body"]
    assert res.proof_id == "b1"          # legacy response keys read OK
    assert res.proof_url == "https://proof/x"


def test_anchor_conflict_raises(monkeypatch):
    monkeypatch.setattr(api.requests, "post",
                        lambda *a, **k: pytest.fail("must not POST"))
    cfg = Config(api_key="k", base_url="https://app", proof_url="https://p")
    with pytest.raises(ValueError):
        api.anchor_standard(cfg, sha256_hex="a" * 64, file_size=1,
                            folder="f1", matter="m2")


def test_anchor_reads_canonical_only_response(monkeypatch):
    # Current servers emit canonical keys ONLY on 2xx — no legacy keys
    # present at all. Must parse without KeyError.
    def fake_post(url, json=None, headers=None, timeout=None):
        return _Resp({
            "proof_id": "p1", "txid": "t1", "folder_slug": "ff",
            "proof_url": "https://proof/new",
        })

    monkeypatch.setattr(api.requests, "post", fake_post)
    cfg = Config(api_key="k", base_url="https://app", proof_url="https://p")
    res = api.anchor_standard(cfg, sha256_hex="a" * 64, file_size=1,
                              folder="ff")
    assert res.proof_id == "p1"
    assert res.folder_slug == "ff"
    assert res.proof_url == "https://proof/new"
    # legacy read aliases mirror the canonical fields
    assert res.bundle_id == "p1"
    assert res.matter_slug == "ff"
    assert res.receipt_url == "https://proof/new"


def test_anchor_reads_new_response_key_with_legacy_fallback(monkeypatch):
    # Server that emits the new keys -> we prefer them.
    def fake_post(url, json=None, headers=None, timeout=None):
        return _Resp({
            "proof_id": "p1", "txid": "t1", "folder_slug": "ff",
            "proof_url": "https://proof/new", "bundle_id": "OLD",
            "matter_slug": "OLDM", "receipt_url": "https://OLD",
        })

    monkeypatch.setattr(api.requests, "post", fake_post)
    cfg = Config(api_key="k", base_url="https://app", proof_url="https://p")
    res = api.anchor_standard(cfg, sha256_hex="a" * 64, file_size=1,
                              folder="ff")
    assert res.matter_slug == "ff"
    assert res.receipt_url == "https://proof/new"
    assert res.bundle_id == "p1"


# ───────────────────── log jsonl artifact additive ─────────────────────

def test_log_row_has_both_keys(monkeypatch, tmp_path):
    monkeypatch.setattr(log, "STATE_DIR", tmp_path)
    monkeypatch.setattr(log, "LOG_PATH", tmp_path / "anchors.jsonl")
    log.record_anchor(sha256_hex="a", txid="t", proof_id="b",
                      mode="standard", folder="mm", proof_url="https://r",
                      bundle_url=None, label=None)
    row = json.loads((tmp_path / "anchors.jsonl").read_text().strip())
    # canonical keys primary
    assert row["folder"] == "mm"
    assert row["proof_id"] == "b"
    assert row["proof_url"] == "https://r"
    # legacy keys still written alongside for existing consumers
    assert row["matter"] == "mm"
    assert row["bundle_id"] == "b"
    assert row["receipt_url"] == "https://r"


# ───────────────────── CLI dry-run JSON additive ─────────────────────

def test_cli_anchor_dryrun_legacy_matter(monkeypatch, tmp_path, capsys):
    f = tmp_path / "doc.txt"
    f.write_text("hello")
    monkeypatch.setattr("satsignal.config._read_credentials_file",
                        lambda: {})
    for k in ("SATSIGNAL_MATTER", "SATSIGNAL_FOLDER"):
        monkeypatch.delenv(k, raising=False)
    rc = main(["anchor", str(f), "--matter", "casework", "--json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["matter"] == "casework"   # legacy preserved
    assert out["folder"] == "casework"   # new alias added
    assert out["dry_run"] is True


def test_cli_anchor_dryrun_new_folder(monkeypatch, tmp_path, capsys):
    f = tmp_path / "doc.txt"
    f.write_text("hello")
    monkeypatch.setattr("satsignal.config._read_credentials_file",
                        lambda: {})
    for k in ("SATSIGNAL_MATTER", "SATSIGNAL_FOLDER"):
        monkeypatch.delenv(k, raising=False)
    rc = main(["anchor", str(f), "--folder", "casework", "--json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["folder"] == "casework"
    assert out["matter"] == "casework"


def test_anchor_help_mentions_api_key(capsys):
    """Regression for finding F8 (2026-05-21 cold-start probe): the
    anchor sub-parser's --help must surface SATSIGNAL_API_KEY so a
    newcomer doesn't only discover it via a failed --broadcast.
    """
    import pytest

    from satsignal.cli import _build_parser

    parser = _build_parser()
    # Trigger the anchor sub-parser's help; argparse exits 0 on --help.
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["anchor", "--help"])
    assert exc_info.value.code == 0

    out = capsys.readouterr().out
    assert "SATSIGNAL_API_KEY" in out, (
        "anchor --help must name SATSIGNAL_API_KEY (finding F8)"
    )
    # The canonical env var stays documented; legacy SATSIGNAL_MATTER
    # is intentionally absent from help since 0.5.0 (hidden fallback).
    assert "SATSIGNAL_FOLDER" in out
    assert "SATSIGNAL_MATTER" not in out


def test_cli_matter_is_hidden_alias_same_dest(monkeypatch, tmp_path, capsys):
    # 0.5.0: --matter shares --folder's dest; standard argparse
    # last-flag-wins semantics replace the old exit-2 conflict rule.
    f = tmp_path / "doc.txt"
    f.write_text("hello")
    monkeypatch.setattr("satsignal.config._read_credentials_file",
                        lambda: {})
    for k in ("SATSIGNAL_MATTER", "SATSIGNAL_FOLDER"):
        monkeypatch.delenv(k, raising=False)
    rc = main(["anchor", str(f), "--folder", "A", "--matter", "B", "--json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["folder"] == "B"  # last flag wins
    rc = main(["anchor", str(f), "--matter", "B", "--folder", "A", "--json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["folder"] == "A"


def test_cli_matter_flag_hidden_from_help(capsys):
    from satsignal.cli import _build_parser

    with pytest.raises(SystemExit) as ei:
        _build_parser().parse_args(["anchor", "--help"])
    assert ei.value.code == 0
    out = capsys.readouterr().out
    assert "--folder" in out
    assert "--matter" not in out


def test_cli_folders_alias_of_matters(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr("satsignal.cli.Config.load",
                        staticmethod(lambda: Config(api_key="k")))
    monkeypatch.setattr("satsignal.api.list_folders",
                        lambda cfg: calls.append(1) or [])
    rc_old = main(["matters"])
    rc_new = main(["folders"])
    assert rc_old == 0 and rc_new == 0
    assert len(calls) == 2  # both verbs hit the same code path


def test_write_credentials_conflict(tmp_path, monkeypatch):
    import satsignal.config as cfgmod
    monkeypatch.setattr(cfgmod, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(cfgmod, "CREDENTIALS_PATH",
                        tmp_path / "credentials.toml")
    with pytest.raises(ValueError):
        cfgmod.write_credentials("sk", matter="m", folder="f")
    # 0.5.0: the canonical `folder` key is written, even from the
    # legacy `matter=` kwarg (CLI >= 0.4.0 reads it).
    p = cfgmod.write_credentials("sk", matter="legacy")
    assert 'folder = "legacy"' in p.read_text()
    assert 'matter =' not in p.read_text()
