"""Additive folder/proof vocabulary alias — compat + conflict tests.

Covers, per coordinator policy:
  * legacy `--matter` / `SATSIGNAL_MATTER` / config `matter` / `matter=`
    keep working byte-identically (zero-break)
  * the new `--folder` / `SATSIGNAL_FOLDER` / config `folder` / `folder=`
    surface works
  * conflict rule: both supplied + different => fail loudly
  * WIRE-TOKEN POLICY: the HTTP body still sends `matter_slug`
  * JSON/jsonl output ADDS the new keys without dropping legacy ones
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


def test_config_env_conflict_raises(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("SATSIGNAL_FOLDER", "f1")
    monkeypatch.setenv("SATSIGNAL_MATTER", "m2")
    monkeypatch.setattr("satsignal.config._read_credentials_file",
                        lambda: {})
    with pytest.raises(ValueError):
        Config.load()


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
    # WIRE: frozen legacy key on the wire, no folder_slug emitted.
    assert captured["body"]["matter_slug"] == "legacy"
    assert "folder_slug" not in captured["body"]
    assert res.matter_slug == "legacy"
    assert res.folder_slug == "legacy"  # read alias


def test_anchor_new_kwarg_folds_into_matter_slug_wire(monkeypatch):
    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        captured["body"] = json
        return _Resp({
            "bundle_id": "b1", "txid": "t1", "matter_slug": "newf",
            "receipt_url": "https://proof/x",
        })

    monkeypatch.setattr(api.requests, "post", fake_post)
    cfg = Config(api_key="k", base_url="https://app", proof_url="https://p")
    api.anchor_standard(cfg, sha256_hex="a" * 64, file_size=1,
                        folder="newf")
    assert captured["body"]["matter_slug"] == "newf"
    assert "folder_slug" not in captured["body"]


def test_anchor_conflict_raises(monkeypatch):
    monkeypatch.setattr(api.requests, "post",
                        lambda *a, **k: pytest.fail("must not POST"))
    cfg = Config(api_key="k", base_url="https://app", proof_url="https://p")
    with pytest.raises(ValueError):
        api.anchor_standard(cfg, sha256_hex="a" * 64, file_size=1,
                            folder="f1", matter="m2")


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
    log.record_anchor(sha256_hex="a", txid="t", bundle_id="b", mode="standard",
                       matter="mm", receipt_url="https://r",
                       bundle_url=None, label=None)
    row = json.loads((tmp_path / "anchors.jsonl").read_text().strip())
    # legacy keys preserved byte-identically
    assert row["matter"] == "mm"
    assert row["bundle_id"] == "b"
    assert row["receipt_url"] == "https://r"
    # new aliases added alongside
    assert row["folder"] == "mm"
    assert row["proof_id"] == "b"
    assert row["proof_url"] == "https://r"


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
    # While we're here, confirm the other two env vars stay mentioned —
    # they were already covered by per-flag help text; the epilog should
    # not delete that coverage.
    assert "SATSIGNAL_FOLDER" in out
    assert "SATSIGNAL_MATTER" in out


def test_cli_anchor_conflict_exit2(monkeypatch, tmp_path, capsys):
    f = tmp_path / "doc.txt"
    f.write_text("hello")
    monkeypatch.setattr("satsignal.config._read_credentials_file",
                        lambda: {})
    for k in ("SATSIGNAL_MATTER", "SATSIGNAL_FOLDER"):
        monkeypatch.delenv(k, raising=False)
    rc = main(["anchor", str(f), "--folder", "A", "--matter", "B", "--json"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "aliases" in err


def test_cli_folders_alias_of_matters(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr("satsignal.cli.Config.load",
                        staticmethod(lambda: Config(api_key="k")))
    monkeypatch.setattr("satsignal.api.list_matters",
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
    # legacy-only still writes the frozen `matter` key
    p = cfgmod.write_credentials("sk", matter="legacy")
    assert 'matter = "legacy"' in p.read_text()
