"""Regression tests for the 2026-05-22 cold-start LOW findings:

Probe a: `satsignal anchor <file> --dry-run` must be accepted (dry-run
was already the default; the flag is a no-op for explicitness/symmetry
with `--broadcast`). Conflict `--dry-run --broadcast` -> exit 2.

Probe b: human-readable `anchor` output must print `folder:` instead of
`matter:`. JSON output, wire body, env vars, config keys, the
`--matter` flag, and `AnchorResult.matter_slug` field are unchanged
(frozen back-compat per the 0.4.0 alias rule).
"""
import pytest

from satsignal.cli import main


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Strip Satsignal env vars + stub the credentials file so tests
    don't pick up real local config."""
    for k in ("SATSIGNAL_MATTER", "SATSIGNAL_FOLDER", "SATSIGNAL_API_KEY",
              "SATSIGNAL_BASE_URL", "SATSIGNAL_PROOF_URL"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr("satsignal.config._read_credentials_file",
                        lambda: {})


# ───────────────────── Probe a: --dry-run flag ─────────────────────

def test_anchor_dry_run_flag_accepted(monkeypatch, tmp_path, capsys):
    """`anchor <file> --dry-run` must exit 0 (no broadcast attempted)."""
    f = tmp_path / "doc.txt"
    f.write_text("hello")
    # Belt-and-braces: if any test path tried to hit the network, fail
    # loudly rather than silently broadcasting.
    monkeypatch.setattr("satsignal.api.requests.post",
                        lambda *a, **k: pytest.fail("must not POST in dry-run"))
    rc = main(["anchor", str(f), "--dry-run"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "DRY RUN" in out


def test_anchor_dry_run_matches_default(monkeypatch, tmp_path, capsys):
    """`--dry-run` must produce the same output as omitting the flag."""
    f = tmp_path / "doc.txt"
    f.write_text("hello")
    monkeypatch.setattr("satsignal.api.requests.post",
                        lambda *a, **k: pytest.fail("must not POST in dry-run"))

    rc1 = main(["anchor", str(f)])
    out1 = capsys.readouterr().out
    assert rc1 == 0

    rc2 = main(["anchor", str(f), "--dry-run"])
    out2 = capsys.readouterr().out
    assert rc2 == 0
    assert out1 == out2


def test_anchor_dry_run_broadcast_conflict_rejected(
    monkeypatch, tmp_path, capsys,
):
    """`--dry-run --broadcast` must be rejected with exit 2 + stderr."""
    f = tmp_path / "doc.txt"
    f.write_text("hello")
    monkeypatch.setattr("satsignal.api.requests.post",
                        lambda *a, **k: pytest.fail("must not POST on conflict"))
    rc = main(["anchor", str(f), "--dry-run", "--broadcast"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "--dry-run" in err
    assert "--broadcast" in err
    assert "mutually exclusive" in err


def test_anchor_dry_run_strict_conflict_rejected(
    monkeypatch, tmp_path, capsys,
):
    """`--dry-run --strict` must be rejected with exit 2 + stderr.

    Closes V2-L4 (2026-05-22 probe-rerun): previously this combo silently
    exited 0 with the usual dry-run summary, ignoring --strict. Strict
    mode's sidecar-gate cannot fire in dry-run (no sidecar is ever
    written), so the combination is incoherent and must be rejected up
    front rather than silently producing a misleading exit 0.
    """
    f = tmp_path / "doc.txt"
    f.write_text("hello")
    monkeypatch.setattr("satsignal.api.requests.post",
                        lambda *a, **k: pytest.fail("must not POST on conflict"))
    rc = main(["anchor", str(f), "--dry-run", "--strict"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "--dry-run" in err
    assert "--strict" in err
    assert "incompatible" in err


# ───────────────────── Probe b: folder: label ─────────────────────

def test_anchor_human_output_says_folder(monkeypatch, tmp_path, capsys):
    """Dry-run preview must print `folder:` and NOT `matter:`."""
    f = tmp_path / "doc.txt"
    f.write_text("hello")
    rc = main(["anchor", str(f), "--folder", "inbox"])
    assert rc == 0
    out = capsys.readouterr().out
    # Probe b assertion: new canonical label
    assert "folder:" in out
    # And the legacy label must not appear in human-readable output
    # (it would appear in JSON only, which we're not requesting here).
    assert "matter:" not in out
    # Sanity: the value still renders next to the new label.
    assert "inbox" in out


def test_anchor_broadcast_human_output_says_folder(
    monkeypatch, tmp_path, capsys,
):
    """Broadcast success path must also print `folder:`, not `matter:`."""
    f = tmp_path / "doc.txt"
    f.write_text("hello")

    # Stub the network: anchor_standard -> fake AnchorResult; fetch_bundle
    # returns harmless bytes; the log record is captured to keep the test
    # hermetic.
    class _Res:
        bundle_id = "b1"
        proof_id = "b1"
        txid = "deadbeef"
        mode = "standard"
        matter_slug = "inbox"
        folder_slug = "inbox"
        receipt_url = "https://proof/x"
        proof_url = "https://proof/x"
        bundle_url = None  # avoid sidecar write path

    monkeypatch.setattr("satsignal.cli.api.anchor_standard",
                        lambda *a, **k: _Res())
    monkeypatch.setattr("satsignal.cli.log.record_anchor",
                        lambda **k: None)
    # Pretend we have an API key configured.
    monkeypatch.setenv("SATSIGNAL_API_KEY", "test-key")

    rc = main(["anchor", str(f), "--folder", "inbox", "--broadcast"])
    # bundle_url=None means we hit the no-bundle warning; rc may be 0
    # unless --strict was passed. We didn't pass --strict.
    assert rc == 0
    captured = capsys.readouterr()
    out = captured.out
    assert "folder:   inbox" in out
    assert "matter:" not in out


def test_anchor_json_output_unchanged(monkeypatch, tmp_path, capsys):
    """JSON output is frozen: both `folder` and `matter` keys remain
    (legacy + canonical superset per 0.4.0)."""
    import json as _json

    f = tmp_path / "doc.txt"
    f.write_text("hello")
    rc = main(["anchor", str(f), "--folder", "inbox", "--json"])
    assert rc == 0
    out = _json.loads(capsys.readouterr().out)
    # Legacy key preserved byte-identically; new key added alongside.
    assert out["matter"] == "inbox"
    assert out["folder"] == "inbox"
    assert out["dry_run"] is True


def test_anchor_dry_run_with_json_emits_legacy_and_new_keys(
    monkeypatch, tmp_path, capsys,
):
    """`--dry-run --json` (explicit dry-run + JSON) is still valid and
    emits the same payload as the default-dry-run case."""
    import json as _json

    f = tmp_path / "doc.txt"
    f.write_text("hello")
    rc = main(["anchor", str(f), "--folder", "inbox", "--dry-run", "--json"])
    assert rc == 0
    out = _json.loads(capsys.readouterr().out)
    assert out["matter"] == "inbox"
    assert out["folder"] == "inbox"
    assert out["dry_run"] is True
