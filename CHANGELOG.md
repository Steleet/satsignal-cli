# Changelog

## 0.5.0 — 2026-06-09

Canonical folder/proof vocabulary (decision 0046 vocabulary sunset).
The Satsignal API now emits canonical keys ONLY on 2xx responses
(`proof_id`, `proof_url`, `folder_slug`, …); this release moves the CLI
to send and prefer the canonical vocabulary everywhere.

- **Wire request now sends `folder_slug`** (canonical) instead of the
  legacy `matter_slug` key, and folder listing now calls the canonical
  `GET /api/v1/folders` route (container key `folders`). Requires a
  Satsignal server with the folder/proof vocabulary (any current cloud
  server; self-hosted deployments from the 2026-05 vocabulary-alias
  release onward). Pre-alias self-hosted servers need CLI ≤ 0.4.x.
- **Response reads prefer canonical keys** (`proof_id` / `proof_url` /
  `folder_slug` / `folders`); the legacy-key fallback reads
  (`bundle_id` / `receipt_url` / `matter_slug` / `matters`) are kept so
  alias-window servers that still emit legacy responses keep working.
- **`--folder` is the only documented flag**; `--matter` is now a
  *hidden* alias sharing the same destination. Behavior change: passing
  both no longer exits 2 on conflict — standard last-flag-wins alias
  semantics apply. Same for `satsignal login --matter`.
- **`SATSIGNAL_FOLDER` is read first; `SATSIGNAL_MATTER` is an
  undocumented legacy fallback.** Behavior change: both set with
  different values no longer raises — `SATSIGNAL_FOLDER` simply wins.
  Same precedence for the config-file `folder` / `matter` keys.
- **`satsignal login` now writes the canonical `folder` key** to
  `credentials.toml` (read by CLI ≥ 0.4.0; existing files with `matter`
  keep being read).
- **`satsignal matters` is now a hidden alias** of `satsignal folders`
  (still works; no longer listed in `--help`).
- Human-readable anchor output prints `proof:` instead of `bundle:`.
- CLI JSON / `anchors.jsonl` output keeps emitting BOTH canonical and
  legacy keys (local artifacts, not wire calls) so existing output
  parsers don't break.
- Library surface back-compat: `AnchorResult.bundle_id` /
  `.matter_slug` / `.receipt_url` remain as read-only aliases of the
  canonical fields; `api.list_matters` aliases `api.list_folders`;
  `anchor_standard(matter=…)` / `write_credentials(matter=…)` kwargs
  still accepted (conflict with the canonical kwarg still raises,
  mirroring the server's `conflicting_alias` error). Note:
  `Config(matter=…)` constructor kwarg is gone — the field is now
  `folder` (`.matter` remains as a read-only property).

## 0.4.3 — 2026-05-23

Cluster k + cluster l from the 2026-05-23 LOW sweep.

- **Behavior change: `satsignal anchor --dry-run --strict` is now rejected with exit 2** and a clear error message, instead of silently exiting 0. Dry-run never writes a sidecar, so strict-mode's sidecar-gate cannot fire — silent exit 0 was misleading. Scripts that previously relied on `--dry-run --strict` succeeding silently will now see exit 2; re-run without `--strict` for a preview, or with `--broadcast --strict` to exercise strict-mode end-to-end. Pre-1.0 semver allows behavior changes in patches; flagging here for visibility.
- README "Status" line refreshed (0.4.0 → 0.4.2, and now 0.4.3 with this release).
- Declared `Development Status :: 4 - Beta` PyPI classifier (consistency pass across the Satsignal package family).

## 0.4.2

Two cold-start LOW findings closed (Probes a + b from the 2026-05-21 cold-start review) plus CI release-infra migration. Released 2026-05-22.

- **`satsignal anchor --dry-run` is now an explicit no-op flag.** Dry-run was already the default (broadcast requires `--broadcast`); this lets scripts pass `--dry-run` for symmetry with `--broadcast` and explicitness. Conflicting `--dry-run --broadcast` is rejected with exit 2, mirroring the existing `--folder` / `--matter` 0.4.0 alias-conflict pattern.
- **`satsignal anchor` human-readable output now prints `folder:`** instead of `matter:` (canonical proof/folder vocabulary). JSON output, the `--matter` flag, `SATSIGNAL_MATTER` env, config `matter` key, library `matter_slug=` kwarg, and the `matter_slug` wire token are all byte-identical — legacy paths stay frozen back-compat per the 0.4.0 alias rule.
- **Release infrastructure: PyPI publishes via Trusted Publishers (OIDC).** Workflow file is `.github/workflows/publish.yml`; no API tokens, no `~/.pypirc`. Mirrors the `satsignal-mcp` 0.4.1 pilot; see `RELEASE.md` in `Steleet/satsignal-mcp` and the public "How we publish" section at <https://satsignal.cloud/docs.html#how-we-publish>. This is the first `satsignal-cli` release via the OIDC workflow.

No behavior change for existing scripts. Every existing flag, env var, config key, JSON field, and wire token is byte-identical to 0.4.1.

## 0.4.1

`satsignal anchor --help` now documents `SATSIGNAL_API_KEY`.

A 2026-05-21 cold-start review (six-vector probe, finding 8) flagged
that `--help` documented `SATSIGNAL_FOLDER` and `SATSIGNAL_MATTER` in
flag help text but never mentioned `SATSIGNAL_API_KEY` — the env var
the user most needs before `--broadcast` will work. The runtime error
from `config.require_api_key()` was clear, but a newcomer reading
`--help` first wouldn't discover the env-var path until they tried to
broadcast and failed.

- Added an `epilog` to the `anchor` sub-parser enumerating
  `SATSIGNAL_API_KEY`, `SATSIGNAL_FOLDER`, and `SATSIGNAL_MATTER` with
  one-line descriptions and the key-creation pointer.
- New test `test_anchor_help_mentions_api_key` regression-pins the
  discoverability fix.
- No behavior change. `require_api_key()`, the runtime error message,
  and every existing flag are byte-identical.

## 0.4.0

Additive proof/folder vocabulary aliases — fully backward-compatible.

- New `--folder` option, `SATSIGNAL_FOLDER` env, config-file `folder`
  key, and `folder=` / `folder_slug=` library kwargs, alongside the
  frozen legacy `--matter` / `SATSIGNAL_MATTER` / `matter` config key
  / `matter_slug=`.
- New read-only `satsignal folders` listing verb (alias of
  `satsignal matters`); the legacy verb is unchanged.
- `--json` / `anchors.jsonl` output now includes `folder` / `proof` /
  `proof_id` **alongside** the legacy `matter` / `bundle_id` fields
  (additive superset; legacy keys retained).
- Conflict rule: the new and legacy spellings with different non-empty
  values are rejected (CLI exit 2 / `ValueError`) before any network
  call (mirrors the server's `conflicting_alias`); equal accepted.
- The HTTP request body still sends the frozen `matter_slug` wire
  token, so this works unchanged against every Satsignal server
  (including older / self-hosted deployments).
- `login` still writes the legacy `matter` config key; `__version__`
  and `User-Agent` track the package version automatically.

Every existing `--matter` / `SATSIGNAL_MATTER` / config / kwarg usage
keeps working byte-identically.

## 0.3.2 and earlier

See the git history.
