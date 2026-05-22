# Changelog

## Unreleased

- Release infrastructure: PyPI publishes via Trusted Publishers (OIDC) — workflow file is `.github/workflows/publish.yml`, no API tokens, no `~/.pypirc`. Mirrors the `satsignal-mcp` 0.4.1 pilot; see `RELEASE.md` in `Steleet/satsignal-mcp` and the public "How we publish" section at <https://satsignal.cloud/docs.html#how-we-publish>.
- `satsignal anchor --dry-run` is now an explicit no-op flag (dry-run
  was already the default; this lets scripts pass `--dry-run` for
  symmetry with `--broadcast`). Conflicting `--dry-run --broadcast`
  combinations are rejected with exit 2.
- `satsignal anchor` human-readable output now prints `folder:`
  instead of `matter:` (canonical proof/folder vocabulary). JSON
  output, the `--matter` flag, `SATSIGNAL_MATTER` env, config keys,
  and the `matter_slug` wire token are byte-identical (legacy paths
  are frozen back-compat per the 0.4.0 alias rule).

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
