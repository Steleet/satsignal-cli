# Changelog

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
