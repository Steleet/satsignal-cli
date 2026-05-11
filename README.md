# satsignal-cli

Customer-facing CLI for [Satsignal](https://satsignal.cloud) — anchor and verify files against the BSV-anchored notary.

> **Status: v0.1 draft.** Standard-mode anchor + verify works end-to-end. Sealed mode is `verify`-only (you can verify a sealed bundle produced by the web UI; producing one from the CLI lands in v0.2). Multi-proof (`content_canonical`, `chunk_merkle`) verification falls back to the web verifier at `/verify`.

## Install

```bash
pip install satsignal-cli                # Python 3.11+
pip install 'satsignal-cli[toml-py39]'   # Python 3.9 / 3.10
```

## Quickstart

```bash
satsignal login                       # paste your API key (sk_…)
satsignal anchor report.pdf           # dry-run preview
satsignal anchor report.pdf --broadcast
# → writes report.pdf.mbnt next to the file
satsignal verify report.pdf
# → chain-confirms by default; exit 0 on success
```

## Commands

| verb | purpose |
|---|---|
| `satsignal anchor <file>` | anchor a file; dry-run by default, writes `<file>.mbnt` on `--broadcast` |
| `satsignal verify <file>` | verify a file against its `.mbnt` sidecar; chain-confirms by default |
| `satsignal show <bundle>` | print receipt details (txid, mode, proofs, etc.) |
| `satsignal log` | list recent anchors from `~/.local/state/satsignal/anchors.jsonl` |
| `satsignal login` | store API key in `~/.config/satsignal/credentials.toml` |
| `satsignal matters` | list workspace matters |

## Sidecar convention

`satsignal anchor` writes `<file>.mbnt` next to the source by default. Override with `-o`. `satsignal verify` looks for the sidecar in this order:

1. `<file>.mbnt` directly next to the source
2. `.satsignal/<single-bundle>.mbnt` in the source's parent directory (only if there's exactly one — otherwise pass `--bundle` explicitly)

This convention mirrors GPG's `.asc` / RFC 3161's `.tsr` — one file in, one receipt out, same directory.

## Configuration

Reads (in order, first wins):

1. Environment: `SATSIGNAL_API_KEY`, `SATSIGNAL_BASE_URL`, `SATSIGNAL_MATTER`, `SATSIGNAL_PROOF_URL`
2. `~/.config/satsignal/credentials.toml` (mode 600)
3. Defaults: `base_url = https://app.satsignal.cloud`, `proof_url = https://proof.satsignal.cloud`, `matter = inbox`

The credentials file is plain TOML:

```toml
api_key  = "sk_..."
base_url = "https://app.satsignal.cloud"
matter   = "inbox"
```

## Verify semantics

`satsignal verify` implements the conformant procedure from [bundle-v1.md §7](https://proof.satsignal.cloud/spec-bundle) in order:

1. Open ZIP, parse `manifest.json` / `canonical.json` / `proofs.json` (if present)
2. Cryptographic check (standard: SHA-256; sealed: HMAC-SHA256 with master salt)
3. `doc_hash` consistency via JCS-canonical SHA-256
4. Chain confirmation — fetch raw tx, parse OP_RETURN MBNT payload, compare `doc_hash`

Exit codes match bundle-v1.md §8:

| exit | class | meaning |
|---|---|---|
| 0 | VERIFIED / PENDING / OFFLINE | crypto + chain OK (PENDING = 0 confirmations; OFFLINE = chain skipped) |
| 1 | CRYPTO | bundle malformed or hashes don't match |
| 2 | CHAIN | bundle is valid but the on-chain anchor doesn't commit to this canonical doc |
| 3 | NETWORK | couldn't reach WhatsOnChain / Bitails |
| 4 | (auth) | API key missing or rejected (anchor flow only) |
| 5 | (bundle not found) |
| 6 | VERSION | `mbnt_version` unsupported by this CLI |

`PENDING` returning exit 0 is intentional — `satsignal verify && cp report.pdf out/` should succeed the moment the anchor is broadcast. Opt into stricter gating with `--min-confirmations N`.

## Offline mode

`satsignal verify --offline` skips the chain check. The warning ("locally-fabricated bundles pass crypto-only checks") is non-suppressible — `--quiet` does not silence it. This matches the chain-confirm-by-default rule from the spec; making the chain check opt-in by default would invert the safety property the protocol exists to provide.

## What v0.1 deliberately omits

- **Sealed-mode anchoring.** The CLI can verify sealed bundles, but can't produce them (requires client-side HKDF + HMAC + bundle assembly). Use [sealed.satsignal.cloud](https://sealed.satsignal.cloud) until v0.2.
- **`content_canonical` / `chunk_merkle` verification.** These require porting the verifier.html canonicalizers (text-norm-v1, json-jcs-v1, csv-norm-v1, etc.) to Python. The CLI flags their presence and points to the web verifier for now.
- **Manifest mode (Phase 8b).** Out of scope for v0.1.
- **`--watch` / `--bulk`.** Single-file anchors only.

## See also

- Bundle format spec: <https://proof.satsignal.cloud/spec-bundle>
- LangChain integration: <https://github.com/Steleet/langchain-satsignal>
- API docs: <https://app.satsignal.cloud/docs>
