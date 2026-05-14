# Arobi Network v3.2.8 Training Corpus Receipt

Date: 2026-05-14

## Root Cause

Arobi Network `3.2.5` added a manifest to the governed LaaS training-corpus
export, and `3.2.7` hardened public vision metadata value sanitization. The
remaining operator gap was a lightweight receipt surface: Q release gates,
operators, and monitoring jobs had to pull the full sanitized record payload to
prove the current export boundary, record count, and sanitized-corpus hash.

That made the public/private/zero-zero lane split correct, but it was heavier
than necessary for continuous audit checks and created avoidable duplicate
payload movement.

## Change

Version `3.2.8` adds a manifest-only receipt route:

```text
GET /api/v1/audit/training-corpus/manifest
GET /api/v1/audit/training-corpus/manifest?include_internal=true
```

The route returns no training records. It returns a receipt with:

- `schema_version`
- `receipt_id`
- `generated_at`
- `include_internal`
- `records_total`
- `records_sha256`
- `boundary_contract`
- `manifest`

The existing `GET /api/v1/audit/training-corpus` response now also includes
the same `receipt` field next to the backward-compatible `manifest` and
`records` fields.

## Lane And Security Contract

- The receipt route is non-public and remains behind local-admin or
  `AROBI_API_TOKEN` access.
- `00`, `zero-zero`, and their aliases remain blocked from every Q training
  export.
- The receipt hashes the sanitized exported records, not raw sealed evidence.
- `boundary_contract` is `manifest-only-no-record-payload` on the manifest
  route so operators can verify they are not moving record payloads.
- No stored audit entry migration is required. Existing hash-bound entries
  remain valid and the new receipt is computed at export time.
- No genesis, `NETWORK_MAGIC`, or network protocol migration is part of this
  release.

## Q Pipeline Use

Q and release gates should poll the receipt route first. A changed
`records_sha256`, `records_total`, `migration_id`, or lane counter indicates a
new sanitized corpus boundary and should trigger a governed corpus pull from
`GET /api/v1/audit/training-corpus`.

## Verification

Run from the repository root:

```powershell
cargo fmt --all --check
cargo check --locked
cargo test --locked
cargo clippy --locked -- -D warnings
```

Targeted regressions:

- `training_corpus_response_includes_manifest_for_q_pipeline_audits`
- `training_corpus_manifest_route_is_admin_only`
