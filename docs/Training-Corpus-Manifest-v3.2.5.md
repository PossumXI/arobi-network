# Arobi Network v3.2.5 Training Corpus Manifest

Date: 2026-05-14

## Root Cause

Arobi Network `3.2.3` added a governed LaaS export for Q training pipelines,
and `3.2.4` made legacy lane migration durable. The remaining gap was evidence
about the export itself: callers received the sanitized records but did not get
a machine-readable summary proving how many source records were inspected, how
many private records were skipped, how many `00` records were blocked, or how
many tampered records were excluded.

That made the public/private/zero-zero lane split correct in code but weaker as
an auditable training boundary.

## Change

Version `3.2.5` adds an export manifest to the training-corpus response. The
manifest uses `schema_version: 2` because it now carries deterministic per-lane
policy accounting, not just aggregate export counters:

```json
{
  "manifest": {
    "schema_version": 2,
    "migration_id": "arobi-ledger-lane-v0.3-20260514",
    "include_internal": false,
    "source_total": 3,
    "exported_total": 1,
    "public_exported": 1,
    "private_exported": 0,
    "private_skipped": 1,
    "zero_zero_blocked": 1,
    "integrity_failed_blocked": 0,
    "public_reasoning_redacted": 1,
    "metadata_keys_removed": 2,
    "lane_summaries": [
      {
        "lane_id": "public",
        "export_scope": "public-redacted",
        "training_policy": "allowed-redacted",
        "retention_class": "public-evidence",
        "source_total": 1,
        "exported_total": 1,
        "skipped_total": 0,
        "blocked_total": 0,
        "integrity_failed_blocked": 0,
        "public_reasoning_redacted": 1,
        "metadata_keys_removed": 2
      },
      {
        "lane_id": "private",
        "export_scope": "operator-audit",
        "training_policy": "allowed-internal",
        "retention_class": "audit-evidence",
        "source_total": 1,
        "exported_total": 0,
        "skipped_total": 1,
        "blocked_total": 0,
        "integrity_failed_blocked": 0,
        "public_reasoning_redacted": 0,
        "metadata_keys_removed": 0
      },
      {
        "lane_id": "zero-zero",
        "export_scope": "sealed",
        "training_policy": "blocked",
        "retention_class": "sealed-evidence",
        "source_total": 1,
        "exported_total": 0,
        "skipped_total": 0,
        "blocked_total": 1,
        "integrity_failed_blocked": 0,
        "public_reasoning_redacted": 0,
        "metadata_keys_removed": 0
      }
    ]
  },
  "records": [],
  "total": 1,
  "include_internal": false
}
```

The existing `AuditLedger::export_training_corpus(false)` compatibility helper
still returns records only. New Q data-pipeline jobs should use
`AuditLedger::export_training_corpus_with_manifest(...)` or the API response
manifest so every adapter/training corpus can carry its own boundary receipt.
The lane summaries are always emitted in `public`, `private`, `zero-zero`
order so downstream release gates can diff manifests without special sorting.

## Security Contract

- `zero-zero` and `00` aliases remain blocked from all training exports.
- Public reasoning remains redacted.
- Secret-like metadata keys remain removed from public and internal exports.
- Entries that fail `verify()` are counted in `integrity_failed_blocked` and are
  not exported.
- The route stays behind local-admin or `AROBI_API_TOKEN` access and remains
  non-public.
- No genesis, `NETWORK_MAGIC`, or `NETWORK_VERSION` changes are part of this
  release.

## Verification

Run from the repository root:

```powershell
cargo fmt --all --check
cargo check --locked
cargo test --locked
cargo clippy --locked -- -D warnings
```

Targeted tests:

- `training_export_manifest_accounts_for_redaction_and_tamper_blocks`
- `training_corpus_response_includes_manifest_for_q_pipeline_audits`
