# Arobi Network v3.2.11 Training Legacy Completion Reclassification

## Purpose

Version `3.2.11` completes the v3.2.10 quorum guard by migrating legacy
training evidence at export time for Q data pipelines.

Some v3.2.9 private ledger entries used `event=round_completed` with
`aggregation_metric_status=pending_real_aggregation_metric`. Those entries were
really gradient-quorum evidence, not completed aggregation evidence. Letting Q
train on the old vocabulary would teach a false operational state.

## What Changed

- Verified legacy training-coordinator export records are reclassified from
  `round_completed` to `gradient_quorum_reached`.
- Their exported `aggregation_metric_status` becomes `pending_aggregation`.
- The original values are retained as `legacy_event` and
  `legacy_aggregation_metric_status`.
- The export also adds `q_training_migration` so downstream jobs can identify
  the applied migration.
- Entry id, block height, and entry hash are unchanged in the exported record,
  preserving auditor traceability back to the exact durable ledger entry.

## Migration Boundary

This is not a stored schema migration and does not rewrite sled data, block
history, consensus identity, or entry hashes. The raw historical entry remains
available for audit. The Q training corpus receives the corrected semantic
label.

## Verification

```powershell
cargo test --locked legacy_pending_real_aggregation_metric_is_reclassified_for_q_export
cargo test --locked training_round_events_are_durably_audited_for_q_training
cargo test --locked gradient_quorum_does_not_emit_completion_without_real_aggregation
cargo test --locked completion_requires_real_aggregation_output
cargo fmt --all --check
cargo check --locked
cargo test --locked
cargo clippy --locked -- -D warnings
```
