# Arobi Network v3.2.10 Training Coordinator Quorum Guard

## Purpose

Version `3.2.10` closes an audit-truth gap in the federated training
coordinator. Prior behavior treated gradient quorum as `round_completed`,
broadcast `TrainingRoundComplete`, and wrote a placeholder `aggregated_loss:
0.0` before real aggregation existed.

That was operationally misleading for LaaS and unsafe for Q's internal training
corpus because downstream systems could learn false completion evidence.

## What Changed

- Gradient quorum now emits `GradientQuorumReached`, not `RoundCompleted`.
- The coordinator writes a private-lane `gradient_quorum_reached` audit entry
  with `aggregation_metric_status=pending_aggregation`.
- The coordinator records worker count, required workers, total samples,
  checkpoint input id, and gradient hashes without storing raw gradient payload
  bytes.
- `TrainingRoundComplete` gossip is no longer broadcast from the quorum path.
- `round_completed` audit evidence is reserved for a future real aggregation
  completion path with an actual checkpoint and aggregated loss.

## Data Migration

No stored schema migration is required. Existing v3.2.9 private audit records
remain readable. Operators should treat any historical `round_completed` record
with `aggregation_metric_status=pending_real_aggregation_metric` as a legacy
quorum record, not as proof of aggregation completion.

New records use:

- `event=gradient_quorum_reached`
- `aggregation_metric_status=pending_aggregation`
- `lane=private`
- `source_system=training_coordinator`

## Verification

```powershell
cargo test --locked gradient_quorum_does_not_emit_completion_without_real_aggregation
cargo test --locked training_round_events_are_durably_audited_for_q_training
cargo fmt --all --check
cargo check --locked
cargo test --locked
cargo clippy --locked -- -D warnings
```

## Operator Notes

This release does not change `NETWORK_MAGIC`, `NETWORK_VERSION`, genesis text,
or the audit entry schema. It changes the evidence vocabulary so the network can
separate "ready for aggregation" from "aggregation completed."
