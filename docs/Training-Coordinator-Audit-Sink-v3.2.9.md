# Arobi Network v3.2.9 Training Coordinator Audit Sink

## Purpose

Version `3.2.9` closes the gap where federated training rounds emitted P2P
events but did not also write durable LaaS audit evidence. Training activity is
now visible to Q's internal audit corpus and to operator replay without exposing
sealed `00` evidence or raw gradient payloads.

## What Changed

- Node startup initializes the durable `AuditLedger` before the federated
  training coordinator.
- The training coordinator receives an audit sink backed by the same ledger and
  sled store used by `POST /api/v1/audit/record`.
- Round start, gradient receipt, and round completion events write private-lane
  `training_decision` audit entries.
- Metadata records model id, round id, checkpoint id, worker count, sample count,
  and gradient hash. Raw gradient bytes are not recorded.
- Public Q training exports skip these private records unless
  `include_internal=true`; `zero-zero` export blocking is unchanged.

## Verification

```powershell
cargo test --locked training_round_events_are_durably_audited_for_q_training
cargo fmt --all --check
cargo check --locked
cargo test --locked
cargo clippy --locked -- -D warnings
```

## Operator Notes

This release does not change `NETWORK_MAGIC`, `NETWORK_VERSION`, genesis text,
or stored audit entry schema. It only adds a new producer of private-lane audit
entries using the existing append, rollback, export, and manifest contracts.
