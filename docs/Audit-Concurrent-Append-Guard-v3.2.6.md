# Arobi Network v3.2.6 Concurrent Audit Append Guard

Date: 2026-05-14

## Root Cause

The LaaS audit ledger used independent write locks for `latest_block`,
`latest_hash`, and `entries`. That was safe for ordinary single-threaded append
paths, but concurrent Q, JAWS, or Immaculate ingestion workers could interleave
between those locks. A worker could reserve a block height, another worker could
advance the latest hash, and the final entry order could stop matching the
canonical hash chain.

For accountable AGI work, that is not acceptable. Training export and public
evidence can only be trusted if the decision ledger has one ordered append path.

## Change

`AuditLedger` now has an `append_lock` mutex around `record_decision_with_metadata`
and `rollback_latest`. This keeps block height, previous hash, entry hash, and
entry insertion atomic from the perspective of competing ingestion workers.

The guard does not change stored audit entry shape, consensus identity,
`NETWORK_MAGIC`, or `NETWORK_VERSION`.

## Verification

The regression test `concurrent_record_decision_preserves_hash_chain` starts
multiple workers at the same time, records mixed public/private LaaS audit
events, and verifies:

- total entry count matches all worker appends
- `verify_chain()` remains true
- block heights are strictly ordered
- every entry's `previous_hash` equals the prior entry hash

Run from the repository root:

```powershell
cargo fmt --all --check
cargo check --locked
cargo test --locked
cargo clippy --locked -- -D warnings
```
