# Arobi Network v3.2.6 Atomic Audit Append

Date: 2026-05-14

## Root Cause

The LaaS audit ledger already separated public, private, and zero-zero lanes, but
`AuditLedger::record_decision_with_metadata` assigned block height, read the
previous hash, updated the latest hash, and pushed the entry through separate
locks. Under concurrent `POST /api/v1/audit/record` calls, two entries could
observe an inconsistent tip and produce a broken in-memory hash chain.

That is especially dangerous for accountability infrastructure: the next node
restart would fail closed when durable audit entries are rehydrated, even though
each individual write looked successful at request time.

## Change

Version `3.2.6` serializes audit appends with an internal append lock. The lock
covers the whole append critical section:

1. allocate the next block height;
2. read the current previous hash;
3. construct the hash-bound entry;
4. advance the latest hash;
5. push the entry into the in-memory chain.

`rollback_latest` uses the same append lock so failed durable appends cannot race
with a new successful append.

## Safety Contract

- This does not change genesis, `NETWORK_MAGIC`, or `NETWORK_VERSION`.
- This does not change stored audit entry shape.
- Public/private/zero-zero lane policy remains unchanged.
- Existing durable data is still read and migrated through the v3.2.4/v3.2.5
  lane contract.
- The fix only makes concurrent live audit ingestion preserve one canonical
  chain order.

## Verification

Run from the repository root:

```powershell
cargo fmt --all --check
cargo check --locked
cargo test --locked
cargo clippy --locked -- -D warnings
```

Targeted regression:

- `concurrent_record_decision_preserves_hash_chain`
