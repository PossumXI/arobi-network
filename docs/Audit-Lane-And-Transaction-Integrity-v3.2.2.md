# Arobi Network v3.2.2 Audit Lane And Transaction Integrity

Date: 2026-05-14

## Root Cause

Arobi Network already exposed public, private, and `00` concepts at the API layer, but the audit ledger hash did not bind every tribunal/accountability field. An entry could be altered after recording by changing lane-adjacent fields such as `network_context`, metadata, requester, clearance, action, outcome, or latency without breaking `verify()`.

Transaction `data` was also accepted by the signing API and by `Transaction`, but canonical transaction IDs and signatures only covered sender, recipient, amount, fee, nonce, and timestamp. That left data-bearing audit and embedding transactions weaker than value-only transfers.

## Change

Version `3.2.2` hardens two boundaries:

- Audit entries now carry an explicit `AuditLane` policy with `lane_id`, `export_scope`, `training_policy`, `retention_class`, and `migration_id`.
- `AuditEntry::compute_hash()` now binds the full accountable record: input summary/hash, decision, confidence, reasoning, factors, ethics result/details, subsystems, network context, lane policy, requester, clearance, action, outcome, latency, and sorted metadata.
- `AuditLedger::record_decision_with_metadata(...)` lets callers bind metadata at creation time instead of mutating records after hashing.
- `AuditLedger::get_entries_by_lane(...)` gives operators a direct way to inspect public, private, and `00` lanes separately.
- Audit entries are durably appended to the sled `audit_entries` tree before `/api/v1/audit/record` returns success, and startup rehydrates the verifier from that store.
- Transaction IDs and transaction signatures now include a hash of optional `data`, so changing embedded data changes the tx ID and invalidates the signature.
- Transaction validation now verifies that non-genesis transaction IDs match the canonical fields, including `data_hash`.
- `/api/v1/admin/sign` now signs the same data-bound canonical digest used by transaction verification and returns the data-bound tx ID.
- `/api/v1/admin/sign` is no longer a public POST route; it requires local access or the configured API token.
- Node startup now fails closed if durable audit entries cannot verify, instead of serving APIs with a compromised in-memory audit chain.

## Migration Notes

- Deploy `3.2.2` across network nodes as a coordinated integrity release.
- Flush or re-sign any pending mempool transaction that contains `data`. Old data-bearing signatures were not payload-bound.
- Value-only transactions keep the same logical fields and continue to sign with an empty data hash.
- Existing genesis transactions remain valid through their existing genesis bypass path.
- Non-genesis transactions with manually assigned or stale IDs must be rebuilt from the canonical `Transaction::compute_id(...)` path.
- For audit ingestion, prefer `record_decision_with_metadata(...)` when the lane, classification, source system, or training policy is known at ingest time.
- If a node refuses startup because durable audit verification fails, preserve the sled data directory for forensics before attempting repair or replay.
- For Q training exports, use `AuditLane.training_policy` as the policy boundary:
  - `public`: redacted export, redacted training allowed.
  - `private`: internal operator-audit export, internal training allowed.
  - `zero-zero`: sealed export, training blocked.

## Verification

Run the release gate from the repository root:

```powershell
cargo fmt --all --check
cargo check --locked
cargo test --locked
```

Targeted tests added or exercised:

- `audit_hash_binds_lane_and_accountability_fields`
- `audit_entry_verify_detects_tribunal_field_tampering`
- `audit_ledger_verify_chain_detects_stored_entry_metadata_tampering`
- `try_from_entries_rejects_tampered_durable_entries`
- `audit_lanes_keep_public_private_and_zero_zero_policies_separate`
- `audit_entries_survive_store_reopen_and_rehydrate_ledger`
- `admin_signing_route_requires_local_or_token_access`
- `data_payload_is_bound_to_transaction_signature_and_id`
- `node_ops_pool_reward_is_valid_without_private_key_signature`
