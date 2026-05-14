# Arobi Network v3.2.4 Audit Lane Legacy Migration

## Purpose

Arobi Network `3.2.4` makes the `3.2.2` lane contract upgrade durable for
older nodes. Versions before lane policy existed stored audit entries without a
`lane` object and chained them with the pre-lane hash algorithm. A node running
the newer verifier must be able to load that data without weakening the
public/private/zero-zero separation.

## What Changed

- `Store::load_audit_entries` now detects stored audit records with no `lane`.
- Missing lanes are derived from `metadata.lane`, `metadata.arobi_lane`,
  `metadata.audit_lane`, `metadata.ability_profile`, `metadata.classification`,
  or `network_context`, using the same normalization as new entries.
- Legacy entries are validated against the pre-lane hash algorithm before they
  are accepted.
- Once validated, the full audit chain is re-chained with the current
  accountability hash contract and written back to the durable `audit_entries`
  sled tree.
- If any legacy record fails its old hash or previous-hash check, migration
  fails closed and the node does not silently accept the history.

## Lane Rules

- `public` stays exportable only through redacted public evidence paths.
- `private` stays internal operator-audit evidence.
- `00`, `zero-zero`, `mission-control-00`, `defense`, and related aliases stay
  sealed and blocked from Q training exports.

## Operator Upgrade Steps

1. Stop the old Arobi node cleanly.
2. Start the `3.2.4` binary against the existing data directory.
3. Confirm the node starts without a durable audit verification error.
4. Run `GET /api/v1/audit/training-corpus` from a local-admin or API-token lane
   and confirm public records export while `zero-zero` records remain excluded.
5. Back up the upgraded data directory after the first clean boot.

## Verification

The regression test `legacy_audit_entries_without_lane_are_migrated_on_load`
builds two pre-lane records, verifies the old hash chain, migrates them, and
rehydrates the ledger with the current verifier. It covers both a public lane
record and a sealed `zero-zero` record.
