# LaaS Audit Lane Contract

Version: Arobi Network `3.2.6`

Migration ID: `arobi-ledger-lane-v0.3-20260514`

## Purpose

LaaS audit records now carry an explicit lane contract so public, private, and
zero-zero evidence can share one ledger format without sharing the same export
or training policy.

## Lanes

| Lane | Export scope | Training policy | Retention class |
| --- | --- | --- | --- |
| `public` | `public-redacted` | `allowed-redacted` | `public-evidence` |
| `private` | `operator-audit` | `allowed-internal` | `audit-evidence` |
| `zero-zero` | `sealed` | `blocked` | `sealed-evidence` |

`00`, `zero-zero`, `private-00`, `mission-control`, `mission-control-00`,
`sealed`, `defense`, `defense-grade`, and any lane ending in `-00` normalize
to `zero-zero`.

## API Contract

`POST /api/v1/audit/record` accepts optional fields:

```json
{
  "lane": "public",
  "metadata": {
    "case_id": "example",
    "source_route": "qline-status"
  }
}
```

If `lane` is omitted, Arobi derives the lane from `metadata.lane`,
`metadata.arobi_lane`, `metadata.audit_lane`, `metadata.ability_profile`,
`metadata.classification`, or finally `network_context`.

`GET /api/v1/audit/lane/:lane_id` returns entries for a normalized lane. This is
not a public API path; it remains behind the existing local-admin or API-token
gate.

`GET /api/v1/audit/training-corpus` returns a Q-training-safe corpus with
public lane entries only. Public entries keep lane, model, decision, confidence,
factor, subsystem, integrity, latency, and allowlisted metadata fields, but omit
requester/clearance/action/outcome/signature/raw input fields and reasoning.
The public metadata allowlist includes non-identifying vision/safety telemetry
such as `modality`, `vision_task`, `object_classes`, `object_count`,
`person_count`, `safety_signal`, `safety_signal_confidence`,
`body_language_signal`, and `vision_privacy_policy`.
The response includes a `manifest` block with source count, exported count,
public/private export counts, skipped private count, blocked `zero-zero` count,
integrity-failed block count, public reasoning redaction count, and removed
metadata-key count so Q data-pipeline jobs can prove the export boundary. The
manifest also includes `migration_id` and deterministic `lane_summaries` for
`public`, `private`, and `zero-zero`, allowing downstream jobs to verify lane
policy without inspecting any sealed record content.

`GET /api/v1/audit/training-corpus?include_internal=true` also includes private
operator-audit entries for internal Q adapters. It still strips secret-like
metadata keys. `zero-zero` entries are blocked from this export in all modes.
This route is not a public API path; it remains behind local-admin or API-token
access.

`POST /api/v1/admin/sign` is also behind the local-admin or API-token gate. It
must not be exposed as a public route because it signs canonical ledger payloads.

## Integrity

Audit verification now binds all material accountability fields into the entry
hash: input summary, factors, ethics fields, subsystem list, network context,
lane policy, requester/clearance, action/outcome, latency, and sorted metadata.
Changing any of these fields after recording invalidates `verify()` and the
ledger chain verification.

## Durability

`POST /api/v1/audit/record` now appends each audit entry to the sled
`audit_entries` tree before returning success. Node startup reloads that tree
into the in-process verifier, preserving audit count, block height, tip hash,
lane policy, and chain verification across restarts.

During the `3.2.4` upgrade, entries written before lane policy existed are
validated against the pre-lane hash contract, assigned the derived lane,
re-chained under the current hash contract, and written back to the durable
`audit_entries` tree. If a legacy entry fails its old hash or previous-hash
check, startup fails closed instead of silently accepting a corrupted audit
history.

The `3.2.5` and `3.2.6` upgrades do not change stored audit entry shape or
consensus identity. Existing durable entries are read as-is, and the
training-corpus manifest plus vision-safe metadata contract are derived at
export time from verified entries.

If the durable append fails, the API rolls back the in-memory latest entry and
returns a 5xx instead of reporting an audit receipt that only exists in RAM.

As of `3.2.6`, audit appends are serialized across block-height allocation,
previous-hash selection, latest-hash advancement, and entry insertion. This
prevents concurrent LaaS audit writes from producing duplicate previous hashes
or out-of-order in-memory chains under load.

## Operator Rule

Do not change `NETWORK_MAGIC`, `NETWORK_VERSION`, or genesis block text for this
migration. Those are consensus and history surfaces. This release changes the
audit evidence contract, not the chain identity.

