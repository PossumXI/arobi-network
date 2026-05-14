# Arobi Network v3.2.6 Vision-Safe Training Metadata

Date: 2026-05-14

## Root Cause

Arobi Network `3.2.5` made the Q training-corpus export auditable with a
manifest, but the public metadata allowlist still reflected text and route
events only. A vision pipeline could record lawful safety/object telemetry in
the LaaS audit ledger, yet the training export would remove useful
non-identifying fields such as object count, person count, and safety signal.

That made the export safer than necessary but less useful for Q training and
evaluation. The missing contract also left too much room for future adapters to
invent their own handling of face, biometric, plate, or persistent identity
fields.

## Change

Version `3.2.6` adds a narrow public training metadata contract for
non-identifying vision events:

| Key | Purpose |
| --- | --- |
| `modality` | Declares the source as `vision`, `image`, or similar non-secret modality text. |
| `vision_task` | Names the audited task, such as `object_detection` or `safety_event_review`. |
| `object_classes` | Carries broad object categories, not identities. |
| `object_count` | Aggregate object count. |
| `person_count` | Aggregate person count. |
| `safety_signal` | Non-identifying signal such as `possible_fall` or `blocked_exit`. |
| `safety_signal_confidence` | Confidence for the safety signal. |
| `body_language_signal` | Non-identifying posture/motion cue requiring review; not a person-risk label. |
| `vision_privacy_policy` | Explicit policy label, for example `no_persistent_identity`. |

The export still removes sensitive metadata in public and internal modes when a
key contains markers such as `face`, `biometric`, `license_plate`,
`plate_number`, `subject_id`, `subject_name`, `person_name`, `tracking_id`, or
`persistent_subject`.

## Safety Contract

- This release does not add facial recognition, identity matching, tracking,
  targeting, or surveillance implementation.
- Public training export may carry aggregate human/object/safety telemetry, but
  not persistent identity fields.
- `zero-zero` evidence remains blocked from all training exports.
- Public reasoning remains redacted.
- Private exports still require `include_internal=true` and still strip
  sensitive metadata keys.
- No genesis, `NETWORK_MAGIC`, or `NETWORK_VERSION` changes are part of this
  release.

## Migration

No stored audit entry migration is required. Existing records remain valid.
The new behavior applies at export time through the metadata sanitizer.

Adapters that ingest Q vision evidence should record the allowlisted aggregate
fields above and place identity-bearing or biometric data outside the training
export path. If a regulated lawful facial-recognition workflow is ever added,
it must use a separate explicit authorization, retention, and audit contract
instead of this public training metadata lane.

## Verification

Run from the repository root:

```powershell
cargo fmt --all --check
cargo check --locked
cargo test --locked
cargo clippy --locked -- -D warnings
```

Targeted test:

- `public_training_export_keeps_safe_vision_metadata_and_blocks_identity_fields`
