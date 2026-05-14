# Arobi Network v3.2.7 Vision Metadata Value Sanitizer

Date: 2026-05-14

## Root Cause

Arobi Network `3.2.6` added a narrow public metadata allowlist for
non-identifying vision telemetry, but that contract only evaluated metadata
keys. An ingest adapter could still put unsafe text inside an allowed key, such
as a face-embedding reference in `vision_task`, a license plate in
`vision_privacy_policy`, a name in `body_language_signal`, or an accusatory
label in `safety_signal`.

That created a boundary gap between LaaS audit collection and Q training export.
The record would still be hash-bound and auditable, but the public training
corpus could inherit identity-bearing or person-risk labels from adapter
mistakes.

## Change

Version `3.2.7` keeps the `3.2.6` allowlist, then validates metadata values
before exporting them for Q training. All training exports now remove
allowlisted values that contain:

- secret, token, password, credential, wallet, signature, or clearance markers;

Public exports additionally remove allowlisted values that contain:

- face, facial-recognition, biometric, embedding-vector, license-plate, plate,
  persistent-subject, subject, person, tracking, or identity markers;
- accusatory person-risk labels such as `bad_actor`, `criminal`, `suspect`,
  `suspicious`, `hostile`, `target`, or `perpetrator` when used in
  `safety_signal`, `body_language_signal`, or `vision_task`.

The policy labels `no_persistent_identity`, `no persistent identity`, and
`non_persistent_identity` remain allowed so adapters can declare the privacy
contract without being blocked by the word `identity`.

## Safety Contract

- This release does not add facial recognition, persistent identity matching,
  targeting, surveillance, or automated criminality classification.
- Public Q training export may include aggregate object/person counts and
  safety-review cues, but not identity-bearing or accusatory person labels.
- `zero-zero` evidence remains blocked from all training exports.
- Private exports still require `include_internal=true` and still strip
  sensitive metadata keys and secret-bearing metadata values.
- No genesis, `NETWORK_MAGIC`, `NETWORK_VERSION`, or stored record format changes
  are part of this release.

## Migration

No stored audit entry migration is required. Existing records remain valid and
hash-verifiable. The new behavior is export-time filtering inside the
training-corpus sanitizer, so existing durable data is read unchanged and unsafe
public metadata values are removed only when a Q training export is built.

## Verification

Run from the repository root:

```powershell
cargo fmt --all --check
cargo check --locked
cargo test --locked
cargo clippy --locked -- -D warnings
```

Targeted regression:

- `public_training_export_removes_identity_and_accusatory_vision_values`
- `internal_training_export_removes_secret_values_from_allowed_keys`
