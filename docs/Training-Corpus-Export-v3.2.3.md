# Arobi Network v3.2.3 Training Corpus Export

Date: 2026-05-14

## Root Cause

Arobi Network `3.2.2` separated public, private, and `00` audit lanes and bound
that policy into the audit hash. It did not yet provide a dedicated export for
feeding Q training or adapter pipelines. Operators could inspect full audit
records, but that made the training boundary too implicit: public, private, and
sealed evidence needed a single governed export path with hard blocking for
`00` evidence.

## Change

Version `3.2.3` adds a training-safe LaaS export:

- `AuditLedger::export_training_corpus(false)` exports public lane entries only.
- `AuditLedger::export_training_corpus(true)` also includes private
  operator-audit entries for internal Q adapters.
- `zero-zero` / `00` entries are never exported, regardless of caller options.
- Public records omit reasoning and only retain allowlisted metadata such as
  `lane`, `source_system`, `route`, `release`, `version`, `policy`, `category`,
  and `environment`.
- Public and private exports strip secret-like metadata keys containing markers
  such as `secret`, `token`, `key`, `password`, `credential`, `classified`,
  `clearance`, `requester`, `wallet`, `private`, or `signature`.
- `GET /api/v1/audit/training-corpus` exposes the export behind the existing
  local-admin or `AROBI_API_TOKEN` gate.
- `GET /api/v1/audit/training-corpus?include_internal=true` enables internal
  private lane export. It is still blocked from public API routing.

## Operator Contract

Use this route as the only LaaS-to-Q training export boundary. Do not train Q
from `/api/v1/audit/entries`, `/api/v1/audit/lane/:lane_id`, tribunal exports,
or forensic exports unless a separate operator has performed an explicit manual
redaction pass.

Keep public and `00` pathways integrated at the schema level through
`AuditLane`, but separated at export time:

| Lane | Training export behavior |
| --- | --- |
| `public` | Included by default, redacted |
| `private` | Included only with `include_internal=true`, secret metadata stripped |
| `zero-zero` | Always blocked |

## Verification

Run from the repository root:

```powershell
cargo fmt --all --check
cargo check --locked
cargo test --locked
cargo clippy --locked -- -D warnings
```

Targeted tests:

- `training_export_never_leaks_zero_zero_and_redacts_public_metadata`
- `admin_signing_route_requires_local_or_token_access`

