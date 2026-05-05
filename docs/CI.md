# CI Operator Notes

The repository root is the Rust crate root for `arobi-network`, so the GitHub
Actions workflow runs cargo commands from the default checkout directory.

The CI gate is intentionally narrow and reproducible:

- `cargo fmt --all --check`
- `cargo check --locked`
- `cargo test --locked`

This catches formatting drift, lockfile/build graph drift, and test regressions
before changes reach `main`. Keep any future deployment or Railway-specific
checks in separate workflows so this fast crate health gate stays easy to debug.
