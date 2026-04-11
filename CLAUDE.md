# Provenance Development Guidelines

## Purpose

`@stll/provenance` is a Rust CLI for generating deterministic SBOM and
third-party notice artifacts for JavaScript and Rust repositories.

The project should stay:

- deterministic
- local-first
- Git-friendly
- neutral across users and ecosystems

Do not bake Stella-specific defaults into the product surface unless they are
explicitly opt-in configuration.

## Working Rules

- Preserve deterministic output. If an upstream tool emits volatile fields,
  normalize them before writing checked-in artifacts.
- Never let CI push directly to `main`. Generate locally or in a controlled
  CI/release environment, then commit or open a PR.
- Prefer explicit, file-based workflows over hidden state or remote services.
- Treat generated notice files as inventories, not legal guarantees.
- Keep defaults vendor-neutral. Internal package scopes or similar behavior
  must be configurable, not hardcoded.
- Fail fast on invalid config, missing tools, or unsafe paths.
- Do not write managed outputs into the repository root.
- Keep comments concise and focused on why, not what.
- Add or update tests with every behavior change, especially around output
  normalization and external-tool invocation.

## Commands

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
cargo deny check
cargo package --locked
```

## Release Bar

Before a public release:

- README reflects the current feature set and boundaries honestly
- CI passes on `fmt`, `clippy`, `test`, `doc`, `deny`, and `package`
- the crate packages cleanly with `cargo package --locked`
- the history and public metadata contain nothing you would be unhappy to keep
  permanently visible
