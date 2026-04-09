# stella-compliance

`stella-compliance` is an OSS-first compliance CLI for JavaScript and Rust repositories. It discovers projects, generates compliance artifacts, and fails CI when checked-in outputs drift from the current dependency state.

## Scope

The current baseline focuses on:

- JavaScript projects and workspaces
- Rust crates and workspaces
- Mixed JS/Rust repositories
- Optional container image SBOM generation via `syft`

It is designed to stay local-first and Git-native:

- one config file
- deterministic generated outputs
- no direct CI pushes to `main`
- repo-friendly `generate`, `check`, and `diff` flows

## Installation

### Build from source

```bash
cargo install --path .
```

### Runtime prerequisites

The CLI itself is a single Rust binary. Analysis still depends on ecosystem tooling:

- `cdxgen` for JavaScript and Rust SBOM generation
  - supported discovery order: `cdxgen`, `bunx @cyclonedx/cdxgen`, `npx --yes @cyclonedx/cdxgen`
- `syft` for optional container SBOMs

You can also point the CLI at explicit binaries:

- `STELLA_COMPLIANCE_CDXGEN=/path/to/cdxgen`
- `STELLA_COMPLIANCE_SYFT=/path/to/syft`

## Commands

### `init`

Discover JavaScript and Rust projects under the repo root and write `.stella-compliance.yml`.

```bash
stella-compliance init
```

### `generate`

Generate project and container artifacts into the configured output directory.

```bash
stella-compliance generate
```

### `check`

Re-generate outputs in a temp directory and fail if the checked-in files are stale.

```bash
stella-compliance check
```

### `diff`

Show the textual diff between checked-in outputs and freshly generated outputs.

```bash
stella-compliance diff
```

## Example config

```yaml
version: 1
output_dir: compliance
projects:
  - id: root
    path: .
    ecosystems:
      - javascript
      - rust
containers:
  - name: stella-core
    image: ghcr.io/stella/core:latest
```

## Generated outputs

For each project:

- `compliance/projects/<id>/sbom.cdx.json`
- `compliance/projects/<id>/THIRD-PARTY-NOTICES.txt`

For each configured container:

- `compliance/containers/<name>/sbom.cdx.json`
- `compliance/containers/<name>/THIRD-PARTY-NOTICES.txt`

Repo-level outputs:

- `compliance/THIRD-PARTY-NOTICES.repo.txt`
- `compliance/report.json`

## CI model

The recommended flow is:

1. run `stella-compliance generate` when dependency inputs change
2. commit the generated outputs
3. run `stella-compliance check` in CI

This repo follows that model directly in GitHub Actions.

## Development

```bash
cargo fmt -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo doc --no-deps
cargo deny check
```
