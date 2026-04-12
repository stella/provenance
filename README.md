<p align="center">
  <img src=".github/assets/banner.png" alt="Stella" width="100%" />
</p>

# @stll/provenance

`provenance` is a CLI that generates SBOMs and third-party notices for JavaScript and Rust repositories, and checks that committed outputs stay current.

It is designed to be deterministic, repo-friendly, and boring to operate.

## Scope

The current baseline focuses on:

- JavaScript projects and workspaces
- Rust crates and workspaces
- Mixed JS/Rust repositories
- Optional container image SBOM generation via `syft`

The workflow is file-based:

- one config file
- deterministic generated outputs
- no direct CI pushes to `main`
- repo-friendly `generate`, `check`, and `diff` flows

## Boundaries

- `THIRD-PARTY-NOTICES` is a generated inventory of detected third-party
  components and declared license identifiers. It is not legal advice, and
  some licenses may require additional attribution text at distribution time.
- The safest canonical outputs come from a controlled CI or release environment,
  especially when your dependency graph includes platform-specific packages.
- `output_dir` must point to a dedicated directory such as `provenance`; the
  tool refuses to write managed outputs directly into the repository root.

## Installation

```bash
cargo install --git https://github.com/stella/provenance --locked
```

For local development:

```bash
cargo install --path .
```

## Runtime prerequisites

The CLI itself is a single Rust binary. Analysis still depends on ecosystem tooling:

- `cdxgen` for JavaScript and Rust SBOM generation
  - supported discovery order: `cdxgen`, `bunx @cyclonedx/cdxgen`, `npx --yes @cyclonedx/cdxgen`
- `syft` for optional container SBOMs

You can also point the CLI at explicit binaries:

- `PROVENANCE_CDXGEN=/path/to/cdxgen`
- `PROVENANCE_SYFT=/path/to/syft`

## Quick Start

```bash
provenance init
provenance generate
```

`provenance init` discovers JavaScript and Rust projects under the current root
and writes `.provenance.yml`.

`provenance generate` writes deterministic compliance artifacts into the
configured output directory.

For ongoing verification:

```bash
provenance check
provenance diff
```

## Generated outputs

For a single-project repo:

- `provenance/sbom.cdx.json`
- `provenance/THIRD-PARTY-NOTICES.txt`

For multi-project repos:

- `provenance/projects/<id>/sbom.cdx.json`
- `provenance/projects/<id>/THIRD-PARTY-NOTICES.txt`

For each configured container:

- `provenance/containers/<name>/sbom.cdx.json`
- `provenance/containers/<name>/THIRD-PARTY-NOTICES.txt`

Repo-level outputs:

- `provenance/report.json`

When there is more than one project or any configured containers:

- `provenance/THIRD-PARTY-NOTICES.repo.txt`

## CI model

The recommended flow is:

1. run `provenance generate` when dependency inputs change
2. commit the generated outputs
3. run `provenance check` in CI

This repo follows that model directly in GitHub Actions.

## Development

```bash
cargo fmt -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo test --test integration_real -- --ignored
cargo doc --no-deps
cargo deny check
cargo package --locked
```
