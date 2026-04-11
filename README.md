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

- `PROVENANCE_CDXGEN=/path/to/cdxgen`
- `PROVENANCE_SYFT=/path/to/syft`

## Commands

### `init`

Discover JavaScript and Rust projects under the repo root and write `.provenance.yml`.

```bash
provenance init
```

### `generate`

Generate project and container artifacts into the configured output directory.

```bash
provenance generate
```

### `check`

Re-generate outputs in a temp directory and fail if the checked-in files are stale.

```bash
provenance check
```

### `diff`

Show the textual diff between checked-in outputs and freshly generated outputs.

```bash
provenance diff
```

## Example config

```yaml
version: 1
output_dir: provenance
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

- `provenance/projects/<id>/sbom.cdx.json`
- `provenance/projects/<id>/THIRD-PARTY-NOTICES.txt`

For each configured container:

- `provenance/containers/<name>/sbom.cdx.json`
- `provenance/containers/<name>/THIRD-PARTY-NOTICES.txt`

Repo-level outputs:

- `provenance/THIRD-PARTY-NOTICES.repo.txt`
- `provenance/report.json`

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
cargo doc --no-deps
cargo deny check
cargo package --locked
```
