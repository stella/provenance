# Changelog

## Unreleased

### Patch

- Make the JavaScript SBOM list exactly the production-dependency closure resolved from the manifest and lockfile.
- License the CLI and distributed archives under Apache-2.0 and update the crate license metadata.
- Require Rust 1.100 or newer to build from source (`rust-version` 1.89 to 1.100).
- Reject unused Cargo dependencies at build time with Cargo's `unused_dependencies` lint.
