use std::{
    fs,
    path::{Path, PathBuf},
    process::Command as StdCommand,
};

use assert_cmd::Command;
use assert_fs::TempDir;
use serde_json::Value;

fn cargo_bin() -> Command {
    Command::cargo_bin("provenance").unwrap()
}

fn write_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, contents).unwrap();
}

fn resolve_real_cdxgen(dir: &Path) -> PathBuf {
    if let Ok(path) = which::which("cdxgen") {
        return path;
    }

    let bunx =
        which::which("bunx").expect("either cdxgen or bunx is required for the real cdxgen test");
    let path = dir.join("cdxgen-real.sh");
    let script = format!(
        "#!/bin/sh\nset -eu\nexec \"{}\" @cyclonedx/cdxgen \"$@\"\n",
        bunx.display()
    );
    fs::write(&path, script).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).unwrap();
    }

    path
}

fn write_rust_fixture(root: &Path) {
    write_file(
        &root.join("Cargo.toml"),
        r#"[package]
name = "fixture"
version = "0.1.0"
edition = "2024"

[dependencies]
cfg-if = "1.0"
"#,
    );
    write_file(
        &root.join("src/lib.rs"),
        "pub fn fixture() -> bool { true }\n",
    );

    let status = StdCommand::new("cargo")
        .arg("generate-lockfile")
        .current_dir(root)
        .status()
        .unwrap();
    assert!(status.success());
}

fn write_js_fixture(root: &Path) {
    // A workspace member with two production dependencies:
    //   - `picocolors` is imported from production source, so cdxgen records a
    //     usage occurrence and marks it `required`. Its presence is what pushes
    //     cdxgen into usage-based scoping for the workspace.
    //   - `debug` (which pulls the transitive runtime dependency `ms`) is a
    //     production dependency referenced only from a type-declaration file and
    //     a test file. With a `required` sibling present, cdxgen marks `debug`
    //     and `ms` `optional`, so the historic `--required-only` invocation
    //     dropped them from the SBOM even though they ship.
    // `left-pad` is a development-only dependency and must never be reported.
    write_file(
        &root.join("package.json"),
        r#"{ "name": "fixture-root", "private": true, "workspaces": ["packages/*"] }
"#,
    );
    write_file(
        &root.join("packages/app/package.json"),
        r#"{
  "name": "@fixture/app",
  "version": "0.0.0",
  "dependencies": {
    "picocolors": "1.0.0",
    "debug": "4.3.4"
  },
  "devDependencies": {
    "left-pad": "1.3.0"
  }
}
"#,
    );
    write_file(
        &root.join("bunfig.toml"),
        "[install]\nlinker = \"hoisted\"\n",
    );
    write_file(
        &root.join("packages/app/src/index.ts"),
        "import pc from \"picocolors\";\nexport const c = pc;\n",
    );
    write_file(
        &root.join("packages/app/src/types.d.ts"),
        "import type { Debugger } from \"debug\";\nexport type T = Debugger;\n",
    );
    write_file(
        &root.join("packages/app/src/app.test.ts"),
        "import createDebug from \"debug\";\nexport const d = createDebug;\n",
    );

    // The tool runs cdxgen with --no-install-deps, so the production closure must
    // already be materialized in node_modules. Installing production-only keeps
    // development dependencies out of the generated SBOM.
    let status = StdCommand::new("bun")
        .arg("install")
        .arg("--production")
        .arg("--ignore-scripts")
        .current_dir(root)
        .status()
        .expect("bun is required for the real JavaScript cdxgen test");
    assert!(status.success());
}

fn parse_json(path: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn component_names(sbom: &Value) -> Vec<String> {
    sbom["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|component| component["name"].as_str().map(ToString::to_string))
        .collect()
}

#[test]
#[ignore = "requires cdxgen or bunx and network access for a real cdxgen invocation"]
fn generate_with_real_cdxgen_for_rust_project() {
    let temp = TempDir::new().unwrap();
    let helpers = TempDir::new().unwrap();
    write_rust_fixture(temp.path());
    write_file(
        &temp.path().join(".provenance.yml"),
        r"version: 1
output_dir: provenance
projects:
  - id: root
    path: .
    ecosystems:
      - rust
",
    );

    let cdxgen = resolve_real_cdxgen(helpers.path());

    cargo_bin()
        .current_dir(temp.path())
        .env("PROVENANCE_CDXGEN", &cdxgen)
        .arg("generate")
        .assert()
        .success();

    let sbom_path = temp.path().join("provenance/sbom.cdx.json");
    let sbom = parse_json(&sbom_path);
    assert_eq!(sbom["bomFormat"], "CycloneDX");
    assert!(sbom.get("serialNumber").is_none());
    assert!(sbom["metadata"].get("timestamp").is_none());
    assert!(
        sbom["components"]
            .as_array()
            .unwrap()
            .iter()
            .any(|component| { component["name"].as_str() == Some("cfg-if") })
    );

    let notice =
        fs::read_to_string(temp.path().join("provenance/THIRD-PARTY-NOTICES.txt")).unwrap();
    assert!(notice.contains("cfg-if"));

    cargo_bin()
        .current_dir(temp.path())
        .env("PROVENANCE_CDXGEN", &cdxgen)
        .arg("check")
        .assert()
        .success();
}

#[test]
#[ignore = "requires cdxgen or bunx, syft, and network access for real tool invocations"]
fn generate_with_real_cdxgen_and_syft() {
    let temp = TempDir::new().unwrap();
    let helpers = TempDir::new().unwrap();
    write_rust_fixture(temp.path());
    write_file(
        &temp.path().join(".provenance.yml"),
        &format!(
            "version: 1\noutput_dir: provenance\nprojects:\n  - id: root\n    path: .\n    ecosystems:\n      - rust\ncontainers:\n  - name: filesystem\n    image: {}\n",
            temp.path().display()
        ),
    );

    let cdxgen = resolve_real_cdxgen(helpers.path());
    let syft = which::which("syft").expect("syft is required for the real syft integration test");

    cargo_bin()
        .current_dir(temp.path())
        .env("PROVENANCE_CDXGEN", &cdxgen)
        .env("PROVENANCE_SYFT", &syft)
        .arg("generate")
        .assert()
        .success();

    let container_sbom_path = temp
        .path()
        .join("provenance/containers/filesystem/sbom.cdx.json");
    let container_sbom = parse_json(&container_sbom_path);
    assert_eq!(container_sbom["bomFormat"], "CycloneDX");
    assert!(
        container_sbom["components"]
            .as_array()
            .is_some_and(|components| !components.is_empty())
    );

    let repo_notice =
        fs::read_to_string(temp.path().join("provenance/THIRD-PARTY-NOTICES.repo.txt")).unwrap();
    assert!(repo_notice.contains("Container: filesystem"));

    cargo_bin()
        .current_dir(temp.path())
        .env("PROVENANCE_CDXGEN", &cdxgen)
        .env("PROVENANCE_SYFT", &syft)
        .arg("check")
        .assert()
        .success();
}

#[test]
#[ignore = "requires bun, cdxgen or bunx, and network access for a real cdxgen invocation"]
fn generate_includes_shipped_js_dependencies_without_production_source_imports() {
    let temp = TempDir::new().unwrap();
    let helpers = TempDir::new().unwrap();
    write_js_fixture(temp.path());
    write_file(
        &temp.path().join(".provenance.yml"),
        r"version: 1
output_dir: provenance
projects:
  - id: root
    path: .
    ecosystems:
      - javascript
",
    );

    let cdxgen = resolve_real_cdxgen(helpers.path());

    cargo_bin()
        .current_dir(temp.path())
        .env("PROVENANCE_CDXGEN", &cdxgen)
        .arg("generate")
        .assert()
        .success();

    let sbom = parse_json(&temp.path().join("provenance/sbom.cdx.json"));
    let names = component_names(&sbom);

    // Baseline: a production dependency imported from source is always present.
    assert!(
        names.iter().any(|name| name == "picocolors"),
        "expected source-imported dependency 'picocolors' in SBOM, got: {names:?}"
    );

    // `debug` is a production dependency imported only from a `.d.ts` and a
    // `.test.ts`; `ms` is its transitive runtime dependency, never imported
    // directly. Both ship and must appear (regression guard for `--required-only`,
    // which dropped them).
    assert!(
        names.iter().any(|name| name == "debug"),
        "expected shipped production dependency 'debug' in SBOM, got: {names:?}"
    );
    assert!(
        names.iter().any(|name| name == "ms"),
        "expected transitive runtime dependency 'ms' in SBOM, got: {names:?}"
    );

    // `left-pad` is a devDependency and is not installed under --production, so it
    // must not be reported as a shipped component.
    assert!(
        !names.iter().any(|name| name == "left-pad"),
        "development-only dependency 'left-pad' must not appear in SBOM, got: {names:?}"
    );

    let notice =
        fs::read_to_string(temp.path().join("provenance/THIRD-PARTY-NOTICES.txt")).unwrap();
    assert!(
        notice.contains("- debug "),
        "notice should attribute 'debug'"
    );
    assert!(notice.contains("- ms "), "notice should attribute 'ms'");
    assert!(
        !notice.contains("- left-pad "),
        "notice should not attribute dev-only 'left-pad'"
    );

    cargo_bin()
        .current_dir(temp.path())
        .env("PROVENANCE_CDXGEN", &cdxgen)
        .arg("check")
        .assert()
        .success();
}
