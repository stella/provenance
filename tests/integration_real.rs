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

fn write_bunx_cdxgen_wrapper(dir: &Path) -> PathBuf {
    let bunx = which::which("bunx").expect("bunx is required for the real cdxgen integration test");
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

fn parse_json(path: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
#[ignore = "requires bunx and network access for a real cdxgen invocation"]
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

    let cdxgen = write_bunx_cdxgen_wrapper(helpers.path());

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
#[ignore = "requires bunx, syft, and network access for real tool invocations"]
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

    let cdxgen = write_bunx_cdxgen_wrapper(helpers.path());
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
