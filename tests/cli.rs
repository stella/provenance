use std::{
    fs,
    path::{Path, PathBuf},
};

use assert_cmd::Command;
use assert_fs::TempDir;
use predicates::prelude::*;

fn cargo_bin() -> Command {
    Command::cargo_bin("stella-compliance").unwrap()
}

fn make_executable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }
}

fn write_script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, body).unwrap();
    make_executable(&path);
    path
}

fn project_sbom_json() -> &'static str {
    r#"{
  "components": [
    {
      "group": "@stella",
      "name": "app",
      "version": "0.1.0",
      "type": "application"
    },
    {
      "group": "@scope",
      "name": "alpha",
      "version": "1.2.3",
      "type": "library",
      "licenses": [
        { "license": { "id": "MIT" } }
      ]
    },
    {
      "name": "regex",
      "version": "1.11.0",
      "type": "library",
      "licenses": [
        { "license": { "id": "Apache-2.0" } }
      ]
    }
  ]
}"#
}

fn container_sbom_json() -> &'static str {
    r#"{
  "components": [
    {
      "name": "busybox",
      "version": "1.36.1",
      "type": "library",
      "licenses": [
        { "license": { "id": "GPL-2.0-only" } }
      ]
    }
  ]
}"#
}

fn write_cdxgen_stub(dir: &Path) -> PathBuf {
    write_script(
        dir,
        "cdxgen-stub.sh",
        &format!(
            "#!/bin/sh\nset -eu\nout=\"\"\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = \"-o\" ]; then\n    out=\"$2\"\n    shift 2\n    continue\n  fi\n  shift\ndone\nmkdir -p \"$(dirname \"$out\")\"\ncat <<'JSON' > \"$out\"\n{}\nJSON\n",
            project_sbom_json()
        ),
    )
}

fn write_syft_stub(dir: &Path) -> PathBuf {
    write_script(
        dir,
        "syft-stub.sh",
        &format!(
            "#!/bin/sh\nset -eu\ncat <<'JSON'\n{}\nJSON\n",
            container_sbom_json()
        ),
    )
}

fn write_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, contents).unwrap();
}

#[test]
fn init_refuses_to_overwrite_without_force() {
    let temp = TempDir::new().unwrap();
    write_file(&temp.path().join("package.json"), r#"{"name":"root"}"#);
    write_file(
        &temp.path().join(".stella-compliance.yml"),
        "version: 1\noutput_dir: compliance\nprojects: []\n",
    );

    cargo_bin()
        .current_dir(temp.path())
        .arg("init")
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn init_discovers_workspace_roots() {
    let temp = TempDir::new().unwrap();
    write_file(
        &temp.path().join("package.json"),
        r#"{"private":true,"workspaces":["packages/*"]}"#,
    );
    write_file(
        &temp.path().join("packages/app/package.json"),
        r#"{"name":"@stella/app"}"#,
    );
    write_file(
        &temp.path().join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/*\"]\n",
    );
    write_file(
        &temp.path().join("crates/core/Cargo.toml"),
        "[package]\nname=\"core\"\nversion=\"0.1.0\"\n",
    );

    cargo_bin()
        .current_dir(temp.path())
        .arg("init")
        .assert()
        .success()
        .stdout(predicate::str::contains(".stella-compliance.yml"));

    let config = fs::read_to_string(temp.path().join(".stella-compliance.yml")).unwrap();
    assert!(config.contains("id: root"));
    assert!(config.contains("path: ."));
    assert!(config.contains("- javascript"));
    assert!(config.contains("- rust"));
    assert!(!config.contains("packages-app"));
    assert!(!config.contains("crates-core"));
}

#[test]
fn generate_creates_outputs_for_projects_and_containers() {
    let temp = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();
    let cdxgen = write_cdxgen_stub(stubs.path());
    let syft = write_syft_stub(stubs.path());

    write_file(&temp.path().join("package.json"), r#"{"name":"root"}"#);
    write_file(
        &temp.path().join("Cargo.toml"),
        "[package]\nname=\"root\"\nversion=\"0.1.0\"\n",
    );
    write_file(
        &temp.path().join(".stella-compliance.yml"),
        r#"version: 1
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
"#,
    );

    cargo_bin()
        .current_dir(temp.path())
        .env("STELLA_COMPLIANCE_CDXGEN", &cdxgen)
        .env("STELLA_COMPLIANCE_SYFT", &syft)
        .arg("generate")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Generated 1 project(s) and 1 container(s)",
        ));

    let repo_notice =
        fs::read_to_string(temp.path().join("compliance/THIRD-PARTY-NOTICES.repo.txt")).unwrap();
    assert!(repo_notice.contains("Project: root"));
    assert!(repo_notice.contains("@scope/alpha 1.2.3"));
    assert!(repo_notice.contains("Container: stella-core"));
    assert!(repo_notice.contains("busybox 1.36.1"));

    let report = fs::read_to_string(temp.path().join("compliance/report.json")).unwrap();
    assert!(report.contains("\"id\": \"root\""));
    assert!(report.contains("\"name\": \"stella-core\""));
}

#[test]
fn check_passes_when_outputs_are_current() {
    let temp = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();
    let cdxgen = write_cdxgen_stub(stubs.path());

    write_file(&temp.path().join("package.json"), r#"{"name":"root"}"#);
    write_file(
        &temp.path().join(".stella-compliance.yml"),
        r#"version: 1
output_dir: compliance
projects:
  - id: root
    path: .
    ecosystems:
      - javascript
"#,
    );

    cargo_bin()
        .current_dir(temp.path())
        .env("STELLA_COMPLIANCE_CDXGEN", &cdxgen)
        .arg("generate")
        .assert()
        .success();

    cargo_bin()
        .current_dir(temp.path())
        .env("STELLA_COMPLIANCE_CDXGEN", &cdxgen)
        .arg("check")
        .assert()
        .success()
        .stdout(predicate::str::contains("up to date"));
}

#[test]
fn check_and_diff_report_drift() {
    let temp = TempDir::new().unwrap();
    let stubs = TempDir::new().unwrap();
    let cdxgen = write_cdxgen_stub(stubs.path());

    write_file(&temp.path().join("package.json"), r#"{"name":"root"}"#);
    write_file(
        &temp.path().join(".stella-compliance.yml"),
        r#"version: 1
output_dir: compliance
projects:
  - id: root
    path: .
    ecosystems:
      - javascript
"#,
    );

    cargo_bin()
        .current_dir(temp.path())
        .env("STELLA_COMPLIANCE_CDXGEN", &cdxgen)
        .arg("generate")
        .assert()
        .success();

    write_file(
        &temp
            .path()
            .join("compliance/projects/root/THIRD-PARTY-NOTICES.txt"),
        "tampered\n",
    );

    cargo_bin()
        .current_dir(temp.path())
        .env("STELLA_COMPLIANCE_CDXGEN", &cdxgen)
        .arg("check")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Compliance outputs are stale"))
        .stderr(predicate::str::contains("THIRD-PARTY-NOTICES.txt"));

    cargo_bin()
        .current_dir(temp.path())
        .env("STELLA_COMPLIANCE_CDXGEN", &cdxgen)
        .arg("diff")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "=== projects/root/THIRD-PARTY-NOTICES.txt ===",
        ))
        .stdout(predicate::str::contains("--- checked-in"))
        .stdout(predicate::str::contains("+++ generated"));
}
