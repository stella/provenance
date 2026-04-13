use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use miette::{Context, IntoDiagnostic, Result, miette};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    config::{ContainerConfig, Ecosystem, ProjectConfig},
    notice::{DependencyNotice, normalize_licenses},
};

#[derive(Clone, Debug)]
struct CommandSpec {
    program: PathBuf,
    prefix_args: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SbomDocument {
    #[serde(default)]
    pub components: Vec<Component>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Component {
    #[serde(default)]
    pub group: Option<String>,
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub licenses: Vec<ComponentLicense>,
    #[serde(rename = "type", default)]
    pub kind: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComponentLicense {
    #[serde(default)]
    pub license: Option<LicenseReference>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LicenseReference {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
}

#[derive(Debug, Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
    license: Option<String>,
    source: Option<String>,
}

pub fn generate_project_sbom(
    root: &Path,
    project: &ProjectConfig,
    output_path: &Path,
) -> Result<SbomDocument> {
    let project_dir = resolve_project_path(root, &project.path);
    let command_spec = resolve_cdxgen()?;
    let mut command = Command::new(&command_spec.program);
    command.args(&command_spec.prefix_args);
    for ecosystem in &project.ecosystems {
        command.arg("-t").arg(ecosystem.cdxgen_target());
    }
    command
        .arg("--no-install-deps")
        // cdxgen expects a regex here; match node_modules itself and its descendants.
        .arg("--exclude-regex")
        .arg("(^|/)node_modules(/.*)?$")
        .arg("--required-only")
        .arg("--json-pretty")
        .arg("-o")
        .arg(output_path)
        .arg(".")
        .current_dir(&project_dir);

    run_command(
        command,
        &format!("cdxgen for project '{}'", project.id),
        Some(output_path),
    )?;
    normalize_sbom_file(output_path)?;
    load_sbom(output_path)
}

pub fn generate_container_sbom(
    container: &ContainerConfig,
    output_path: &Path,
) -> Result<SbomDocument> {
    let command_spec = resolve_syft()?;
    let mut command = Command::new(&command_spec.program);
    command.args(&command_spec.prefix_args);
    command
        .arg(&container.image)
        .arg("-o")
        .arg("cyclonedx-json");
    let output = command
        .output()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to run syft for '{}'", container.name))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(miette!(
            "syft for '{}' failed: {}",
            container.name,
            stderr.trim()
        ));
    }

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(output_path, &output.stdout)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", output_path.display()))?;
    normalize_sbom_file(output_path)?;
    load_sbom(output_path)
}

pub fn extract_notice_entries(
    sbom: &SbomDocument,
    internal_scopes: &[String],
) -> Vec<DependencyNotice> {
    let mut entries = sbom
        .components
        .iter()
        .filter(|component| component.kind.as_deref() != Some("application"))
        .filter_map(|component| {
            let licenses = normalize_licenses(
                component
                    .licenses
                    .iter()
                    .filter_map(|entry| entry.license.as_ref())
                    .filter_map(|license| {
                        license
                            .id
                            .as_ref()
                            .or(license.name.as_ref())
                            .map(ToString::to_string)
                    })
                    .collect(),
            );

            if licenses.is_empty() {
                return None;
            }

            let package = match &component.group {
                Some(group) if !group.is_empty() => format!("{}/{}", group, component.name),
                _ => component.name.clone(),
            };

            if is_internal_package(&package, internal_scopes) {
                return None;
            }

            Some(DependencyNotice {
                package,
                version: component
                    .version
                    .clone()
                    .unwrap_or_else(|| String::from("unknown")),
                licenses,
            })
        })
        .collect::<Vec<_>>();

    entries.sort();
    entries.dedup();
    entries
}

pub fn extract_rust_notice_entries(
    root: &Path,
    project: &ProjectConfig,
    internal_scopes: &[String],
) -> Result<Vec<DependencyNotice>> {
    if !project.ecosystems.contains(&Ecosystem::Rust) {
        return Ok(Vec::new());
    }

    let project_root = resolve_project_path(root, &project.path);
    let manifest_path = project_root.join("Cargo.toml");
    if !manifest_path.exists() {
        return Ok(Vec::new());
    }
    if !project_root.join("Cargo.lock").exists() {
        return Ok(Vec::new());
    }

    let output = Command::new("cargo")
        .arg("metadata")
        .arg("--format-version=1")
        .arg("--locked")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .output()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to run cargo metadata for '{}'", project.id))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(miette!(
            "cargo metadata for '{}' failed: {}",
            project.id,
            stderr.trim()
        ));
    }

    let metadata = serde_json::from_slice::<CargoMetadata>(&output.stdout)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to parse cargo metadata for '{}'", project.id))?;

    let mut entries = metadata
        .packages
        .into_iter()
        .filter(|package| package.source.is_some())
        .filter_map(|package| {
            let license = package.license.as_deref()?.trim();
            if license.is_empty() || is_internal_package(&package.name, internal_scopes) {
                return None;
            }

            Some(DependencyNotice {
                package: package.name,
                version: package.version,
                licenses: normalize_cargo_license(license),
            })
        })
        .collect::<Vec<_>>();

    entries.sort();
    entries.dedup();
    Ok(entries)
}

fn is_internal_package(package: &str, internal_scopes: &[String]) -> bool {
    internal_scopes.iter().any(|scope| {
        let scope = scope.trim();
        package == scope
            || package
                .strip_prefix(scope)
                .is_some_and(|suffix| suffix.starts_with('/'))
    })
}

fn normalize_cargo_license(license: &str) -> Vec<String> {
    let license = license.trim();
    if license.is_empty() {
        return Vec::new();
    }

    let is_simple_or_expression = license.contains(" OR ")
        && !license.contains(" AND ")
        && !license.contains(" WITH ")
        && !license.contains('(')
        && !license.contains(')');

    if is_simple_or_expression {
        return normalize_licenses(license.split(" OR ").map(ToString::to_string).collect());
    }

    vec![license.to_string()]
}

fn resolve_project_path(root: &Path, project_path: &Path) -> PathBuf {
    if project_path.is_absolute() {
        project_path.to_path_buf()
    } else {
        root.join(project_path)
    }
}

fn resolve_cdxgen() -> Result<CommandSpec> {
    if let Ok(path) = env::var("PROVENANCE_CDXGEN") {
        return Ok(CommandSpec {
            program: PathBuf::from(path),
            prefix_args: Vec::new(),
        });
    }
    if let Ok(path) = which::which("cdxgen") {
        return Ok(CommandSpec {
            program: path,
            prefix_args: Vec::new(),
        });
    }
    if let Ok(path) = which::which("bunx") {
        return Ok(CommandSpec {
            program: path,
            prefix_args: vec![String::from("@cyclonedx/cdxgen")],
        });
    }
    if let Ok(path) = which::which("npx") {
        return Ok(CommandSpec {
            program: path,
            prefix_args: vec![String::from("--yes"), String::from("@cyclonedx/cdxgen")],
        });
    }

    Err(miette!(
        "unable to locate cdxgen. Install it globally, or expose it via bunx/npx, or set PROVENANCE_CDXGEN"
    ))
}

fn resolve_syft() -> Result<CommandSpec> {
    if let Ok(path) = env::var("PROVENANCE_SYFT") {
        return Ok(CommandSpec {
            program: PathBuf::from(path),
            prefix_args: Vec::new(),
        });
    }
    if let Ok(path) = which::which("syft") {
        return Ok(CommandSpec {
            program: path,
            prefix_args: Vec::new(),
        });
    }

    Err(miette!(
        "unable to locate syft. Install it or set PROVENANCE_SYFT"
    ))
}

fn run_command(mut command: Command, label: &str, output_path: Option<&Path>) -> Result<()> {
    let output = command
        .output()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to run {label}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let details = if stderr.trim().is_empty() {
            stdout.trim()
        } else {
            stderr.trim()
        };
        return Err(miette!("{} failed: {}", label, details));
    }

    if let Some(path) = output_path {
        let exists = path.exists();
        if !exists {
            return Err(miette!(
                "{} reported success but did not write {}",
                label,
                path.display()
            ));
        }
    }

    Ok(())
}

fn load_sbom(path: &Path) -> Result<SbomDocument> {
    let raw = fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&raw)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to parse {}", path.display()))
}

fn normalize_sbom_file(path: &Path) -> Result<()> {
    let raw = fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", path.display()))?;
    let mut value = serde_json::from_str::<Value>(&raw)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to parse {}", path.display()))?;

    normalize_sbom_value(&mut value);

    let rendered = serde_json::to_string_pretty(&value)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to render {}", path.display()))?;
    fs::write(path, format!("{rendered}\n"))
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", path.display()))
}

fn normalize_sbom_value(value: &mut Value) {
    remove_object_key(value, &["serialNumber"]);
    remove_object_key(value, &["metadata", "timestamp"]);
    remove_object_key(value, &["annotations"]);
    normalize_hash_algorithms(value);
}

fn normalize_hash_algorithms(value: &mut Value) {
    match value {
        Value::Object(object) => {
            let digest_len = object.get("content").and_then(Value::as_str).map(str::len);

            if digest_len == Some(64) {
                if let Some(Value::String(algorithm)) = object.get_mut("alg") {
                    if algorithm == "SHA-384" {
                        *algorithm = String::from("SHA-256");
                    }
                }
            }

            for child in object.values_mut() {
                normalize_hash_algorithms(child);
            }
        }
        Value::Array(items) => {
            for item in items {
                normalize_hash_algorithms(item);
            }
        }
        _ => {}
    }
}

fn remove_object_key(value: &mut Value, path: &[&str]) {
    match path {
        [] => {}
        [key] => {
            if let Some(object) = value.as_object_mut() {
                object.remove(*key);
            }
        }
        [head, tail @ ..] => {
            if let Some(next) = value.get_mut(*head) {
                remove_object_key(next, tail);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{
        Component, ComponentLicense, LicenseReference, SbomDocument, extract_notice_entries,
        extract_rust_notice_entries, is_internal_package, normalize_cargo_license,
        normalize_sbom_value,
    };
    use serde_json::json;
    use tempfile::tempdir;

    use crate::config::{Ecosystem, ProjectConfig};

    #[test]
    fn extracts_deduplicated_sorted_notice_entries() {
        let sbom = SbomDocument {
            components: vec![
                Component {
                    group: Some(String::from("@stella")),
                    name: String::from("root"),
                    version: Some(String::from("0.1.0")),
                    licenses: Vec::new(),
                    kind: Some(String::from("application")),
                },
                Component {
                    group: Some(String::from("@scope")),
                    name: String::from("alpha"),
                    version: Some(String::from("1.0.0")),
                    licenses: vec![ComponentLicense {
                        license: Some(LicenseReference {
                            id: Some(String::from("MIT")),
                            name: None,
                        }),
                    }],
                    kind: Some(String::from("library")),
                },
                Component {
                    group: Some(String::from("@scope")),
                    name: String::from("alpha"),
                    version: Some(String::from("1.0.0")),
                    licenses: vec![ComponentLicense {
                        license: Some(LicenseReference {
                            id: None,
                            name: Some(String::from("MIT")),
                        }),
                    }],
                    kind: Some(String::from("library")),
                },
            ],
        };

        let entries = extract_notice_entries(&sbom, &[]);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].package, "@scope/alpha");
        assert_eq!(entries[0].licenses, vec![String::from("MIT")]);
    }

    #[test]
    fn filters_internal_scopes_from_notice_entries() {
        let sbom = SbomDocument {
            components: vec![Component {
                group: Some(String::from("@scope")),
                name: String::from("internal"),
                version: Some(String::from("1.0.0")),
                licenses: vec![ComponentLicense {
                    license: Some(LicenseReference {
                        id: Some(String::from("MIT")),
                        name: None,
                    }),
                }],
                kind: Some(String::from("library")),
            }],
        };

        let entries = extract_notice_entries(&sbom, &[String::from("@scope")]);
        assert!(entries.is_empty());
        assert!(is_internal_package(
            "@scope/internal",
            &[String::from("@scope")]
        ));
        assert!(!is_internal_package(
            "@scopeish/internal",
            &[String::from("@scope")]
        ));
    }

    #[test]
    fn normalizes_volatile_sbom_fields() {
        let mut sbom = json!({
            "serialNumber": "urn:uuid:random",
            "metadata": {
                "timestamp": "2026-04-09T19:40:46Z",
                "component": {
                    "name": "package"
                }
            },
            "annotations": [
                {
                    "timestamp": "2026-04-09T19:40:46Z",
                    "text": "generated"
                }
            ],
            "components": [
                {
                    "name": "aho-corasick",
                    "hashes": [
                        {
                            "alg": "SHA-384",
                            "content": "ddd31a130427c27518df266943a5308ed92d4b226cc639f5a8f1002816174301"
                        }
                    ]
                }
            ]
        });

        normalize_sbom_value(&mut sbom);

        assert!(sbom.get("serialNumber").is_none());
        assert!(sbom["metadata"].get("timestamp").is_none());
        assert!(sbom.get("annotations").is_none());
        assert_eq!(sbom["metadata"]["component"]["name"], "package");
        assert_eq!(sbom["components"][0]["hashes"][0]["alg"], "SHA-256");
        assert_eq!(
            sbom["components"][0]["hashes"][0]["content"],
            "ddd31a130427c27518df266943a5308ed92d4b226cc639f5a8f1002816174301"
        );
    }

    #[test]
    fn normalizes_simple_cargo_or_license_expressions() {
        assert_eq!(
            normalize_cargo_license("MIT OR Apache-2.0"),
            vec![String::from("Apache-2.0"), String::from("MIT")]
        );
        assert_eq!(
            normalize_cargo_license("(MIT OR Apache-2.0) AND Unicode-3.0"),
            vec![String::from("(MIT OR Apache-2.0) AND Unicode-3.0")]
        );
    }

    #[test]
    fn skips_rust_notice_entries_for_non_rust_projects() {
        let temp = tempdir().unwrap();
        let project = ProjectConfig {
            id: String::from("root"),
            path: ".".into(),
            ecosystems: vec![Ecosystem::Javascript],
        };

        let entries = extract_rust_notice_entries(temp.path(), &project, &[]).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn skips_rust_notice_enrichment_without_lockfile() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();

        let project = ProjectConfig {
            id: String::from("root"),
            path: ".".into(),
            ecosystems: vec![Ecosystem::Rust],
        };

        let entries = extract_rust_notice_entries(temp.path(), &project, &[]).unwrap();
        assert!(entries.is_empty());
    }
}
