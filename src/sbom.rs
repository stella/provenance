use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use miette::{Context, IntoDiagnostic, Result, miette};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    config::{ContainerConfig, Ecosystem, ProjectConfig, SbomConfig},
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<LicenseReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expression: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LicenseReference {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    internal_scopes: &[String],
    sbom_config: &SbomConfig,
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
        .arg("--exclude-regex")
        .arg(build_exclude_regex(sbom_config))
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
    normalize_sbom_file(output_path, internal_scopes)?;
    enrich_rust_component_licenses(root, project, output_path)?;
    normalize_sbom_file(output_path, internal_scopes)?;
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
    normalize_sbom_file(output_path, &[])?;
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
                    .filter_map(|entry| {
                        entry.expression.clone().or_else(|| {
                            entry.license.as_ref().and_then(|license| {
                                license
                                    .id
                                    .as_ref()
                                    .or(license.name.as_ref())
                                    .map(ToString::to_string)
                            })
                        })
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
    let Some(metadata) = load_cargo_metadata(root, project)? else {
        return Ok(Vec::new());
    };

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

fn enrich_rust_component_licenses(
    root: &Path,
    project: &ProjectConfig,
    output_path: &Path,
) -> Result<()> {
    let Some(metadata) = load_cargo_metadata(root, project)? else {
        return Ok(());
    };

    let license_map = cargo_license_map(&metadata);
    if license_map.is_empty() {
        return Ok(());
    }

    let raw = fs::read_to_string(output_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", output_path.display()))?;
    let mut value = serde_json::from_str::<Value>(&raw)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to parse {}", output_path.display()))?;

    apply_cargo_license_metadata(&mut value, &license_map);

    let rendered = serde_json::to_string_pretty(&value)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to render {}", output_path.display()))?;
    fs::write(output_path, format!("{rendered}\n"))
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", output_path.display()))
}

fn load_cargo_metadata(root: &Path, project: &ProjectConfig) -> Result<Option<CargoMetadata>> {
    if !project.ecosystems.contains(&Ecosystem::Rust) {
        return Ok(None);
    }

    let project_root = resolve_project_path(root, &project.path);
    let manifest_path = project_root.join("Cargo.toml");
    if !manifest_path.exists() || !project_root.join("Cargo.lock").exists() {
        return Ok(None);
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
    Ok(Some(metadata))
}

fn cargo_license_map(metadata: &CargoMetadata) -> BTreeMap<String, Vec<ComponentLicense>> {
    metadata
        .packages
        .iter()
        .filter(|package| package.source.is_some())
        .filter_map(|package| {
            let license = package.license.as_deref()?.trim();
            if license.is_empty() {
                return None;
            }

            Some((
                format!("pkg:cargo/{}@{}", package.name, package.version),
                component_licenses_from_cargo(license),
            ))
        })
        .collect()
}

fn component_licenses_from_cargo(license: &str) -> Vec<ComponentLicense> {
    normalize_cargo_license(license)
        .into_iter()
        .map(|value| {
            if looks_like_license_expression(&value) {
                ComponentLicense {
                    license: None,
                    expression: Some(value),
                }
            } else {
                ComponentLicense {
                    license: Some(LicenseReference {
                        id: Some(value),
                        name: None,
                    }),
                    expression: None,
                }
            }
        })
        .collect()
}

fn looks_like_license_expression(license: &str) -> bool {
    license.contains(" AND ")
        || license.contains(" OR ")
        || license.contains(" WITH ")
        || license.contains('(')
        || license.contains(')')
}

fn apply_cargo_license_metadata(
    value: &mut Value,
    license_map: &BTreeMap<String, Vec<ComponentLicense>>,
) {
    let Some(components) = value.get_mut("components").and_then(Value::as_array_mut) else {
        return;
    };

    for component in components {
        let Some(object) = component.as_object_mut() else {
            continue;
        };
        let Some(purl) = object.get("purl").and_then(Value::as_str) else {
            continue;
        };
        let Some(licenses) = license_map.get(purl) else {
            continue;
        };

        let has_licenses = object
            .get("licenses")
            .and_then(Value::as_array)
            .is_some_and(|entries| !entries.is_empty());
        if has_licenses {
            continue;
        }

        if let Ok(serialized) = serde_json::to_value(licenses) {
            object.insert(String::from("licenses"), serialized);
        }
    }
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

fn build_exclude_regex(sbom_config: &SbomConfig) -> String {
    let mut regexes = vec![String::from("(^|/)node_modules(/.*)?$")];
    regexes.extend(
        sbom_config
            .exclude_regexes
            .iter()
            .map(|regex| regex.trim().to_string())
            .filter(|regex| !regex.is_empty()),
    );
    regexes
        .into_iter()
        .map(|regex| format!("(?:{regex})"))
        .collect::<Vec<_>>()
        .join("|")
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

fn normalize_sbom_file(path: &Path, internal_scopes: &[String]) -> Result<()> {
    let raw = fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", path.display()))?;
    let mut value = serde_json::from_str::<Value>(&raw)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to parse {}", path.display()))?;

    normalize_sbom_value(&mut value, internal_scopes);

    let rendered = serde_json::to_string_pretty(&value)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to render {}", path.display()))?;
    fs::write(path, format!("{rendered}\n"))
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", path.display()))
}

fn normalize_sbom_value(value: &mut Value, internal_scopes: &[String]) {
    remove_object_key(value, &["serialNumber"]);
    remove_object_key(value, &["metadata", "timestamp"]);
    remove_object_key(value, &["annotations"]);
    normalize_hash_algorithms(value);
    remove_cdx_bom_metadata_properties(value);
    remove_internal_components(value, internal_scopes);
}

fn remove_cdx_bom_metadata_properties(value: &mut Value) {
    let Some(properties) = value
        .get_mut("metadata")
        .and_then(|metadata| metadata.get_mut("properties"))
        .and_then(Value::as_array_mut)
    else {
        return;
    };

    properties.retain(|property| {
        property
            .get("name")
            .and_then(Value::as_str)
            .is_none_or(|name| !name.starts_with("cdx:bom:"))
    });

    if properties.is_empty() {
        remove_object_key(value, &["metadata", "properties"]);
    }
}

fn remove_internal_components(value: &mut Value, internal_scopes: &[String]) {
    if internal_scopes.is_empty() {
        return;
    }

    let Some(components) = value.get_mut("components").and_then(Value::as_array_mut) else {
        return;
    };

    let mut removed_refs = BTreeSet::new();
    components.retain(|component| {
        let Some(object) = component.as_object() else {
            return true;
        };

        let kind = object.get("type").and_then(Value::as_str);
        if kind == Some("application") {
            return true;
        }

        let name = object
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let package = match object.get("group").and_then(Value::as_str) {
            Some(group) if !group.is_empty() => format!("{group}/{name}"),
            _ => name.to_string(),
        };

        if !is_internal_package(&package, internal_scopes) {
            return true;
        }

        if let Some(reference) = object.get("bom-ref").and_then(Value::as_str) {
            removed_refs.insert(reference.to_string());
        }

        false
    });

    if removed_refs.is_empty() {
        return;
    }

    let Some(dependencies) = value.get_mut("dependencies").and_then(Value::as_array_mut) else {
        return;
    };

    dependencies.retain(|dependency| {
        dependency
            .get("ref")
            .and_then(Value::as_str)
            .is_none_or(|reference| !removed_refs.contains(reference))
    });

    for dependency in dependencies {
        if let Some(depends_on) = dependency
            .get_mut("dependsOn")
            .and_then(Value::as_array_mut)
        {
            depends_on.retain(|reference| {
                reference
                    .as_str()
                    .is_none_or(|reference| !removed_refs.contains(reference))
            });
        }
    }
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
        CargoMetadata, CargoPackage, Component, ComponentLicense, LicenseReference, SbomDocument,
        apply_cargo_license_metadata, build_exclude_regex, cargo_license_map,
        extract_notice_entries, extract_rust_notice_entries, is_internal_package,
        normalize_cargo_license, normalize_sbom_value,
    };
    use serde_json::json;
    use tempfile::tempdir;

    use crate::config::{Ecosystem, ProjectConfig, SbomConfig};

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
                        expression: None,
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
                        expression: None,
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
                    expression: None,
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
    fn combines_default_and_custom_exclude_regexes() {
        let regex = build_exclude_regex(&SbomConfig {
            exclude_regexes: vec![
                String::from("(^|/)wasm/dist(/.*)?$"),
                String::from("(^|/)[^/]+\\.wasi(?:-browser)?\\.js$"),
            ],
        });

        assert!(regex.contains("node_modules"));
        assert!(regex.contains("wasm/dist"));
        assert!(regex.contains("\\.wasi(?:-browser)?\\.js"));
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

        normalize_sbom_value(&mut sbom, &[]);

        assert!(sbom.get("serialNumber").is_none());
        assert!(sbom["metadata"].get("timestamp").is_none());
        assert!(sbom.get("annotations").is_none());
        assert_eq!(sbom["metadata"]["component"]["name"], "package");
        assert!(sbom["metadata"].get("properties").is_none());
        assert_eq!(sbom["components"][0]["hashes"][0]["alg"], "SHA-256");
        assert_eq!(
            sbom["components"][0]["hashes"][0]["content"],
            "ddd31a130427c27518df266943a5308ed92d4b226cc639f5a8f1002816174301"
        );
    }

    #[test]
    fn filters_internal_components_from_sbom() {
        let mut sbom = json!({
            "metadata": {
                "component": {
                    "type": "application",
                    "group": "@stll",
                    "name": "regex-set"
                },
                "properties": [
                    {
                        "name": "cdx:bom:componentNamespaces",
                        "value": "@napi-rs\n@stll"
                    },
                    {
                        "name": "custom",
                        "value": "keep"
                    }
                ]
            },
            "components": [
                {
                    "bom-ref": "pkg:npm/%40stll/regex-set@0.1.1",
                    "type": "application",
                    "group": "@stll",
                    "name": "regex-set",
                    "version": "0.1.1"
                },
                {
                    "bom-ref": "pkg:npm/%40stll/regex-set-darwin-arm64@0.1.1",
                    "type": "library",
                    "group": "@stll",
                    "name": "regex-set-darwin-arm64",
                    "version": "0.1.1"
                },
                {
                    "bom-ref": "pkg:npm/vite@7.3.2",
                    "type": "library",
                    "name": "vite",
                    "version": "7.3.2"
                }
            ],
            "dependencies": [
                {
                    "ref": "pkg:npm/%40stll/regex-set@0.1.1",
                    "dependsOn": [
                        "pkg:npm/%40stll/regex-set-darwin-arm64@0.1.1",
                        "pkg:npm/vite@7.3.2"
                    ]
                },
                {
                    "ref": "pkg:npm/%40stll/regex-set-darwin-arm64@0.1.1",
                    "dependsOn": []
                }
            ]
        });

        normalize_sbom_value(&mut sbom, &[String::from("@stll")]);

        assert_eq!(sbom["components"].as_array().unwrap().len(), 2);
        assert_eq!(sbom["components"][0]["name"], "regex-set");
        assert_eq!(sbom["components"][1]["name"], "vite");
        assert_eq!(sbom["dependencies"].as_array().unwrap().len(), 1);
        assert_eq!(
            sbom["dependencies"][0]["dependsOn"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            sbom["dependencies"][0]["dependsOn"][0],
            "pkg:npm/vite@7.3.2"
        );
        assert_eq!(sbom["metadata"]["properties"].as_array().unwrap().len(), 1);
        assert_eq!(sbom["metadata"]["properties"][0]["name"], "custom");
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
    fn applies_cargo_component_licenses_to_sbom() {
        let metadata = CargoMetadata {
            packages: vec![
                CargoPackage {
                    name: String::from("bit-vec"),
                    version: String::from("0.8.0"),
                    license: Some(String::from("MIT OR Apache-2.0")),
                    source: Some(String::from(
                        "registry+https://github.com/rust-lang/crates.io-index",
                    )),
                },
                CargoPackage {
                    name: String::from("unicode-ident"),
                    version: String::from("1.0.24"),
                    license: Some(String::from("(MIT OR Apache-2.0) AND Unicode-3.0")),
                    source: Some(String::from(
                        "registry+https://github.com/rust-lang/crates.io-index",
                    )),
                },
            ],
        };
        let license_map = cargo_license_map(&metadata);

        let mut sbom = json!({
            "components": [
                {
                    "name": "bit-vec",
                    "version": "0.8.0",
                    "purl": "pkg:cargo/bit-vec@0.8.0",
                    "type": "library"
                },
                {
                    "name": "unicode-ident",
                    "version": "1.0.24",
                    "purl": "pkg:cargo/unicode-ident@1.0.24",
                    "type": "library"
                },
                {
                    "name": "existing",
                    "version": "1.0.0",
                    "purl": "pkg:cargo/existing@1.0.0",
                    "type": "library",
                    "licenses": [
                        {
                            "license": {
                                "id": "BSD-3-Clause"
                            }
                        }
                    ]
                }
            ]
        });

        apply_cargo_license_metadata(&mut sbom, &license_map);

        assert_eq!(
            sbom["components"][0]["licenses"][0]["license"]["id"],
            "Apache-2.0"
        );
        assert_eq!(sbom["components"][0]["licenses"][1]["license"]["id"], "MIT");
        assert_eq!(
            sbom["components"][1]["licenses"][0]["expression"],
            "(MIT OR Apache-2.0) AND Unicode-3.0"
        );
        assert_eq!(
            sbom["components"][2]["licenses"][0]["license"]["id"],
            "BSD-3-Clause"
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
