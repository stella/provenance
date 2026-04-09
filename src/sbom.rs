use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use miette::{Context, IntoDiagnostic, Result, miette};
use serde::{Deserialize, Serialize};

use crate::{
    config::{ContainerConfig, ProjectConfig},
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
        .arg("scan")
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
    load_sbom(output_path)
}

pub fn extract_notice_entries(sbom: &SbomDocument) -> Vec<DependencyNotice> {
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

fn resolve_project_path(root: &Path, project_path: &Path) -> PathBuf {
    if project_path.is_absolute() {
        project_path.to_path_buf()
    } else {
        root.join(project_path)
    }
}

fn resolve_cdxgen() -> Result<CommandSpec> {
    if let Ok(path) = env::var("STELLA_COMPLIANCE_CDXGEN") {
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
        "unable to locate cdxgen. Install it globally, or expose it via bunx/npx, or set STELLA_COMPLIANCE_CDXGEN"
    ))
}

fn resolve_syft() -> Result<CommandSpec> {
    if let Ok(path) = env::var("STELLA_COMPLIANCE_SYFT") {
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
        "unable to locate syft. Install it or set STELLA_COMPLIANCE_SYFT"
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

#[cfg(test)]
mod tests {
    use super::{
        Component, ComponentLicense, LicenseReference, SbomDocument, extract_notice_entries,
    };

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

        let entries = extract_notice_entries(&sbom);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].package, "@scope/alpha");
        assert_eq!(entries[0].licenses, vec![String::from("MIT")]);
    }
}
