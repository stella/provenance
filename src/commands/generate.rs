use std::{
    fs,
    path::{Path, PathBuf},
};

use miette::{Context, IntoDiagnostic, Result};
use serde::Serialize;

use crate::{
    config::{Config, Ecosystem, resolve_output_dir},
    notice::{DependencyNotice, render_project_notice, render_repo_notice},
    sbom::{extract_notice_entries, generate_container_sbom, generate_project_sbom},
};

#[derive(Debug, Serialize)]
pub struct ComplianceReport {
    version: u32,
    output_dir: String,
    projects: Vec<ProjectReport>,
    containers: Vec<ContainerReport>,
}

#[derive(Debug, Serialize)]
struct ProjectReport {
    id: String,
    path: String,
    ecosystems: Vec<Ecosystem>,
    sbom: String,
    notice: String,
    dependencies_with_licenses: usize,
}

#[derive(Debug, Serialize)]
struct ContainerReport {
    name: String,
    image: String,
    sbom: String,
    notice: String,
    dependencies_with_licenses: usize,
}

pub fn run(root: PathBuf, config_path: Option<PathBuf>, output_dir: Option<PathBuf>) -> Result<()> {
    let root = root
        .canonicalize()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to resolve {}", root.display()))?;
    let config = Config::load(&root, config_path.as_deref())?;
    let output_path = resolve_output_dir(&root, &config, output_dir.as_deref());
    let report = generate_all(&root, &config, &output_path)?;

    println!(
        "Generated {} project(s) and {} container(s) into {}",
        report.projects.len(),
        report.containers.len(),
        output_path.display()
    );
    Ok(())
}

pub fn generate_all(root: &Path, config: &Config, output_path: &Path) -> Result<ComplianceReport> {
    config.validate()?;
    prepare_output_dir(output_path)?;

    let mut report = ComplianceReport {
        version: 1,
        output_dir: String::from("."),
        projects: Vec::new(),
        containers: Vec::new(),
    };
    let mut repo_sections = Vec::<(String, Vec<DependencyNotice>)>::new();

    for project in &config.projects {
        let project_output = output_path.join("projects").join(&project.id);
        fs::create_dir_all(&project_output)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to create {}", project_output.display()))?;

        let sbom_path = project_output.join("sbom.cdx.json");
        let notice_path = project_output.join("THIRD-PARTY-NOTICES.txt");
        let sbom = generate_project_sbom(root, project, &sbom_path)?;
        let entries = extract_notice_entries(&sbom);
        let notice = render_project_notice(&project.id, &entries);
        fs::write(&notice_path, notice)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to write {}", notice_path.display()))?;

        repo_sections.push((format!("Project: {}", project.id), entries.clone()));
        report.projects.push(ProjectReport {
            id: project.id.clone(),
            path: project.path.display().to_string(),
            ecosystems: project.ecosystems.clone(),
            sbom: display_relative(output_path, &sbom_path),
            notice: display_relative(output_path, &notice_path),
            dependencies_with_licenses: entries.len(),
        });
    }

    for container in &config.containers {
        let container_output = output_path.join("containers").join(&container.name);
        fs::create_dir_all(&container_output)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to create {}", container_output.display()))?;

        let sbom_path = container_output.join("sbom.cdx.json");
        let notice_path = container_output.join("THIRD-PARTY-NOTICES.txt");
        let sbom = generate_container_sbom(container, &sbom_path)?;
        let entries = extract_notice_entries(&sbom);
        let notice = render_project_notice(&container.name, &entries);
        fs::write(&notice_path, notice)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to write {}", notice_path.display()))?;

        repo_sections.push((format!("Container: {}", container.name), entries.clone()));
        report.containers.push(ContainerReport {
            name: container.name.clone(),
            image: container.image.clone(),
            sbom: display_relative(output_path, &sbom_path),
            notice: display_relative(output_path, &notice_path),
            dependencies_with_licenses: entries.len(),
        });
    }

    let repo_notice_path = output_path.join("THIRD-PARTY-NOTICES.repo.txt");
    let repo_notice = render_repo_notice(&repo_sections);
    fs::write(&repo_notice_path, repo_notice)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", repo_notice_path.display()))?;

    let report_path = output_path.join("report.json");
    let report_json = serde_json::to_string_pretty(&report)
        .into_diagnostic()
        .wrap_err("failed to render report.json")?;
    fs::write(&report_path, report_json)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", report_path.display()))?;

    Ok(report)
}

fn prepare_output_dir(output_path: &Path) -> Result<()> {
    fs::create_dir_all(output_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create {}", output_path.display()))?;

    for managed_dir in ["projects", "containers"] {
        let path = output_path.join(managed_dir);
        if path.exists() {
            fs::remove_dir_all(&path)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to clear {}", path.display()))?;
        }
    }

    for managed_file in ["THIRD-PARTY-NOTICES.repo.txt", "report.json"] {
        let path = output_path.join(managed_file);
        if path.exists() {
            fs::remove_file(&path)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to remove {}", path.display()))?;
        }
    }

    Ok(())
}

fn display_relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}
