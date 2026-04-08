use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use ignore::WalkBuilder;
use miette::{Context, IntoDiagnostic, Result, miette};
use serde_json::Value as JsonValue;
use toml::Value as TomlValue;

use crate::config::{Ecosystem, ProjectConfig};

#[derive(Default)]
struct Candidate {
    javascript: bool,
    rust: bool,
    js_workspace: bool,
    rust_workspace: bool,
}

pub fn discover_projects(root: &Path) -> Result<Vec<ProjectConfig>> {
    let mut candidates = BTreeMap::<PathBuf, Candidate>::new();

    let mut walker = WalkBuilder::new(root);
    walker.hidden(false);
    walker.git_ignore(true);
    walker.git_global(true);
    walker.git_exclude(true);
    walker.filter_entry(|entry| {
        let name = entry.file_name().to_string_lossy();
        !matches!(
            name.as_ref(),
            ".git" | "node_modules" | "target" | "compliance" | "dist"
        )
    });

    for entry in walker.build() {
        let entry = entry.into_diagnostic()?;
        let is_file = entry
            .file_type()
            .is_some_and(|file_type| file_type.is_file());
        if !is_file {
            continue;
        }

        let Some(file_name) = entry.path().file_name().and_then(|value| value.to_str()) else {
            continue;
        };

        let dir = entry
            .path()
            .parent()
            .ok_or_else(|| miette!("missing parent directory for {}", entry.path().display()))?;
        let candidate = candidates.entry(dir.to_path_buf()).or_default();

        match file_name {
            "package.json" => {
                let raw = fs::read_to_string(entry.path())
                    .into_diagnostic()
                    .wrap_err_with(|| format!("failed to read {}", entry.path().display()))?;
                let parsed: JsonValue = serde_json::from_str(&raw)
                    .into_diagnostic()
                    .wrap_err_with(|| format!("failed to parse {}", entry.path().display()))?;
                candidate.javascript = true;
                candidate.js_workspace = parsed.get("workspaces").is_some();
            }
            "Cargo.toml" => {
                let raw = fs::read_to_string(entry.path())
                    .into_diagnostic()
                    .wrap_err_with(|| format!("failed to read {}", entry.path().display()))?;
                let parsed: TomlValue = toml::from_str(&raw)
                    .into_diagnostic()
                    .wrap_err_with(|| format!("failed to parse {}", entry.path().display()))?;
                candidate.rust = true;
                candidate.rust_workspace = parsed.get("workspace").is_some();
            }
            _ => {}
        }
    }

    let js_workspace_roots: BTreeSet<PathBuf> = candidates
        .iter()
        .filter_map(|(path, candidate)| candidate.js_workspace.then_some(path.clone()))
        .collect();
    let rust_workspace_roots: BTreeSet<PathBuf> = candidates
        .iter()
        .filter_map(|(path, candidate)| candidate.rust_workspace.then_some(path.clone()))
        .collect();

    let mut projects = Vec::new();

    for (path, candidate) in candidates {
        let mut ecosystems = BTreeSet::new();

        if candidate.javascript && !has_workspace_ancestor(&path, &js_workspace_roots) {
            ecosystems.insert(Ecosystem::Javascript);
        }
        if candidate.rust && !has_workspace_ancestor(&path, &rust_workspace_roots) {
            ecosystems.insert(Ecosystem::Rust);
        }

        if ecosystems.is_empty() {
            continue;
        }

        let relative = path.strip_prefix(root).unwrap_or(&path);
        projects.push(ProjectConfig {
            id: slugify(relative),
            path: if relative.as_os_str().is_empty() {
                PathBuf::from(".")
            } else {
                relative.to_path_buf()
            },
            ecosystems: ecosystems.into_iter().collect(),
        });
    }

    if projects.is_empty() {
        return Err(miette!(
            "no JavaScript or Rust projects were discovered under {}",
            root.display()
        ));
    }

    Ok(projects)
}

fn has_workspace_ancestor(path: &Path, roots: &BTreeSet<PathBuf>) -> bool {
    let mut current = path.parent();
    while let Some(parent) = current {
        if roots.contains(parent) {
            return true;
        }
        current = parent.parent();
    }
    false
}

fn slugify(relative_path: &Path) -> String {
    if relative_path.as_os_str().is_empty() || relative_path == Path::new(".") {
        return String::from("root");
    }

    let slug = relative_path
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("-");

    let slug = slug
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' => ch.to_ascii_lowercase(),
            _ => '-',
        })
        .collect::<String>();

    let slug = slug
        .split('-')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("-");

    if slug.is_empty() {
        String::from("project")
    } else {
        slug
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use tempfile::tempdir;

    use super::discover_projects;

    #[test]
    fn skips_nested_workspace_members() {
        let temp = tempdir().unwrap();
        let root = temp.path();

        fs::write(
            root.join("package.json"),
            r#"{"private": true, "workspaces": ["packages/*"]}"#,
        )
        .unwrap();
        fs::create_dir_all(root.join("packages/app")).unwrap();
        fs::write(
            root.join("packages/app/package.json"),
            r#"{"name": "@stella/app"}"#,
        )
        .unwrap();

        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/*\"]\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("crates/core")).unwrap();
        fs::write(
            root.join("crates/core/Cargo.toml"),
            "[package]\nname = \"core\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();

        let projects = discover_projects(root).unwrap();
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].id, "root");
        assert_eq!(projects[0].path, PathBuf::from("."));
        assert_eq!(projects[0].ecosystems.len(), 2);
    }
}
