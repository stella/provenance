use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use miette::{Context, IntoDiagnostic, Result, miette};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub version: u32,
    #[serde(default = "default_output_dir")]
    pub output_dir: PathBuf,
    #[serde(default, skip_serializing_if = "NoticeConfig::is_default")]
    pub notice: NoticeConfig,
    pub projects: Vec<ProjectConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub containers: Vec<ContainerConfig>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NoticeConfig {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub internal_scopes: Vec<String>,
}

impl NoticeConfig {
    pub fn is_default(&self) -> bool {
        self.internal_scopes.is_empty()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectConfig {
    pub id: String,
    pub path: PathBuf,
    pub ecosystems: Vec<Ecosystem>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerConfig {
    pub name: String,
    pub image: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Javascript,
    Rust,
}

impl Ecosystem {
    pub fn cdxgen_target(self) -> &'static str {
        match self {
            Self::Javascript => "javascript",
            Self::Rust => "rust",
        }
    }
}

fn default_output_dir() -> PathBuf {
    PathBuf::from("provenance")
}

impl Config {
    pub fn load(root: &Path, explicit_path: Option<&Path>) -> Result<Self> {
        let path = resolve_config_path(root, explicit_path);
        let raw = fs::read_to_string(&path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read config at {}", path.display()))?;
        let config: Self = serde_yaml::from_str(&raw)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to parse {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(miette!(
                "unsupported config version {}; expected 1",
                self.version
            ));
        }
        if self.projects.is_empty() {
            return Err(miette!("config must define at least one project"));
        }

        let mut seen_ids = BTreeSet::new();
        for project in &self.projects {
            if project.id.trim().is_empty() {
                return Err(miette!("project ids cannot be empty"));
            }
            if !seen_ids.insert(project.id.clone()) {
                return Err(miette!("duplicate project id '{}'", project.id));
            }
            if project.ecosystems.is_empty() {
                return Err(miette!(
                    "project '{}' must declare at least one ecosystem",
                    project.id
                ));
            }
        }

        for scope in &self.notice.internal_scopes {
            if scope.trim().is_empty() {
                return Err(miette!("notice internal scopes cannot be empty"));
            }
        }

        let mut seen_container_names = BTreeSet::new();
        for container in &self.containers {
            if container.name.trim().is_empty() {
                return Err(miette!("container names cannot be empty"));
            }
            if container.image.trim().is_empty() {
                return Err(miette!(
                    "container '{}' must declare an image reference",
                    container.name
                ));
            }
            if !seen_container_names.insert(container.name.clone()) {
                return Err(miette!("duplicate container name '{}'", container.name));
            }
        }

        Ok(())
    }
}

pub fn resolve_config_path(root: &Path, explicit_path: Option<&Path>) -> PathBuf {
    match explicit_path {
        Some(path) if path.is_absolute() => path.to_path_buf(),
        Some(path) => root.join(path),
        None => root.join(".provenance.yml"),
    }
}

pub fn resolve_output_dir(root: &Path, config: &Config, explicit_path: Option<&Path>) -> PathBuf {
    match explicit_path {
        Some(path) if path.is_absolute() => path.to_path_buf(),
        Some(path) => root.join(path),
        None if config.output_dir.is_absolute() => config.output_dir.clone(),
        None => root.join(&config.output_dir),
    }
}
