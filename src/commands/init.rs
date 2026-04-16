use std::{fs, path::PathBuf};

use miette::{Context, IntoDiagnostic, Result, miette};

use crate::{
    config::{Config, resolve_config_path},
    detect::discover_projects,
};

pub fn run(root: PathBuf, config_path: Option<PathBuf>, force: bool) -> Result<()> {
    let root = root
        .canonicalize()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to resolve {}", root.display()))?;
    let path = resolve_config_path(&root, config_path.as_deref());

    if path.exists() && !force {
        return Err(miette!(
            "{} already exists. Re-run with --force to overwrite it",
            path.display()
        ));
    }

    let config = Config {
        version: 1,
        output_dir: PathBuf::from("provenance"),
        notice: Default::default(),
        sbom: Default::default(),
        projects: discover_projects(&root)?,
        containers: Vec::new(),
    };
    config.validate()?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to create {}", parent.display()))?;
    }
    let rendered = serde_yaml::to_string(&config)
        .into_diagnostic()
        .wrap_err("failed to render config file")?;
    fs::write(&path, rendered)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", path.display()))?;

    println!("Wrote {}", path.display());
    Ok(())
}
