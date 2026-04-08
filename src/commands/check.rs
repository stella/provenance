use std::path::PathBuf;

use miette::{Context, IntoDiagnostic, Result, miette};

use crate::{
    commands::generate::generate_all,
    config::{Config, resolve_output_dir},
    drift::{compare_dirs, render_deltas},
};

pub fn run(root: PathBuf, config_path: Option<PathBuf>, output_dir: Option<PathBuf>) -> Result<()> {
    let root = root
        .canonicalize()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to resolve {}", root.display()))?;
    let config = Config::load(&root, config_path.as_deref())?;
    let checked_in_output = resolve_output_dir(&root, &config, output_dir.as_deref());
    let temp = tempfile::tempdir().into_diagnostic()?;
    let generated_output = temp.path().join("compliance");

    generate_all(&root, &config, &generated_output)?;

    let deltas = compare_dirs(&checked_in_output, &generated_output)?;
    if deltas.is_empty() {
        println!("Compliance outputs are up to date.");
        return Ok(());
    }

    let rendered = render_deltas(&deltas);
    Err(miette!(
        "Compliance outputs are stale.\n\n{}\nRun `stella-compliance generate --root {}` to refresh them.",
        rendered,
        root.display()
    ))
}
