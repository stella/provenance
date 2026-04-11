use std::path::PathBuf;

use miette::{Context, IntoDiagnostic, Result};

use crate::{
    commands::generate::{display_relative, ensure_safe_output_dir, generate_all},
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
    ensure_safe_output_dir(&root, &checked_in_output)?;
    let report_output_dir = display_relative(&root, &checked_in_output);
    let temp = tempfile::tempdir().into_diagnostic()?;
    let generated_output = temp.path().join("provenance");

    generate_all(&root, &config, &generated_output, &report_output_dir)?;

    let deltas = compare_dirs(&checked_in_output, &generated_output)?;
    if deltas.is_empty() {
        println!("No provenance drift.");
    } else {
        print!("{}", render_deltas(&deltas));
    }
    Ok(())
}
