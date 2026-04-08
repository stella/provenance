use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use ignore::WalkBuilder;
use miette::{IntoDiagnostic, Result};
use similar::TextDiff;

#[derive(Debug)]
pub struct FileDelta {
    pub path: PathBuf,
    pub expected: Option<String>,
    pub actual: Option<String>,
}

pub fn compare_dirs(expected_root: &Path, actual_root: &Path) -> Result<Vec<FileDelta>> {
    let expected_paths = collect_files(expected_root)?;
    let actual_paths = collect_files(actual_root)?;

    let all_paths = expected_paths
        .union(&actual_paths)
        .cloned()
        .collect::<BTreeSet<_>>();

    let mut deltas = Vec::new();

    for relative in all_paths {
        let expected_path = expected_root.join(&relative);
        let actual_path = actual_root.join(&relative);
        let expected = read_optional(&expected_path)?;
        let actual = read_optional(&actual_path)?;
        if expected != actual {
            deltas.push(FileDelta {
                path: relative,
                expected,
                actual,
            });
        }
    }

    Ok(deltas)
}

pub fn render_deltas(deltas: &[FileDelta]) -> String {
    let mut out = String::new();
    for delta in deltas {
        out.push_str(&format!("=== {} ===\n", delta.path.display()));
        match (&delta.expected, &delta.actual) {
            (Some(expected), Some(actual)) => {
                let diff = TextDiff::from_lines(expected, actual);
                out.push_str(
                    &diff
                        .unified_diff()
                        .header("checked-in", "generated")
                        .to_string(),
                );
            }
            (Some(_), None) => out.push_str("File is missing from generated output.\n"),
            (None, Some(_)) => out.push_str("Generated output contains an extra file.\n"),
            (None, None) => {}
        }
        if !out.ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

fn collect_files(root: &Path) -> Result<BTreeSet<PathBuf>> {
    if !root.exists() {
        return Ok(BTreeSet::new());
    }

    let mut files = BTreeSet::new();
    let mut walker = WalkBuilder::new(root);
    walker.hidden(false);
    walker.git_ignore(false);
    walker.git_global(false);
    walker.git_exclude(false);

    for entry in walker.build() {
        let entry = entry.into_diagnostic()?;
        if !entry
            .file_type()
            .is_some_and(|file_type| file_type.is_file())
        {
            continue;
        }
        if let Ok(relative) = entry.path().strip_prefix(root) {
            files.insert(relative.to_path_buf());
        }
    }

    Ok(files)
}

fn read_optional(path: &Path) -> Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path).into_diagnostic()?;
    Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
}
