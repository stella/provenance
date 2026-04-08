use std::path::PathBuf;

use clap::{Parser, Subcommand};
use miette::Result;

use crate::commands;

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "OSS-first compliance CLI for JavaScript and Rust repositories",
    long_about = None
)]
pub struct Cli {
    #[arg(long, global = true, default_value = ".")]
    pub root: PathBuf,

    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    #[arg(long, global = true)]
    pub output_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Discover projects and create a starter config file.
    Init {
        #[arg(long)]
        force: bool,
    },
    /// Generate compliance artifacts from the current config.
    Generate,
    /// Fail if generated compliance artifacts drift from checked-in outputs.
    Check,
    /// Show the current diff between generated and checked-in outputs.
    Diff,
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { force } => commands::init::run(cli.root, cli.config, force),
        Commands::Generate => commands::generate::run(cli.root, cli.config, cli.output_dir),
        Commands::Check => commands::check::run(cli.root, cli.config, cli.output_dir),
        Commands::Diff => commands::diff::run(cli.root, cli.config, cli.output_dir),
    }
}
