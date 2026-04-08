pub mod cli;
mod commands;
mod config;
mod detect;
mod drift;
mod notice;
mod sbom;

pub use cli::run;
