pub mod cli;
mod commands;
mod config;
mod detect;
mod drift;
mod javascript;
mod notice;
mod sbom;

pub use cli::run;
