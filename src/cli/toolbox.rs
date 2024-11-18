//! Command-line parser for `sq toolbox`.

use clap::{Parser, Subcommand};

pub mod extract_cert;

#[derive(Parser, Debug)]
#[clap(
    name = "toolbox",
    about = "Tools for developers, maintainers, and forensic specialists",
    long_about =
"Tools for developers, maintainers, and forensic specialists

This is a collection of low-level tools to inspect and manipulate \
OpenPGP data structures.
",
    subcommand_required = true,
    arg_required_else_help = true,
    disable_help_subcommand = true,
)]
pub struct Command {
    #[clap(subcommand)]
    pub subcommand: Subcommands,
}

#[derive(Debug, Subcommand)]
pub enum Subcommands {
    ExtractCert(extract_cert::Command),
}
