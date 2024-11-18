//! Tools for developers, maintainers, and forensic specialists.

use crate::{
    Sq,
    Result,
    cli::toolbox::{Command, Subcommands},
};

pub mod extract_cert;

pub fn dispatch(sq: Sq, command: Command) -> Result<()>
{
    match command.subcommand {
        Subcommands::ExtractCert(command) =>
            extract_cert::dispatch(sq, command),
    }
}
