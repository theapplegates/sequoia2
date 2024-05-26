//! Operations on certs.

use crate::{
    Sq,
    Result,
    cli::cert::{Command, Subcommands},
};

pub mod import;
pub mod export;
pub mod lint;

pub fn dispatch(sq: Sq, command: Command) -> Result<()>
{
    match command.subcommand {
        Subcommands::Import(command) =>
            import::dispatch(sq, command),

        Subcommands::Export(command) =>
            export::dispatch(sq, command),

        Subcommands::Lint(command) =>
            lint::lint(sq, command),
    }
}
