//! Operations on certs.

use crate::{
    Config,
    Result,
    cli::cert::{Command, Subcommands},
};

pub mod import;
pub mod export;

pub fn dispatch(config: Config, command: Command) -> Result<()>
{
    match command.subcommand {
        Subcommands::Import(command) =>
            import::dispatch(config, command),

        Subcommands::Export(command) =>
            export::dispatch(config, command),
    }
}
