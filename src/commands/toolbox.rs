//! Operations on certs.

use crate::{
    Config,
    Result,
    cli::toolbox::{Command, Subcommands},
};

pub mod armor;
pub mod dearmor;
pub mod packet;

pub fn dispatch(config: Config, command: Command) -> Result<()>
{
    match command.subcommand {
        Subcommands::Packet(command) =>
            packet::dispatch(config, command),
        Subcommands::Armor(command) =>
            armor::dispatch(config, command),
        Subcommands::Dearmor(command) =>
            dearmor::dispatch(config, command),
    }
}
