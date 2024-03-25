//! Tools for developers, maintainers, and forensic specialists.

use crate::{
    Config,
    Result,
    cli::toolbox::{Command, Subcommands},
};

pub mod armor;
pub mod dearmor;
pub mod extract_cert;
pub mod keyring;
pub mod packet;

pub fn dispatch(config: Config, command: Command) -> Result<()>
{
    match command.subcommand {
        Subcommands::Keyring(command) =>
            keyring::dispatch(config, command),
        Subcommands::Packet(command) =>
            packet::dispatch(config, command),
        Subcommands::ExtractCert(command) =>
            extract_cert::dispatch(config, command),
        Subcommands::Armor(command) =>
            armor::dispatch(config, command),
        Subcommands::Dearmor(command) =>
            dearmor::dispatch(config, command),
    }
}
