//! Tools for developers, maintainers, and forensic specialists.

use crate::{
    Sq,
    Result,
    cli::toolbox::{Command, Subcommands},
};

pub mod armor;
pub mod dearmor;
pub mod extract_cert;
pub mod strip_userid;

pub fn dispatch(sq: Sq, command: Command) -> Result<()>
{
    match command.subcommand {
        Subcommands::ExtractCert(command) =>
            extract_cert::dispatch(sq, command),
        Subcommands::Armor(command) =>
            armor::dispatch(sq, command),
        Subcommands::Dearmor(command) =>
            dearmor::dispatch(sq, command),
        Subcommands::StripUserid(command) =>
            strip_userid::userid_strip(sq, command),
    }
}
