//! Operations on certs.

use crate::{
    Sq,
    Result,
    cli::cert::{Command, list, Subcommands},
    commands::pki::authenticate,
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

        // List all authenticated bindings.
        Subcommands::List(list::Command {
            email, gossip, certification_network, trust_amount,
            pattern, show_paths,
        }) => if let Some(handle) = pattern.as_ref()
            .and_then(|p| p.parse().ok())
            .iter().filter(|_| ! *email).next()
        {
            // A key handle was given as pattern and --email was not
            // given.  Act like `sq pki identify`.
            authenticate(
                &sq, false, None,
                false, *gossip, *certification_network, *trust_amount,
                None, Some(&handle), *show_paths)
        } else {
            authenticate(
                &sq, pattern.is_none(), pattern,
                *email, *gossip, *certification_network, *trust_amount,
                None, None, *show_paths)
        },

        Subcommands::Lint(command) =>
            lint::lint(sq, command),
    }
}
