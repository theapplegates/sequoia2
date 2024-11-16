//! Operations on certs.

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;

use crate::{
    Sq,
    Result,
    cli::cert::{Command, list, Subcommands},
    common::pki::authenticate,
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
            userid, pattern, gossip, certification_network, trust_amount,
            show_paths,
        }) => {
            let userid = userid.designators.into_iter().next();

            if let Some(kh) = pattern.as_ref()
                .and_then(|p| p.parse::<KeyHandle>().ok())
            {
                let cert = sq.resolve_cert(&kh.into(), 0)?.0;
                authenticate(
                    &sq, false, None,
                    *gossip, *certification_network, *trust_amount,
                    userid.as_ref(), Some(&cert), *show_paths)
            } else {
                authenticate(
                    &sq, pattern.is_none(), pattern,
                    *gossip, *certification_network, *trust_amount,
                    userid.as_ref(), None, *show_paths)
            }
        }

        Subcommands::Lint(command) =>
            lint::lint(sq, command),
    }
}
