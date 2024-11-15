use sequoia_openpgp as openpgp;
use openpgp::Result;

pub mod link;
pub mod path;
pub mod vouch;

use crate::cli;
use cli::types::TrustAmount;

use crate::Sq;
use crate::common::pki::authenticate;

pub fn dispatch(sq: Sq, cli: cli::pki::Command) -> Result<()> {
    tracer!(TRACE, "pki::dispatch");

    use cli::pki::*;
    match cli.subcommand {
        // Authenticate a given binding.
        Subcommands::Authenticate(authenticate::Command {
            email, gossip, certification_network, trust_amount,
            cert, userid, show_paths,
        }) => {
            let cert = sq.resolve_cert(&cert, 0)?.0;

            authenticate(
                &sq, false, None,
                *email, *gossip, *certification_network, *trust_amount,
                Some(&userid), Some(&cert), *show_paths,
            )?
        }

        // Find all authenticated bindings for a given User ID, list
        // the certificates.
        Subcommands::Lookup(lookup::Command {
            email, gossip, certification_network, trust_amount,
            userid, show_paths,
        }) => authenticate(
            &sq, false, None,
            *email, *gossip, *certification_network, *trust_amount,
            Some(&userid), None, *show_paths)?,

        // Find and list all authenticated bindings for a given
        // certificate.
        Subcommands::Identify(identify::Command {
            gossip, certification_network, trust_amount,
            cert, show_paths,
        }) => {
            let cert = sq.resolve_cert(&cert, 0)?.0;

            authenticate(
                &sq, false, None,
                false, *gossip, *certification_network, *trust_amount,
                None, Some(&cert), *show_paths)?;
        }

        // Authenticates a given path.
        Subcommands::Path(command) =>
            self::path::path(sq, command)?,

        Subcommands::Vouch(command) =>
            self::vouch::vouch(sq, command)?,

        Subcommands::Link(command) =>
            self::link::link(sq, command)?,
    }

    Ok(())
}
