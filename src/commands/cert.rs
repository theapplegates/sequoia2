//! Operations on certs.

use sequoia_openpgp as openpgp;
use openpgp::{
    Fingerprint,
    KeyHandle,
};

use crate::{
    Sq,
    Result,
    cli::cert::{Command, list, Subcommands},
    cli::types::cert_designator,
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
            mut certs, pattern, gossip, certification_network, trust_amount,
            show_paths,
        }) => {
            if let Some(pattern) = pattern {
                let mut d = None;
                if let Ok(kh) = pattern.parse::<KeyHandle>() {
                    if matches!(kh, KeyHandle::Fingerprint(Fingerprint::Invalid(_))) {
                        let hex = pattern.chars()
                            .map(|c| {
                                if c == ' ' { 0 } else { 1 }
                            })
                            .sum::<usize>();

                        if hex >= 16 {
                            weprintln!("Warning: {} looks like a fingerprint or key ID, \
                                        but its invalid.  Treating it as a text pattern.",
                                       pattern);
                        }
                    } else {
                        d = Some(cert_designator::CertDesignator::Cert(kh));
                    }
                };

                certs.push(d.unwrap_or_else(|| {
                    cert_designator::CertDesignator::Grep(pattern)
                }));
            }

            let certs = sq.resolve_certs_or_fail(
                &certs, trust_amount.map(|t| t.amount())
                    .unwrap_or(sequoia_wot::FULLY_TRUSTED))?;

            authenticate(
                &mut std::io::stdout(),
                &sq, certs.is_empty(), None,
                *gossip, *certification_network, *trust_amount,
                None, None,
                (! certs.is_empty()).then_some(certs),
                *show_paths)
        },

        Subcommands::Lint(command) =>
            lint::lint(sq, command),
    }
}
