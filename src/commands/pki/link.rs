use std::{
    sync::Arc,
    time::Duration,
};

use sequoia_openpgp as openpgp;
use openpgp::Result;

use sequoia_cert_store as cert_store;
use cert_store::{LazyCert, Store};

use crate::Sq;
use crate::commands::active_certification;
use crate::common::NULL_POLICY;
use crate::parse_notations;

use crate::cli::pki::link;
use crate::cli::types::Expiration;
use crate::cli::types::TrustAmount;

pub fn link(sq: Sq, c: link::Command) -> Result<()> {
    use link::Subcommands::*;
    match c.subcommand {
        Add(c) => add(sq, c)?,
        Authorize(c) => authorize(sq, c)?,
        Retract(c) => retract(sq, c)?,
        List(c) => list(sq, c)?,
    }
    Ok(())
}

pub fn add(sq: Sq, c: link::AddCommand)
    -> Result<()>
{
    let trust_root = sq.local_trust_root()?;
    let trust_root = trust_root.to_cert()?;

    let (cert, _source)
        = sq.resolve_cert(&c.cert, sequoia_wot::FULLY_TRUSTED)?;

    let vc = cert.with_policy(sq.policy, Some(sq.time))?;
    let userids = c.userids.resolve(&vc)?;

    let notations = parse_notations(c.notation)?;

    let templates: Vec<(TrustAmount<_>, Expiration)> = if c.temporary {
        // Make the partially trusted link one second younger.  When
        // the fully trusted link expired, then this link will come
        // into effect.  If the user has fully linked the binding in
        // the meantime, then this won't override that, which is
        // exactly what we want.
        let week = Duration::new(7 * 24 * 60 * 60, 0);

        vec![
            (TrustAmount::Other(40), c.expiration.value()),
            (c.amount, Expiration::from_duration(week)),
        ]
    } else {
        vec![
            (c.amount, c.expiration.value()),
        ]
    };

    crate::common::pki::certify::certify(
        &sq,
        c.recreate, // Recreate.
        &trust_root,
        &cert,
        &userids[..],
        true, // User-supplied user IDs.
        &templates,
        0, // Trust depth.
        &[][..], // Domain.
        &[][..], // Regex.
        true, // Local.
        false, // Non-revocable.
        &notations[..],
        None, // Output.
        false) // Binary.
}

pub fn authorize(sq: Sq, c: link::AuthorizeCommand)
    -> Result<()>
{
    let trust_root = sq.local_trust_root()?;
    let trust_root = trust_root.to_cert()?;

    let (cert, _source)
        = sq.resolve_cert(&c.cert, sequoia_wot::FULLY_TRUSTED)?;

    let vc = cert.with_policy(sq.policy, Some(sq.time))?;
    let userids = c.userids.resolve(&vc)?;

    let notations = parse_notations(c.notation)?;

    crate::common::pki::certify::certify(
        &sq,
        c.recreate, // Recreate.
        &trust_root,
        &cert,
        &userids[..],
        true, // User supplied user IDs.
        &[(c.amount, c.expiration.value())][..],
        c.depth,
        &c.domain[..],
        &c.regex[..],
        true, // Local.
        false, // Non-revocable.
        &notations[..],
        None, // Output.
        false) // Binary.
}

pub fn retract(sq: Sq, c: link::RetractCommand)
    -> Result<()>
{
    let trust_root = sq.local_trust_root()?;
    let trust_root = trust_root.to_cert()?;

    let (cert, _source)
        = sq.resolve_cert(&c.cert, sequoia_wot::FULLY_TRUSTED)?;

    let vc = cert.with_policy(NULL_POLICY, Some(sq.time))?;
    let userids = c.userids.resolve(&vc)?;

    let notations = parse_notations(c.notation)?;

    crate::common::pki::certify::certify(
        &sq,
        c.recreate, // Recreate.
        &trust_root,
        &cert,
        &userids[..],
        true, // User supplied user IDs.
        &[(TrustAmount::None, Expiration::Never)],
        0,
        &[][..], &[][..], // Domain, regex.
        true, // Local.
        false, // Non-revocable.
        &notations[..],
        None, // Output.
        false) // Binary.
}

pub fn list(sq: Sq, c: link::ListCommand)
    -> Result<()>
{
    let cert_store = sq.cert_store_or_else()?;
    cert_store.prefetch_all();

    let trust_root = sq.local_trust_root()?;
    let trust_root = trust_root.to_cert()?;
    let trust_root_key = trust_root.primary_key().key().role_as_unspecified();

    let cert_store = sq.cert_store_or_else()?;
    let mut dirty = false;

    let (certs, errors) = if c.certs.is_empty() {
        (cert_store.certs(), Vec::new())
    } else {
        let (c, e) = sq.resolve_certs(&c.certs, 0)?;
        (Box::new(c.into_iter().map(|c| Arc::new(LazyCert::from(c))))
         as Box<dyn Iterator<Item=Arc<LazyCert<'_>>>>,
         e)
    };

    for error in errors.iter() {
        crate::print_error_chain(error);
    }
    if ! errors.is_empty() {
        return Err(anyhow::anyhow!("Failed to resolve certificates"));
    }

    for cert in certs {
        let cert = if let Ok(cert) = cert.to_cert() {
            cert
        } else {
            // Invalid cert.  Skip it.
            continue;
        };

        let userids = cert.userids()
            .map(|ua| ua.userid().clone())
            .collect::<Vec<_>>();

        for (userid, certification) in active_certification(
                &sq, &cert, userids.iter(), trust_root_key)
            .into_iter()
            .filter_map(|(user, certification)| {
                if let Some(certification) = certification {
                    Some((user, certification))
                } else {
                    None
                }
            })
        {
            let (depth, amount) = certification.trust_signature()
                .unwrap_or((0, sequoia_wot::FULLY_TRUSTED as u8));

            if c.ca && depth == 0 {
                // Only show CAs.
                continue;
            }

            if dirty {
                weprintln!();
            }
            dirty = true;

            weprintln!(initial_indent=" - ┌ ", subsequent_indent="   │ ",
                       "{}", cert.fingerprint());
            weprintln!(initial_indent="   └ ",
                       "{:?}", String::from_utf8_lossy(userid.value()));

            const INDENT: &'static str = "     - ";

            if amount == 0 {
                weprintln!(initial_indent=INDENT, "link was retracted");
            } else {
                let mut regex: Vec<_> = certification.regular_expressions()
                    .map(|re| String::from_utf8_lossy(re))
                    .collect();
                regex.sort();
                regex.dedup();

                let summary = if depth > 0 {
                    if amount == sequoia_wot::FULLY_TRUSTED as u8
                        && regex.is_empty()
                    {
                        "is linked as a fully trusted CA"
                    } else {
                        "is linked as a partially trusted CA"
                    }
                } else {
                    "is linked"
                };
                weprintln!(initial_indent=INDENT, "{}", summary);

                if let Some(e) = certification.signature_expiration_time() {
                    weprintln!(initial_indent=INDENT,
                               "expiration: {}",
                               chrono::DateTime::<chrono::Utc>::from(e)
                               .format("%Y‑%m‑%d"));
                }

                if depth != 0 && depth != 255 {
                    weprintln!(initial_indent=INDENT,
                               "trust depth: {}", depth);
                }

                if amount != sequoia_wot::FULLY_TRUSTED as u8 {
                    weprintln!(initial_indent=INDENT,
                               "trust amount: {}", amount);
                }

                if ! regex.is_empty() {
                    weprintln!(initial_indent=INDENT,
                               "regular expressions: {}", regex.join("; "));
                }
            }
        }
    }

    Ok(())
}
