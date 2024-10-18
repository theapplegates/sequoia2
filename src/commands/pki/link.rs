use std::time::Duration;

use sequoia_openpgp as openpgp;
use openpgp::Result;

use sequoia_cert_store as cert_store;
use cert_store::Store;

use crate::Sq;
use crate::commands::active_certification;
use crate::commands::pki::TrustAmount;
use crate::parse_notations;

use crate::cli::pki::link;
use crate::cli::types::Expiration;

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

    let (cert, _from_file)
        = sq.resolve_cert(&c.cert, sequoia_wot::FULLY_TRUSTED)?;

    let vc = cert.with_policy(sq.policy, Some(sq.time))?;
    let userids = c.userids.resolve(&vc)?;

    let notations = parse_notations(c.notation)?;

    let templates = if c.temporary {
        // Make the partially trusted link one second younger.  When
        // the fully trusted link expired, then this link will come
        // into effect.  If the user has fully linked the binding in
        // the meantime, then this won't override that, which is
        // exactly what we want.
        let week = Duration::new(7 * 24 * 60 * 60, 0);

        vec![
            (TrustAmount::Other(40), c.expiration),
            (c.amount, Expiration::Duration(week)),
        ]
    } else {
        vec![
            (c.amount, c.expiration),
        ]
    };

    crate::common::pki::certify::certify(
        &sq,
        c.recreate, // Recreate.
        &trust_root,
        &cert,
        &userids[..],
        true, // Add userid.
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

    let (cert, _from_file)
        = sq.resolve_cert(&c.cert, sequoia_wot::FULLY_TRUSTED)?;

    let vc = cert.with_policy(sq.policy, Some(sq.time))?;
    let mut userids = c.userids.resolve(&vc)?;
    let user_supplied_userids = if userids.is_empty() {
        // Use all self-signed User IDs.
        userids = vc.userids()
            .map(|ua| ua.userid().clone())
            .collect::<Vec<_>>();

        if userids.is_empty() {
            return Err(anyhow::anyhow!(
                "{} has no self-signed user IDs, and you didn't provide \
                 an alternate user ID",
                vc.fingerprint()));
        }

        false
    } else {
        true
    };

    let notations = parse_notations(c.notation)?;

    crate::common::pki::certify::certify(
        &sq,
        c.recreate, // Recreate.
        &trust_root,
        &cert,
        &userids[..],
        c.userids.add_userid().unwrap_or(false),
        user_supplied_userids,
        &[(c.amount, c.expiration)][..],
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

    let (cert, _from_file)
        = sq.resolve_cert(&c.cert, sequoia_wot::FULLY_TRUSTED)?;

    let vc = cert.with_policy(sq.policy, Some(sq.time))?;
    let mut userids = c.userids.resolve(&vc)?;

    let user_supplied_userids = if userids.is_empty() {
        // Nothing was specified.  Retract all known User IDs.
        userids = cert.userids().map(|ua| ua.userid().clone()).collect();

        false
    } else {
        true
    };

    let notations = parse_notations(c.notation)?;

    crate::common::pki::certify::certify(
        &sq,
        c.recreate, // Recreate.
        &trust_root,
        &cert,
        &userids[..],
        false, // Add userid.
        user_supplied_userids,
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
    for cert in cert_store.certs() {
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
                &sq, &cert, userids, trust_root_key)
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
                continue;
            }

            if amount == 0 {
                wprintln!("{}, {:?}'s link was retracted.",
                          cert.fingerprint(),
                          String::from_utf8_lossy(userid.value()));
            } else {
                let mut params = Vec::new();

                if let Some(e) = certification.signature_expiration_time() {
                    params.push(format!(
                        "expiration: {}",
                        chrono::DateTime::<chrono::Utc>::from(e)
                            .format("%Y‑%m‑%d")));
                }

                if depth != 0 && depth != 255 {
                    params.push(format!("trust depth: {}", depth));
                }

                if amount != sequoia_wot::FULLY_TRUSTED as u8 {
                    params.push(format!("trust amount: {}", amount));
                }

                let mut regex: Vec<_> = certification.regular_expressions()
                    .map(|re| String::from_utf8_lossy(re))
                    .collect();
                regex.sort();
                regex.dedup();

                if depth > 0 {
                    if amount == sequoia_wot::FULLY_TRUSTED as u8
                        && regex.is_empty()
                    {
                        eprint!("{}, {:?} is linked as a fully trusted CA",
                                cert.fingerprint(),
                                String::from_utf8_lossy(userid.value()));
                    } else {
                        eprint!("{}, {:?} is linked as a partially trusted CA",
                                cert.fingerprint(),
                                String::from_utf8_lossy(userid.value()));
                    }
                } else {
                    eprint!("{}, {:?} is linked",
                            cert.fingerprint(),
                            String::from_utf8_lossy(userid.value()));
                }

                if ! regex.is_empty() {
                    params.push(format!("regular expressions: {}",
                                        regex.join("; ")));
                }

                if ! params.is_empty() {
                    wprintln!(": {}.", params.join(", "));
                } else {
                    wprintln!(".");
                }
            }
        }
    }

    Ok(())
}
