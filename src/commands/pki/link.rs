use std::time::Duration;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Result;
use openpgp::cert::prelude::*;
use openpgp::packet::prelude::*;

use sequoia_cert_store as cert_store;
use cert_store::Store;
use cert_store::store::UserIDQueryParams;

use crate::Sq;
use crate::commands::active_certification;
use crate::commands::pki::TrustAmount;
use crate::parse_notations;
use crate::print_error_chain;

use crate::cli::pki::link;
use crate::cli::types::Expiration;

/// Checks that the search terms provided to --userid, --email, and
/// patterns match known User IDs.
///
/// If `self_signed` is true, then only self-signed User IDs are
/// considered.
///
/// On success, returns the matching User IDs.  This includes mapping
/// email addresses to their matching User IDs.  If an email address
/// matches multiple User IDs, they are all returned.
pub fn check_userids(sq: &Sq, cert: &Cert, self_signed: bool,
                     userids: &Vec<String>, emails: &Vec<String>,
                     patterns: &Vec<String>)
    -> Result<Vec<UserID>>
{
    if userids.is_empty() && emails.is_empty() && patterns.is_empty() {
        // Nothing to do.
        return Ok(vec![]);
    }

    let mut userids = userids.iter()
        .map(|u| UserID::from(&u[..]))
        .collect::<Vec<UserID>>();

    let mut emails = emails.iter()
        .map(|email| {
            match UserIDQueryParams::is_email(email) {
                Ok(email) => {
                    // We have the normalized email address.
                    Ok(email)
                }
                Err(err) => {
                    let err = anyhow::Error::from(err).context(format!(
                        "{:?} is not a valid email address", email));
                    print_error_chain(&err);
                    Err(err)
                }
            }
        })
        .collect::<Result<Vec<String>>>()?;

    // If it looks like an email address, add it to email.  Otherwise,
    // add it to User ID.
    for pattern in patterns.iter() {
        if let Ok(email) = UserIDQueryParams::is_email(pattern) {
            emails.push(email);
        } else {
            userids.push(UserID::from(&pattern[..]));
        }
    }

    let self_signed_userids = || -> Result<Vec<UserID>> {
        let vc = cert.with_policy(sq.policy, sq.time)
            .with_context(|| {
                format!("{} is not valid according to the current policy",
                        cert.fingerprint())
            })?;
        Ok(vc.userids().map(|ua| ua.userid().clone()).collect())
    };

    let known_userids: Vec<UserID> = if self_signed {
        // Only consider User IDs that have a valid self signature.
        self_signed_userids()?
    } else {
        // Consider any known UserID.
        cert.userids().map(|ua| ua.userid().clone()).collect()
    };

    let mut results = Vec::new();
    let mut error = None;

    for userid in userids.into_iter() {
        if known_userids.iter().any(|known_userid| known_userid == &userid) {
            results.push(userid);
        } else {
            let err = anyhow::anyhow!(
                "{:?} does not match any self-signed User IDs.  If you want \
                 to use a User ID that is not endorsed by the key's owner, \
                 use \"--petname\"",
                String::from_utf8_lossy(userid.value()));
            print_error_chain(&err);
            if error.is_none() {
                error = Some(err);
            }
        }
    }

    if ! emails.is_empty() {
        let known_emails = known_userids.iter()
            .filter_map(|known_userid| {
                if let Ok(Some(email)) = known_userid.email_normalized() {
                    Some((known_userid.clone(), email))
                } else {
                    None
                }
            })
            .collect::<Vec<(UserID, String)>>();

        for email in emails.into_iter() {
            let mut matches = known_emails.iter()
                .filter_map(|(known_userid, known_email)| {
                    if known_email == &email {
                        Some(known_userid.clone())
                    } else {
                        None
                    }
                })
                .collect::<Vec<UserID>>();

            if matches.is_empty() {
                let err = anyhow::anyhow!(
                    "{:?} does not match any valid, self-signed email \
                     addresses.  If you want to use an email address that \
                     is not endorsed by the key's owner, use \"--petname\"",
                    email);
                print_error_chain(&err);
                if error.is_none() {
                    error = Some(err);
                }
            } else {
                results.append(&mut matches);
            }
        }
    }

    if let Some(err) = error {
        // Some of the search terms did not match, print some
        // diagnostics, and bail.

        if known_userids.is_empty() {
            if self_signed {
                wprintln!("{} has no self-signed User IDs.",
                          cert.fingerprint());
            } else {
                wprintln!("{} has no known User IDs.",
                          cert.fingerprint());
            }
        } else {
            if self_signed {
                wprintln!("{} has the following self-signed User IDs:",
                          cert.fingerprint());
            } else {
                wprintln!("{} has the following known User IDs:",
                          cert.fingerprint());
            }

            // Show whether a User ID is self-signed or not, unless we
            // are only interested in self-signed User IDs, in which
            // don't bother; it's redundant.
            let self_signed_userids = if self_signed {
                vec![]
            } else {
                self_signed_userids().unwrap_or(vec![])
            };

            for (i, userid) in known_userids.iter().enumerate() {
                wprintln!(
                    "  {}. {:?}{}",
                    i + 1, String::from_utf8_lossy(userid.value()),
                    if self_signed_userids.contains(userid) {
                        " (self signed)"
                    } else {
                        ""
                    });
            }
        }

        Err(err)
    } else {
        results.sort();
        results.dedup();

        Ok(results)
    }
}

pub fn link(sq: Sq, c: link::Command) -> Result<()> {
    use link::Subcommands::*;
    match c.subcommand {
        Add(c) => add(sq, c)?,
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

    let mut userids =
        check_userids(&sq, &cert, true, &c.userid, &c.email, &c.pattern)
            .context("sq pki link add: Invalid User IDs")?;
    userids.extend(c.petname.iter().map(|petname| {
        // If it is a bare email, we wrap it in angle brackets.
        if UserIDQueryParams::is_email(petname).is_ok() {
            UserID::from(&format!("<{}>", petname)[..])
        } else {
            UserID::from(&petname[..])
        }
    }));

    let vc = cert.with_policy(sq.policy, Some(sq.time))?;

    let user_supplied_userids = if userids.is_empty() {
        if c.all {
            userids = vc.userids().map(|ua| ua.userid().clone()).collect();
        } else {
            wprintln!("No User IDs specified.  \
                       Pass \"--all\" or one or more User IDs.  \
                       {}'s self-signed User IDs are:",
                      cert.fingerprint());
            for (i, userid) in vc.userids().enumerate() {
                wprintln!("  {}. {:?}",
                          i + 1,
                          String::from_utf8_lossy(userid.value()));
            }
            return Err(anyhow::anyhow!("No User IDs specified"));
        }

        false
    } else {
        true
    };

    let trust_depth: u8 = if let Some(depth) = c.depth {
        depth
    } else if ! c.ca.is_empty() {
        255
    } else {
        0
    };

    let mut regex = c.regex;
    if trust_depth == 0 && !regex.is_empty() {
        return Err(
            anyhow::format_err!("A regex only makes sense \
                                 if the trust depth is greater than 0"));
    }

    let mut star = false;
    for domain in c.ca.iter() {
        if domain == "*" {
            star = true;
        }
    }

    // If there's a catch all, we don't need to add any regular
    // expressions.
    if star {
        regex = Vec::new();
    }

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
        user_supplied_userids,
        &templates,
        trust_depth,
        if star {
            &[][..]
        } else {
            &c.ca[..]
        },
        &regex[..],
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

    let mut userids =
        check_userids(&sq, &cert, false, &c.userid, &c.email, &c.pattern)
        .context("sq pki link retract: Invalid User IDs")?;

    let user_supplied_userids = if userids.is_empty() {
        // Nothing was specified.  Retract all known User IDs.
        let vc = cert.with_policy(sq.policy, Some(sq.time))?;
        userids = vc.userids().map(|ua| ua.userid().clone()).collect();

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
                            .format("%Y-%m-%d")));
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
