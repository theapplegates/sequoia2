use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Context;

use chrono::DateTime;
use chrono::Utc;

use sequoia_openpgp as openpgp;
use openpgp::Result;
use openpgp::cert::prelude::*;
use openpgp::packet::prelude::*;
use openpgp::packet::signature::subpacket::NotationDataFlags;
use openpgp::types::RevocationStatus;
use openpgp::types::SignatureType;

use sequoia_cert_store as cert_store;
use cert_store::Store;
use cert_store::StoreUpdate;
use cert_store::store::UserIDQueryParams;

use crate::Config;
use crate::commands::active_certification;
use crate::commands::get_certification_keys;
use crate::parse_notations;
use crate::print_error_chain;

use crate::cli::pki::link;

/// Checks that the search terms provided to --userid, --email, and
/// patterns match known User IDs.
///
/// If `self_signed` is true, then only self-signed User IDs are
/// considered.
///
/// On success, returns the matching User IDs.  This includes mapping
/// email addresses to their matching User IDs.  If an email address
/// matches multiple User IDs, they are all returned.
pub fn check_userids(config: &Config, cert: &Cert, self_signed: bool,
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
        let vc = cert.with_policy(config.policy, config.time)
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

// Returns whether two signatures have the same parameters.
//
// This does some normalization and only considers things that are
// relevant to links.
fn diff_link(old: &Signature, new: &SignatureBuilder, new_ct: SystemTime)
    -> bool
{
    let mut changed = false;

    let a_expiration = old.signature_expiration_time();
    let b_expiration = if let Some(vp) = new.signature_validity_period() {
        Some(new_ct + vp)
    } else {
        None
    };
    if a_expiration != b_expiration {
        changed = true;
        wprintln!(
            "  Updating expiration time: {} -> {}.",
            if let Some(a_expiration) = a_expiration {
                chrono::DateTime::<chrono::offset::Utc>::from(
                    a_expiration).to_string()
            } else {
                "no expiration".to_string()
            },
            if let Some(b_expiration) = b_expiration {
                chrono::DateTime::<chrono::offset::Utc>::from(
                    b_expiration).to_string()
            } else {
                "no expiration".to_string()
            });
    }

    let (a_depth, a_amount) = old.trust_signature().unwrap_or((0, 120));
    let (b_depth, b_amount) = new.trust_signature().unwrap_or((0, 120));

    if a_amount != b_amount {
        changed = true;
        wprintln!("  Updating trust amount: {} -> {}.",
                  a_amount, b_amount);
    }
    if a_depth != b_depth {
        changed = true;
        wprintln!("  Update trust depth: {} -> {}.",
                  a_depth, b_depth);
    }

    let mut a_regex: Vec<_> = old.regular_expressions().collect();
    a_regex.sort();
    a_regex.dedup();
    let mut b_regex: Vec<_> = new.regular_expressions().collect();
    b_regex.sort();
    b_regex.dedup();

    if a_regex != b_regex {
        changed = true;
        wprintln!("  Updating regular expressions:");
        let a_regex: Vec<String> = a_regex.into_iter()
            .enumerate()
            .map(|(i, r)| {
                format!("{}. {:?}",
                        i + 1, String::from_utf8_lossy(r))
            })
            .collect();
        wprintln!("    Current link:\n      {}",
                  a_regex.join("\n      "));

        let b_regex: Vec<String> = b_regex.into_iter()
            .enumerate()
            .map(|(i, r)| {
                format!("{}. {:?}",
                        i + 1, String::from_utf8_lossy(r))
            })
            .collect();
        wprintln!("    Updated link:\n      {}",
                  b_regex.join("\n      "));
    }

    let a_notations: Vec<_> = old.notation_data()
        .filter(|n| n.name() != "salt@notations.sequoia-pgp.org")
        .collect();
    let b_notations: Vec<_> = new.notation_data()
        .filter(|n| n.name() != "salt@notations.sequoia-pgp.org")
        .collect();
    if a_notations != b_notations {
        changed = true;
        wprintln!("  Updating notations.");
        let a_notations: Vec<String> = a_notations.into_iter()
            .enumerate()
            .map(|(i, n)| {
                format!("{}. {:?}", i + 1, n)
            })
            .collect();
        wprintln!("    Current link:\n      {}",
                  a_notations.join("\n      "));

        let b_notations: Vec<String> = b_notations.into_iter()
            .enumerate()
            .map(|(i, n)| {
                format!("{}. {:?}", i + 1, n)
            })
            .collect();
        wprintln!("    Updated link:\n       {}",
                  b_notations.join("\n      "));
    }

    let a_exportable = old.exportable_certification().unwrap_or(true);
    let b_exportable = new.exportable_certification().unwrap_or(true);
    if a_exportable != b_exportable {
        changed = true;
        wprintln!("  Updating exportable flag: {} -> {}.",
                  a_exportable, b_exportable);
    }

    changed
}

pub fn link(config: Config, c: link::Command) -> Result<()> {
    use link::Subcommands::*;
    match c.subcommand {
        Add(c) => add(config, c)?,
        Retract(c) => retract(config, c)?,
        List(c) => list(config, c)?,
    }
    Ok(())
}

pub fn add(config: Config, c: link::AddCommand)
    -> Result<()>
{
    let trust_root = config.local_trust_root()?;
    let trust_root = trust_root.to_cert()?;

    let cert = config.lookup_one(&c.certificate, None, true)?;

    let mut userids =
        check_userids(&config, &cert, true, &c.userid, &c.email, &c.pattern)
            .context("sq pki link add: Invalid User IDs")?;
    userids.extend(c.petname.iter().map(|petname| {
        // If it is a bare email, we wrap it in angle brackets.
        if UserIDQueryParams::is_email(petname).is_ok() {
            UserID::from(&format!("<{}>", petname)[..])
        } else {
            UserID::from(&petname[..])
        }
    }));

    let vc = cert.with_policy(config.policy, Some(config.time))?;

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
    let trust_amount: u8 = c.amount.amount();

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

        if let Err(err) = UserIDQueryParams::is_domain(&domain) {
            return Err(err).context(format!(
                "{:?} is not a valid domain", domain));
        }
    }

    // If there's a catch all, we don't need to add any regular
    // expressions.
    if star {
        regex = Vec::new();
    } else {
        for mut domain in c.ca.into_iter() {
            // Escape any control characters.
            const CONTROL: &[(&str, &str)] = &[
                (".", "\\."),
                ("|", "\\|"),
                ("(", "\\("),
                (")", "\\)"),
                ("*", "\\*"),
                ("+", "\\+"),
                ("?", "\\?"),
                ("^", "\\^"),
                ("$", "\\$"),
                ("[", "\\["),
                ("]", "\\]"),
            ];
            for (c, e) in CONTROL.iter() {
                domain = domain.replace(c, e);
            }

            regex.push(format!("<[^>]+[@.]{}>$", domain));
        }
    }

    // Create the certification.
    let mut builder
        = SignatureBuilder::new(SignatureType::GenericCertification);

    if trust_depth != 0 || trust_amount != 120 {
        builder = builder.set_trust_signature(trust_depth, trust_amount)?;
    }

    for regex in regex {
        builder = builder.add_regular_expression(regex)?;
    }

    builder = builder.set_exportable_certification(false)?;

    // Creation time.
    builder = builder.set_signature_creation_time(config.time)?;

    let notations = parse_notations(c.notation)?;
    for (critical, n) in notations {
        builder = builder.add_notation(
            n.name(),
            n.value(),
            NotationDataFlags::empty().set_human_readable(),
            critical)?;
    };

    let builders: Vec<SignatureBuilder> = if c.temporary {
        // Make the partially trusted link one second younger.  When
        // the fully trusted link expired, then this link will come
        // into effect.  If the user has fully linked the binding in
        // the meantime, then this won't override that, which is
        // exactly what we want.
        let mut partial = builder.clone();
        partial = partial.set_signature_creation_time(
            config.time - Duration::new(1, 0))?;
        partial = partial.set_trust_signature(trust_depth, 40)?;

        builder = builder.set_signature_validity_period(
            Duration::new(7 * 24 * 60 * 60, 0))?;

        vec![ builder, partial ]
    } else {
        if let Some(validity) = c
            .expiry
            .as_duration(DateTime::<Utc>::from(config.time))? {
            builder = builder.set_signature_validity_period(validity)?;
        }
        vec![ builder ]
    };

    // Sign it.
    let keys = get_certification_keys(
        &[trust_root], config.policy, None, Some(config.time), None)
        .context("Looking up local trust root")?;
    assert!(
        keys.len() == 1,
        "Expect exactly one result from get_certification_keys()"
    );
    let mut signer = keys.into_iter().next().unwrap().0;

    let certifications = active_certification(
            &config, &vc.fingerprint(), userids,
            signer.public())
        .into_iter()
        .map(|(userid, active_certification)| {
            let userid_str = || String::from_utf8_lossy(userid.value());

            if let Some(ua) = vc.userids().find(|ua| ua.userid() == &userid) {
                if let RevocationStatus::Revoked(_) = ua.revocation_status() {
                    // It's revoked.
                    if user_supplied_userids {
                        // It was explicitly mentioned.  Return an
                        // error.
                        return Err(anyhow::anyhow!(
                            "Can't link {:?} with {}, it's revoked",
                            userid_str(), cert.fingerprint()));
                    } else {
                        // We're just considering valid, self-signed
                        // User IDs.  Silently, skip it.
                        return Ok(vec![]);
                    }
                }
            } else {
                wprintln!("Note: {:?} is NOT a self signed User ID.  \
                           If this was a mistake, use \
                           `sq pki link retract {} \"{}\"` to undo it.",
                          userid_str(), cert.fingerprint(), userid);
            }

            if let Some(active_certification) = active_certification {
                let active_certification_ct
                    = active_certification.signature_creation_time()
                    .expect("valid signature");

                let retracted = matches!(active_certification.trust_signature(),
                                         Some((_depth, 0)));
                if retracted {
                    wprintln!("{}, {} was retracted at {}.",
                              cert.fingerprint(), userid_str(),
                              chrono::DateTime::<chrono::offset::Utc>::from(
                                  active_certification_ct));
                } else {
                    wprintln!("{}, {} was already linked at {}.",
                              cert.fingerprint(), userid_str(),
                              chrono::DateTime::<chrono::offset::Utc>::from(
                                  active_certification_ct));
                }

                let changed = diff_link(
                    &active_certification,
                    &builders[0], config.time);

                if ! changed && config.force {
                    wprintln!("  Link parameters are unchanged, but \
                               updating anyway as \"--force\" was specified.");
                } else if c.temporary {
                    wprintln!("  Creating a temporary link, \
                               which expires in a week.");
                } else if ! changed {
                    wprintln!("  Link parameters are unchanged, no update \
                               needed (specify \"--force\" to update anyway).");

                    // Return a signature packet to indicate that we
                    // processed something.  But don't return a
                    // signature.
                    return Ok(vec![ Packet::from(userid.clone()) ]);
                } else {
                    wprintln!("  Link parameters changed, updating link.");
                }
            }

            wprintln!("Linking {} and {:?}.",
                      cert.fingerprint(), userid_str());

            let mut sigs = builders.iter()
                .map(|builder| {
                    builder.clone().sign_userid_binding(
                        &mut signer,
                        cert.primary_key().key(),
                        &userid)
                        .with_context(|| {
                            format!("Creating certification for {:?}",
                                    userid_str())
                        })
                        .map(Into::into)
                })
                .collect::<Result<Vec<Packet>>>()?;

            wprintln!();

            let mut packets = vec![ Packet::from(userid.clone()) ];
            packets.append(&mut sigs);
            Ok(packets)
        })
        .collect::<Result<Vec<Vec<Packet>>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<Packet>>();

    if certifications.is_empty() {
        return Err(anyhow::anyhow!(
            "Can't link {} to anything.  The certificate has no self-signed \
             User IDs and you didn't specify any User IDs to link to it.",
            cert.fingerprint()));
    }

    if certifications.iter().all(|p| matches!(p, Packet::UserID(_))) {
        // There are no signatures to insert.  We're done.
        return Ok(());
    }

    let cert = cert.insert_packets(certifications.clone())?;

    let cert_store = config.cert_store_or_else()?;
    cert_store.update(Arc::new(cert.into()))
        .with_context(|| format!("Updating {}", c.certificate))?;

    Ok(())
}

pub fn retract(config: Config, c: link::RetractCommand)
    -> Result<()>
{
    let trust_root = config.local_trust_root()?;
    let trust_root = trust_root.to_cert()?;
    let trust_root_kh = trust_root.key_handle();

    let cert = config.lookup_one(&c.certificate, None, true)?;

    let mut userids =
        check_userids(&config, &cert, false, &c.userid, &c.email, &c.pattern)
        .context("sq pki link retract: Invalid User IDs")?;

    // Nothing was specified.  Retract all known User IDs.
    if userids.is_empty() {
        let vc = cert.with_policy(config.policy, Some(config.time))?;
        userids = vc.userids().map(|ua| ua.userid().clone()).collect();
    }

    // Create the certification.
    let mut builder
        = SignatureBuilder::new(SignatureType::GenericCertification);

    builder = builder.set_trust_signature(0, 0)?;
    builder = builder.set_exportable_certification(false)?;

    // Creation time.
    builder = builder.set_signature_creation_time(config.time)?;

    let notations = parse_notations(c.notation)?;
    for (critical, n) in notations {
        builder = builder.add_notation(
            n.name(),
            n.value(),
            NotationDataFlags::empty().set_human_readable(),
            critical)?;
    };

    // Sign it.
    let keys = get_certification_keys(
        &[trust_root], config.policy, None, Some(config.time), None)
        .context("Looking up local trust root")?;
    assert!(
        keys.len() == 1,
        "Expect exactly one result from get_certification_keys()"
    );
    let mut signer = keys.into_iter().next().unwrap().0;

    let certifications = active_certification(
            &config, &cert.fingerprint(), userids, signer.public())
        .into_iter()
        .map(|(userid, active_certification)| {
            let userid_str = || String::from_utf8_lossy(userid.value());

            if let Some(ua) = cert.userids().find(|ua| ua.userid() == &userid) {
                if ! ua.certifications().any(|c| {
                    c.get_issuers().into_iter()
                        .any(|issuer| issuer.aliases(&trust_root_kh))
                })
                {
                    wprintln!("You never linked {:?} to {}, \
                               no need to retract it.",
                              userid_str(), cert.fingerprint());
                    return Ok(vec![]);
                }
            }

            if let Some(active_certification) = active_certification {
                let active_certification_ct
                    = active_certification.signature_creation_time()
                    .expect("valid signature");

                let retracted = matches!(active_certification.trust_signature(),
                                         Some((_depth, 0)));
                if retracted {
                    wprintln!("{}, {} was already retracted at {}.",
                              cert.fingerprint(), userid_str(),
                              chrono::DateTime::<chrono::offset::Utc>::from(
                                  active_certification_ct));
                } else {
                    wprintln!("{}, {} was linked at {}.",
                              cert.fingerprint(), userid_str(),
                              chrono::DateTime::<chrono::offset::Utc>::from(
                                  active_certification_ct));
                }

                let changed = diff_link(
                    &active_certification,
                    &builder, config.time);

                if ! changed && config.force {
                    wprintln!("  Link parameters are unchanged, but \
                               updating anyway as \"--force\" was specified.");
                } else if ! changed {
                    wprintln!("  Link parameters are unchanged, no update \
                               needed (specify \"--force\" to update anyway).");

                    // Return a signature packet to indicate that we
                    // processed something.  But don't return a
                    // signature.
                    return Ok(vec![ Packet::from(userid.clone()) ]);
                } else {
                    wprintln!("  Link parameters changed, updating link.");
                }
            } else if config.force {
                wprintln!("There is no link to retract between {} and {:?}, \
                           retracting anyways as \"--force\" was specified.",
                          cert.fingerprint(), userid_str());
            } else {
                wprintln!("There is no link to retract between {} and {:?} \
                           (specify \"--force\" to mark as retracted anyways).",
                          cert.fingerprint(), userid_str());

                // Return a signature packet to indicate that we
                // processed something.  But don't return a
                // signature.
                return Ok(vec![ Packet::from(userid.clone()) ]);
            }

            wprintln!("Breaking link between {} and {:?}.",
                      cert.fingerprint(), userid_str());

            // XXX: If we already have exactly this signature (modulo
            // the creation time), then don't add it!  Note: it is
            // explicitly NOT enough to check that there is a
            // certification from the local trust root.

            let sig = builder.clone().sign_userid_binding(
                &mut signer,
                cert.primary_key().key(),
                &userid)
                .with_context(|| {
                    format!("Creating certification for {:?}", userid_str())
                })?;

            Ok(vec![ Packet::from(userid.clone()), Packet::from(sig) ])
        })
        .collect::<Result<Vec<Vec<Packet>>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<Packet>>();

    if certifications.is_empty() {
        wprintln!("Nothing to retract.");
        return Ok(());
    }

    let cert = cert.insert_packets(certifications.clone())?;

    let cert_store = config.cert_store_or_else()?;
    cert_store.update(Arc::new(cert.into()))
        .with_context(|| format!("Updating {}", c.certificate))?;

    Ok(())
}

pub fn list(config: Config, c: link::ListCommand)
    -> Result<()>
{
    let cert_store = config.cert_store_or_else()?;
    cert_store.prefetch_all();

    let trust_root = config.local_trust_root()?;
    let trust_root = trust_root.to_cert()?;
    let trust_root_key = trust_root.primary_key().key().role_as_unspecified();

    let cert_store = config.cert_store_or_else()?;
    for cert in cert_store.certs() {
        for (userid, certification) in active_certification(
                &config, &cert.fingerprint(), cert.userids().collect(),
                trust_root_key)
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
                        "expiry: {}",
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
