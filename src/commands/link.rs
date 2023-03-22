use std::borrow::Cow;
use std::time::SystemTime;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Result;
use openpgp::cert::prelude::*;
use openpgp::packet::prelude::*;
use openpgp::packet::signature::subpacket::NotationDataFlags;
use openpgp::types::RevocationStatus;
use openpgp::types::SignatureType;

use sequoia_cert_store as cert_store;
use cert_store::StoreUpdate;
use cert_store::store::UserIDQueryParams;

use crate::Config;
use crate::commands::get_certification_keys;
use crate::parse_duration;
use crate::parse_notations;
use crate::print_error_chain;

use crate::sq_cli::link;

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
        let vc = cert.with_policy(&config.policy, config.time)
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
            let err = anyhow::anyhow!(format!(
                "{:?} does not match any self-signed User IDs.  If you want \
                 to use a User ID that is not endorsed by the key's owner, \
                 use \"--petname\"",
                String::from_utf8_lossy(userid.value())));
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
                let err = anyhow::anyhow!(format!(
                    "{:?} does not match any valid, self-signed email \
                     addresses.  If you want to use an email address that \
                     is not endorsed by the key's owner, use \"--petname\"",
                    email));
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
                eprintln!("{} has no self-signed User IDs.",
                          cert.fingerprint());
            } else {
                eprintln!("{} has no known User IDs.",
                          cert.fingerprint());
            }
        } else {
            if self_signed {
                eprintln!("{} has the following self-signed User IDs:",
                          cert.fingerprint());
            } else {
                eprintln!("{} has the following known User IDs:",
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
                eprintln!(
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

pub fn link(config: Config, c: link::Command) -> Result<()> {
    use link::Subcommands::*;
    match c.subcommand {
        Add(c) => add(config, c)?,
        Retract(c) => retract(config, c)?,
    }
    Ok(())
}

pub fn add(mut config: Config, c: link::AddCommand)
    -> Result<()>
{
    let trust_root = config.local_trust_root()?;

    let cert = config.lookup_one(&c.certificate, None, true)?;

    let mut userids =
        check_userids(&config, &cert, true, &c.userid, &c.email, &c.pattern)
            .context("sq link add: Invalid User IDs")?;
    userids.extend(c.petname.iter().map(|petname| {
        // If it is a bare email, we wrap it in angle brackets.
        if UserIDQueryParams::is_email(petname).is_ok() {
            UserID::from(&format!("<{}>", petname)[..])
        } else {
            UserID::from(&petname[..])
        }
    }));

    let vc = cert.with_policy(&config.policy, Some(config.time))?;

    let user_supplied_userids = if userids.is_empty() {
        userids = vc.userids().map(|ua| ua.userid().clone()).collect();
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
    let trust_amount: u8 = c.amount;

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

    let expires = c.expires;
    let expires_in = c.expires_in;

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

    match (expires, expires_in) {
        (None, None) =>
            // Default expiration: never.
            (),
        (Some(t), None) if t == "never" =>
            // The default is no expiration; there is nothing to do.
            (),
        (Some(t), None) => {
            let expiration = SystemTime::from(
                crate::parse_iso8601(
                    &t, chrono::NaiveTime::from_hms_opt(0, 0, 0).unwrap())?);
            let validity = expiration.duration_since(config.time)?;
            builder = builder.set_signature_validity_period(validity)?;
        },
        (None, Some(d)) if d == "never" =>
            // The default is no expiration; there is nothing to do.
            (),
        (None, Some(d)) => {
            let d = parse_duration(&d)?;
            builder = builder.set_signature_validity_period(d)?;
        },
        (Some(_), Some(_)) => unreachable!("conflicting args"),
    }

    let notations = parse_notations(c.notation)?;
    for (critical, n) in notations {
        builder = builder.add_notation(
            n.name(),
            n.value(),
            NotationDataFlags::empty().set_human_readable(),
            critical)?;
    };

    // Sign it.
    let signers = get_certification_keys(
        &[trust_root], &config.policy, None, Some(config.time), None)
        .context("Looking up local trust root")?;
    assert_eq!(signers.len(), 1);
    let mut signer = signers.into_iter().next().unwrap();

    let certifications = userids.iter()
        .map(|userid| {
            let userid_str = || String::from_utf8_lossy(userid.value());

            if let Some(ua) = vc.userids().find(|ua| ua.userid() == userid) {
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
                eprintln!("Note: {:?} is NOT a self signed User ID.  \
                           If this was a mistake, use \
                           `sq link retract {} \"{}\"` to undo it.",
                          userid_str(), cert.fingerprint(), userid);
            }

            eprintln!("Linking {:?} and {}.",
                      userid_str(), cert.fingerprint());

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
        return Err(anyhow::anyhow!(
            "Can't link {} to anything.  The certificate has no self-signed \
             User IDs and you didn't specify any User IDs to link to it.",
            cert.fingerprint()));
    }

    let cert = cert.insert_packets(certifications.clone())?;

    let cert_store = config.cert_store_mut_or_else()?;
    cert_store.update(Cow::Owned(cert.into()))
        .with_context(|| format!("Updating {}", c.certificate))?;

    Ok(())
}

pub fn retract(mut config: Config, c: link::RetractCommand)
    -> Result<()>
{
    let trust_root = config.local_trust_root()?;
    let trust_root_kh = trust_root.key_handle();

    let cert = config.lookup_one(&c.certificate, None, true)?;

    let mut userids =
        check_userids(&config, &cert, false, &c.userid, &c.email, &c.pattern)
        .context("sq link retract: Invalid User IDs")?;

    // Nothing was specified.  Retract all known User IDs.
    if userids.is_empty() {
        let vc = cert.with_policy(&config.policy, Some(config.time))?;
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
    let signers = get_certification_keys(
        &[trust_root], &config.policy, None, Some(config.time), None)
        .context("Looking up local trust root")?;
    assert_eq!(signers.len(), 1);
    let mut signer = signers.into_iter().next().unwrap();

    let certifications = userids.iter()
        .map(|userid| {
            let userid_str = || String::from_utf8_lossy(userid.value());

            if let Some(ua) = cert.userids().find(|ua| ua.userid() == userid) {
                if ! ua.certifications().any(|c| {
                    c.get_issuers().into_iter()
                        .any(|issuer| issuer.aliases(&trust_root_kh))
                })
                {
                    eprintln!("You never linked {:?} to {}, \
                               no need to retract it.",
                              userid_str(), cert.fingerprint());
                    return Ok(vec![]);
                }
            }

            eprintln!("Breaking link between {:?} and {}.",
                      userid_str(), cert.fingerprint());

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
        eprintln!("Nothing to retract.");
        return Ok(());
    }

    let cert = cert.insert_packets(certifications.clone())?;

    let cert_store = config.cert_store_mut_or_else()?;
    cert_store.update(Cow::Owned(cert.into()))
        .with_context(|| format!("Updating {}", c.certificate))?;

    Ok(())
}
