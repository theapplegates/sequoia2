use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;

use anyhow::Context;

use chrono::DateTime;
use chrono::Utc;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Result;
use openpgp::packet::prelude::*;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::packet::signature::subpacket::NotationDataFlags;
use openpgp::serialize::Serialize;
use openpgp::types::RevocationStatus;
use openpgp::types::SignatureType;

use sequoia_cert_store as cert_store;
use cert_store::StoreUpdate;
use cert_store::store::UserIDQueryParams;

use crate::Sq;
use crate::cli::types::Expiration;
use crate::cli::types::FileOrStdout;
use crate::cli::types::TrustAmount;
use crate::cli::types::userid_designator::ResolvedUserID;
use crate::commands::active_certification;

// Returns whether two certifications have the same parameters.
//
// This does some normalization and only considers things that are
// relevant to certifications:
//
//   - Expiration time
//   - Trust depth
//   - Trust amount
//   - Regular expressions
//   - Notations
//   - Exportable
pub fn diff_certification(o: &mut dyn std::io::Write,
                          sq: &Sq, old: &Signature, new: &SignatureBuilder,
                          new_ct: SystemTime)
    -> bool
{
    make_qprintln!(o, sq.quiet());
    let mut changed = false;

    let a_expiration = old.signature_expiration_time();
    let b_expiration = if let Some(vp) = new.signature_validity_period() {
        Some(new_ct + vp)
    } else {
        None
    };
    if a_expiration != b_expiration {
        changed = true;
        qprintln!(
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
        qprintln!("  Updating trust amount: {} -> {}.",
                  a_amount, b_amount);
    }
    if a_depth != b_depth {
        changed = true;
        qprintln!("  Updating trust depth: {} -> {}.",
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
        qprintln!("  Updating regular expressions:");
        let a_regex: Vec<String> = a_regex.into_iter()
            .enumerate()
            .map(|(i, r)| {
                format!("{}. {:?}",
                        i + 1, String::from_utf8_lossy(r))
            })
            .collect();
        qprintln!("    Current certification:\n      {}",
                  a_regex.join("\n      "));

        let b_regex: Vec<String> = b_regex.into_iter()
            .enumerate()
            .map(|(i, r)| {
                format!("{}. {:?}",
                        i + 1, String::from_utf8_lossy(r))
            })
            .collect();
        qprintln!("    New certification:\n      {}",
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
        qprintln!("  Updating notations.");
        let a_notations: Vec<String> = a_notations.into_iter()
            .enumerate()
            .map(|(i, n)| {
                format!("{}. {:?}", i + 1, n)
            })
            .collect();
        qprintln!("    Current certification:\n      {}",
                  a_notations.join("\n      "));

        let b_notations: Vec<String> = b_notations.into_iter()
            .enumerate()
            .map(|(i, n)| {
                format!("{}. {:?}", i + 1, n)
            })
            .collect();
        qprintln!("    Updated certification:\n       {}",
                  b_notations.join("\n      "));
    }

    let a_exportable = old.exportable_certification().unwrap_or(true);
    let b_exportable = new.exportable_certification().unwrap_or(true);
    if a_exportable != b_exportable {
        changed = true;
        qprintln!("  Updating exportable flag: {} -> {}.",
                  a_exportable, b_exportable);
    }

    changed
}

/// This function is used for certifications and retractions.
///
/// If the trust amount is 0, the operation is interpreted as a
/// retraction and the wording is changed accordingly.
pub fn certify(o: &mut dyn std::io::Write,
               sq: &Sq,
               recreate: bool,
               certifier: &Cert,
               cert: &Cert,
               userids: &[ResolvedUserID],
               user_supplied_userids: bool,
               templates: &[(TrustAmount<u8>, Expiration)],
               trust_depth: u8,
               domain: &[String],
               regex: &[String],
               local: bool,
               non_revocable: bool,
               notations: &[(bool, NotationData)],
               output: Option<FileOrStdout>,
               binary: bool)
    -> Result<()>
{
    assert!(templates.len() > 0);
    assert!(userids.len() > 0);
    make_qprintln!(o, sq.quiet());

    if certifier.fingerprint() == cert.fingerprint() {
        sq.hint(
            format_args!("\
The certificate to certify is the same as the certificate being certified. \
If you are trying to add a user ID, try:"))
            .sq().arg("key").arg("userid").arg("add")
            .arg("--cert").arg(cert.fingerprint())
            .arg("--userid").arg(userids[0].userid())
            .done();

        return Err(
            anyhow::format_err!("\
The certifier is the same as the certificate to certify."));
    }

    if trust_depth == 0 && !regex.is_empty() {
        return Err(
            anyhow::format_err!("A regex constraint only makes sense \
                                 if the trust depth is greater than 0"));
    }

    // Get the signer to certify with.
    let mut signer = sq.get_certification_key(certifier, None)?;

    let mut base
        = SignatureBuilder::new(SignatureType::GenericCertification)
        .set_signature_creation_time(sq.time)?;

    for domain in domain {
        if let Err(err) = UserIDQueryParams::is_domain(domain) {
            return Err(err).context(format!(
                "{:?} is not a valid domain", domain));
        }

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

        let mut domain = domain.to_string();
        for (c, e) in CONTROL.iter() {
            domain = domain.replace(c, e);
        }

        base = base.add_regular_expression(format!("<[^>]+[@.]{}>$", domain))?;
    }
    for regex in regex {
        base = base.add_regular_expression(regex)?;
    }

    if local {
        base = base.set_exportable_certification(false)?;
    }

    if non_revocable {
        base = base.set_revocable(false)?;
    }

    for (critical, n) in notations {
        base = base.add_notation(
            n.name(),
            n.value(),
            NotationDataFlags::empty().set_human_readable(),
            *critical)?;
    };

    let mut retract = false;

    let mut builders = Vec::with_capacity(templates.len());
    for (i, (trust_amount, expiration)) in templates.into_iter().enumerate() {
        let mut builder = base.clone();

        let trust_amount: u8 = trust_amount.amount();
        if trust_amount == 0 {
            retract = true;
        }
        if trust_depth != 0 || trust_amount != 120 {
            builder = builder.set_trust_signature(
                trust_depth, trust_amount)?;
        }

        // Creation time.
        //
        // If we should make two certifications, then the first one
        // should be at `sq.time - 1`, and the second one at
        // `sq.time`.  That is, the first one is a second earlier.
        let backdate = Duration::new((templates.len() - 1 - i) as u64, 0);
        let ct = sq.time - backdate;
        builder = builder.set_signature_creation_time(ct)?;

        // Expiration.
        if let Some(validity) = expiration
            .as_duration(DateTime::<Utc>::from(sq.time))?
        {
            builder = builder.set_signature_validity_period(validity)?;
        }

        builders.push(builder);
    }

    // Get the active certification as of the reference time.
    let certifications = active_certification(
            &sq, &cert, userids.iter(),
            certifier.primary_key().key().role_as_unspecified())
        .into_iter()
        .map(|(userid, active_certification)| {
            let userid_str = || String::from_utf8_lossy(userid.userid().value());

            if let Some(ua) = cert.userids().find(|ua| ua.userid() == userid.userid()) {
                if retract {
                    // Check if we certified it.
                    if ! ua.certifications().any(|c| {
                        c.get_issuers().into_iter()
                            .any(|issuer| issuer.aliases(&certifier.key_handle()))
                    })
                    {
                        qprintln!("You never certified {:?} for {}, \
                                   there is nothing to retract.",
                                  userid_str(), cert.fingerprint());
                        if user_supplied_userids {
                            return Err(anyhow::anyhow!(
                                "You never certified {:?} for {}, \
                                 there is nothing to retract.",
                                userid_str(), cert.fingerprint()));
                        } else {
                            return Ok(vec![ Packet::from(userid.userid().clone()) ]);
                        }
                    }
                } else {
                    if let RevocationStatus::Revoked(_)
                        = ua.revocation_status(sq.policy, sq.time)
                    {
                        // It's revoked.
                        if user_supplied_userids {
                            // It was explicitly mentioned.  Return an
                            // error.
                            return Err(anyhow::anyhow!(
                                "Can't certify {:?} for {}, it's revoked",
                                userid_str(), cert.fingerprint()));
                        } else {
                            // We're just considering valid, self-signed
                            // user IDs.  Silently, skip it.
                            return Ok(vec![]);
                        }
                    }
                }
            } else if userid.existing() {
                if retract {
                    qprintln!("You never certified {:?} for {}, \
                               there is nothing to retract.",
                              userid_str(), cert.fingerprint());
                    if user_supplied_userids {
                        return Err(anyhow::anyhow!(
                            "You never certified {:?} for {}, \
                             there is nothing to retract.",
                            userid_str(), cert.fingerprint()));
                    } else {
                        // Return a signature packet to indicate that we
                        // processed something.  But don't return a
                        // signature.
                        return Ok(vec![ Packet::from(userid.userid().clone()) ]);
                    }
                } else {
                    return Err(anyhow::anyhow!(
                        "{:?} is NOT a self-signed user ID.",
                        userid_str()));
                }
            }

            if let Some(active_certification) = active_certification {
                let active_certification_ct
                    = active_certification.signature_creation_time()
                    .expect("valid signature");

                let retracted = matches!(active_certification.trust_signature(),
                                         Some((_depth, 0)));
                if retracted {
                    qprintln!("A prior certification for {}, {} was retracted at {}.",
                              cert.fingerprint(), userid_str(),
                              chrono::DateTime::<chrono::offset::Utc>::from(
                                  active_certification_ct));
                } else {
                    qprintln!("{}, {} was previously certified at {}.",
                              cert.fingerprint(), userid_str(),
                              chrono::DateTime::<chrono::offset::Utc>::from(
                                  active_certification_ct));
                }

                let changed = diff_certification(
                    o,
                    &sq,
                    &active_certification,
                    &builders[0], sq.time);

                if ! changed {
                    qprintln!("  Certification parameters are unchanged.");

                    if ! recreate {
                        // Return a signature packet to indicate that we
                        // processed something.  But don't return a
                        // signature.
                        return Ok(vec![ Packet::from(userid.userid().clone()) ]);
                    }
                } else {
                    qprintln!("  Parameters changed, creating a new certification.");
                }
            }

            if retract {
                qprintln!("Retracting {:?} for {}.",
                          userid_str(), cert.fingerprint());
            } else {
                qprintln!("Certifying {:?} for {}.",
                          userid_str(), cert.fingerprint());
            }

            let mut sigs = builders.iter()
                .map(|builder| {
                    builder.clone().sign_userid_binding(
                        &mut signer,
                        cert.primary_key().key(),
                        userid.userid())
                        .with_context(|| {
                            format!("Creating certification for {:?}",
                                    userid_str())
                        })
                        .map(Into::into)
                })
                .collect::<Result<Vec<Packet>>>()?;

            qprintln!();

            let mut packets = vec![ Packet::from(userid.userid().clone()) ];
            packets.append(&mut sigs);
            Ok(packets)
        })
        .collect::<Result<Vec<Vec<Packet>>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<Packet>>();

    if certifications.is_empty() {
        if retract {
            return Err(anyhow::anyhow!(
                "Can't retract links for {}.  There is nothing to retract.",
                cert.fingerprint()));
        } else {
            return Err(anyhow::anyhow!(
                "Can't certify {}.  The certificate has no self-signed \
                 user IDs and you didn't specify any user IDs to certify.",
                cert.fingerprint()));
        }
    }

    if certifications.iter().all(|p| matches!(p, Packet::UserID(_))) {
        // There are no signatures to insert.  We're done.
        return Ok(());
    }

    let cert = cert.clone().insert_packets(certifications)?;

    if let Some(output) = output {
        // And export it.
        let path = output.path().map(Clone::clone);
        let mut message = output.create_pgp_safe(
            &sq,
            binary,
            sequoia_openpgp::armor::Kind::PublicKey,
        )?;
        cert.serialize(&mut message)?;
        message.finalize()?;

        if ! local {
            if let Some(path) = path {
                sq.hint(format_args!(
                    "Updated certificate written to {}.  \
                     To make the update effective, it has to be published \
                     so that others can find it, for example using:",
                    path.display()))
                    .sq().arg("network").arg("keyserver").arg("publish")
                    .arg_value("--cert-file", path.display())
                    .done();
            } else {
                sq.hint(format_args!(
                    "To make the update effective, it has to be published \
                     so that others can find it."));
            }
        }
    } else {
        // Import it.
        let cert_store = sq.cert_store_or_else()?;

        let fipr = cert.fingerprint();
        if let Err(err) = cert_store.update(Arc::new(cert.into())) {
            weprintln!("Error importing updated cert: {}", err);
            return Err(err);
        } else if ! local {
            sq.hint(format_args!(
                "Imported updated cert into the cert store.  \
                 To make the update effective, it has to be published \
                 so that others can find it, for example using:"))
                .sq().arg("network").arg("keyserver").arg("publish")
                .arg_value("--cert", fipr)
                .done();
        }
    }

    Ok(())
}
