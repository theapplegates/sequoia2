use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Fingerprint;
use openpgp::Result;
use openpgp::types::RevocationStatus;
use openpgp::packet::UserID;

use sequoia_wot as wot;
use wot::store::Backend;
use wot::store::Store;

use crate::cli;
use cli::types::TrustAmount;
use cli::types::userid_designator;

use super::output::ConciseHumanReadableOutputNetwork;
use super::output::OutputType;

use crate::Sq;

const TRACE: bool = false;

pub fn required_trust_amount(trust_amount: Option<TrustAmount<usize>>,
                             certification_network: bool)
    -> Result<usize>
{
    let amount = if let Some(v) = &trust_amount {
        v.amount()
    } else {
        if certification_network {
            // Look for multiple paths.  Specifically, try to find 10
            // paths.
            10 * wot::FULLY_TRUSTED
        } else {
            wot::FULLY_TRUSTED
        }
    };

    Ok(amount)
}

// Returns whether there is a matching self-signed User ID.
fn have_self_signed_userid(cert: &Cert,
                           pattern: &UserID, email: bool)
    -> bool
{
    if email {
        if let Ok(Some(pattern)) = pattern.email_normalized() {
            // userid contains a valid email address.
            cert.userids().any(|u| {
                if let Ok(Some(userid)) = u.userid().email_normalized() {
                    pattern == userid
                } else {
                    false
                }
            })
        } else {
            false
        }
    } else {
        cert.userids().any(|u| u.userid() == pattern)
    }
}

/// Authenticate bindings defined by a Query on a Network
///
/// If `gossip` is specified, paths that are not rooted are still
/// shown (with a trust amount of 0, of course).
pub fn authenticate<'store, 'rstore>(
    sq: &Sq<'store, 'rstore>,
    precompute: bool,
    list_pattern: Option<String>,
    gossip: bool,
    certification_network: bool,
    trust_amount: Option<TrustAmount<usize>>,
    userid_designator: Option<&userid_designator::UserIDDesignator>,
    certificate: Option<&Cert>,
    show_paths: bool,
) -> Result<()>
    where 'store: 'rstore,
{
    tracer!(TRACE, "authenticate");

    // Build the network.
    let cert_store = match sq.cert_store() {
        Ok(Some(cert_store)) => cert_store,
        Ok(None) => {
            return Err(anyhow::anyhow!("Certificate store has been disabled"));
        }
        Err(err) => {
            return Err(err).context("Opening certificate store");
        }
    };

    if precompute {
        cert_store.precompute();
    }

    let mut n = wot::NetworkBuilder::rooted(cert_store, &*sq.trust_roots());
    if certification_network {
        n = n.certification_network();
    }
    let n = n.build();

    let required_amount =
        required_trust_amount(trust_amount, certification_network)?;

    let fingerprint: Option<Fingerprint> = certificate.map(|c| c.fingerprint());

    let email = userid_designator.map(|u| u.is_email()).unwrap_or(false);
    let userid = userid_designator.map(|u| u.value());

    let mut bindings = Vec::new();
    if matches!(userid, Some(_)) && email {
        t!("Authenticating email: {:?}", userid);

        let email = userid.expect("required");

        let userid_check = UserID::from(format!("<{}>", email));
        if let Ok(Some(email_check)) = userid_check.email2() {
            if email != email_check {
                return Err(anyhow::anyhow!(
                    "{:?} does not appear to be an email address",
                    email));
            }
        } else {
            return Err(anyhow::anyhow!(
                "{:?} does not appear to be an email address",
                email));
        }

        // Now, iterate over all of the certifications of the target,
        // and select the bindings where the User ID matches the email
        // address.
        bindings = if let Some(fingerprint) = fingerprint.as_ref() {
            n.certified_userids_of(fingerprint)
                .into_iter()
                .map(|userid| (fingerprint.clone(), userid))
                .collect::<Vec<_>>()
        } else {
            n.lookup_synopses_by_email(&email)
        };

        let email_normalized = userid_check.email_normalized()
            .expect("checked").expect("checked");
        bindings = bindings.into_iter()
            .filter_map(|(fingerprint, userid_other)| {
                if let Ok(Some(email_other_normalized))
                    = userid_other.email_normalized()
                {
                    if email_normalized == email_other_normalized {
                        Some((fingerprint, userid_other.clone()))
                    } else {
                        None
                    }
                } else {
                    None
                }
            }).collect();
    } else if let Some(fingerprint) = fingerprint.as_ref() {
        if let Some(userid) = userid {
            t!("Authenticating {}, {:?}", fingerprint, userid);
            bindings.push((fingerprint.clone(), UserID::from(userid)));
        } else {
            // Fingerprint, no User ID.
            t!("Authenticating {}", fingerprint);
            bindings = n.certified_userids_of(&fingerprint)
                .into_iter()
                .map(|userid| (fingerprint.clone(), userid))
                .collect();
        }
    } else if let Some(userid) = userid {
        // The caller did not specify a certificate.  Find all
        // bindings with the User ID.
        t!("Authenticating user ID: {:?}", userid);
        bindings = n.lookup_synopses_by_userid(UserID::from(userid))
            .into_iter()
            .map(|fpr| (fpr, UserID::from(userid)))
            .collect();
    } else {
        // No User ID, no Fingerprint.
        // List everything.
        t!("Authenticating everything");

        bindings = n.certified_userids();

        if let Some(ref pattern) = list_pattern {
            // Or rather, just User IDs that match the pattern.
            let pattern = pattern.to_lowercase();

            bindings = bindings
                .into_iter()
                .filter(|(_fingerprint, userid)| {
                    if email {
                        // Compare with the normalized email address,
                        // and the raw email address.
                        if let Ok(Some(email)) = userid.email_normalized() {
                            // A normalized email is already lowercase.
                            if email.contains(&pattern) {
                                return true;
                            }
                        }

                        if let Ok(Some(email)) = userid.email2() {
                            if email.to_lowercase().contains(&pattern) {
                                return true;
                            }
                        }

                        return false;
                    } else if let Ok(userid)
                        = std::str::from_utf8(userid.value())
                    {
                        userid.to_lowercase().contains(&pattern)
                    } else {
                        // Ignore User IDs with invalid UTF-8.
                        false
                    }
                })
                .collect();
        }
    };

    // There may be multiple certifications of the same
    // User ID.  Dedup.
    bindings.sort();
    bindings.dedup();

    let mut authenticated = 0;
    let mut bindings_shown = 0;
    let mut lint_input = true;

    let mut output = ConciseHumanReadableOutputNetwork::new(
        &sq, required_amount, show_paths);

    for (fingerprint, userid) in bindings.iter() {
        let paths = if gossip {
            n.gossip(fingerprint.clone(), userid.clone())
        } else {
            n.authenticate(
                userid.clone(), fingerprint.clone(), required_amount)
        };

        let aggregated_amount = paths.amount();
        if certificate.is_some() && userid_designator.is_none()
            && list_pattern.is_none()
        {
            // We're authenticating a certificate, which was
            // specified.  We don't consider it authenticated, but we
            // do want to show it.
        } else if aggregated_amount == 0 && ! gossip {
            // We didn't authenticate the binding, and we're not in
            // gossip mode.  Don't show it.
            continue;
        }

        lint_input = false;
        if gossip {
            authenticated += 1;
        } else if aggregated_amount >= required_amount {
            authenticated += 1;
        }

        bindings_shown += 1;
        let paths = paths.into_iter().collect::<Vec<(wot::Path, usize)>>();

        output.add_paths(paths, fingerprint, userid, aggregated_amount)?;
    }

    output.finalize()?;

    // We didn't show anything.  Try to figure out what was wrong.
    if lint_input {
        // See if the target certificate exists.
        if let Some(cert) = certificate {
            match cert.with_policy(sq.policy, sq.time) {
                Ok(vc) => {
                    // The certificate is valid under the current
                    // policy.

                    // Check if the certificate has expired.
                    if let Err(err) = vc.alive() {
                        wprintln!("Warning: {} is not live: {}.",
                                  cert.fingerprint(), err);
                    }
                }
                Err(err) => {
                    wprintln!("Warning: {} is not valid according to \
                               the current policy: {}.",
                              cert.fingerprint(),
                              crate::one_line_error_chain(err));
                }
            };

            // Check if the certificate was revoked.
            if let RevocationStatus::Revoked(sigs)
                = cert.revocation_status(sq.policy, sq.time)
            {
                if let Some((reason, message))
                    = sigs[0].reason_for_revocation()
                {
                    wprintln!("Warning: {} is revoked: {}{}",
                              cert.fingerprint(),
                              reason,
                              if message.is_empty() {
                                  "".to_string()
                              } else {
                                  format!(": {:?}",
                                          String::from_utf8_lossy(message))
                              });
                } else {
                    wprintln!("Warning: {} is revoked: unspecified reason",
                              cert.fingerprint());
                }
            }

            // See if there is a matching self-signed User ID.
            if let Some(userid) = userid {
                if ! have_self_signed_userid(cert, &UserID::from(userid), email) {
                    wprintln!("Warning: {} is not a \
                               self-signed User ID for {}.",
                              userid, cert.fingerprint());
                }
            }

            // See if there are any certifications made on
            // this certificate.
            if let Ok(cs) = n.certifications_of(&cert.fingerprint(), 0.into()) {
                if cs.iter().all(|cs| {
                    cs.certifications()
                        .all(|(_userid, certifications)| {
                            certifications.is_empty()
                        })
                })
                {
                    wprintln!("Warning: {} has no valid certifications.",
                              cert.fingerprint());
                }
            }
        }

        // Perhaps the caller specified an email address, but forgot
        // to add --email.  If --email is not present and the
        // specified User ID looks like an email, try and be helpful.
        if ! email {
            if let Some(userid) = userid {
                let userid_check = UserID::from(format!("<{}>", email));
                if let Ok(Some(email_check)) = userid_check.email2() {
                    if userid == email_check {
                        wprintln!("WARNING: {} appears to be a bare \
                                   email address.  Perhaps you forgot \
                                   to specify --email.",
                                  email);
                    }
                }
            }
        }

        // See if the trust roots exist.
        if ! gossip {
            if n.roots().iter().all(|r| {
                let fpr = r.fingerprint();
                if let Err(err) = n.lookup_synopsis_by_fpr(&fpr) {
                    wprintln!("Looking up trust root ({}): {}.",
                             fpr, err);
                    true
                } else {
                    false
                }
            })
            {
                wprintln!("No trust roots found.");
            }
        }
    }

    let pattern = || {
        certificate.map(|kh| kh.to_string())
            .or_else(|| userid.map(|u| {
                u.to_string()
            }))
            .or_else(|| list_pattern.clone())
    };

    if gossip {
        // We are in gossip mode.  Mention `sq pki link` as a way to
        // mark bindings as authenticated.
        if ! bindings.is_empty() {
            wprintln!("After checking that a user ID really belongs to \
                       a certificate, use `sq pki link add` to mark \
                       the binding as authenticated, or use \
                       `sq network fetch FINGERPRINT|EMAIL` to look for \
                       new certifications.");
        }
    } else if bindings.is_empty() {
        // There are no matching bindings.  Tell the user about `sq
        // network fetch`.
        if let Some(pattern) = pattern() {
            wprintln!("No bindings match.");

            sq.hint(format_args!(
                "Try searching public directories:"))
                .sq().arg("network").arg("search")
                .arg(pattern)
                .done();
        } else {
            wprintln!("The certificate store does not contain any \
                       certificates.");

            sq.hint(format_args!(
                "Consider creating a key for yourself:"))
                .sq().arg("key").arg("generate")
                .arg_value("--name", "your-name")
                .arg_value("--email", "your-email-address")
                .done();

            sq.hint(format_args!(
                "Consider importing other peoples' certificates:"))
                .sq().arg("cert").arg("import")
                .arg("a-cert-file.pgp")
                .done();

            sq.hint(format_args!(
                "Try searching public directories for other peoples' \
                 certificates:"))
                .sq().arg("network").arg("search")
                .arg("some-mail-address")
                .done();
        }
    } else if bindings.len() - bindings_shown > 0 {
        // Some of the matching bindings were not shown.  Tell the
        // user about the `--gossip` option.
        let bindings = bindings.len();
        assert!(bindings > 0);
        let bindings_not_shown = bindings - bindings_shown;

        if bindings == 1 {
            wprintln!("1 binding found.");
        } else {
            wprintln!("{} bindings found.", bindings);
        }

        if bindings_not_shown == 1 {
            wprintln!("Skipped 1 binding, which could not be authenticated.");
            wprintln!("Pass `--gossip` to see the unauthenticated binding.");
        } else {
            wprintln!("Skipped {} bindings, which could not be authenticated.",
                      bindings_not_shown);
            wprintln!("Pass `--gossip` to see the unauthenticated bindings.");
        }
    }

    if authenticated == 0 {
        if ! lint_input {
            Err(anyhow::anyhow!("Could not authenticate any paths."))
        } else if bindings.is_empty() {
            Err(anyhow::anyhow!("No bindings match the query."))
        } else {
            Err(anyhow::anyhow!("Could not authenticate any matching bindings."))
        }
    } else {
        Ok(())
    }
}
