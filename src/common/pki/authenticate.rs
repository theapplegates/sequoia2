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

use crate::{
    Sq,
    common::ui,
};

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
    o: &mut dyn std::io::Write,
    sq: &Sq<'store, 'rstore>,
    precompute: bool,
    list_pattern: Option<String>,
    gossip: bool,
    certification_network: bool,
    trust_amount: Option<TrustAmount<usize>>,
    userid_designator: Option<&userid_designator::UserIDDesignator>,
    certificate: Option<&Cert>,
    certs: Option<Vec<Cert>>,
    show_paths: bool,
) -> Result<()>
    where 'store: 'rstore,
{
    tracer!(TRACE, "authenticate");

    // Build the network.
    let cert_store = sq.cert_store_or_else()?;
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

    // If email is true, then userid is an unbracketed email address.
    let userid_;
    let (userid, email) = if let Some(designator) = userid_designator {
        t!("User ID: {:?}", designator);

        use userid_designator::UserIDDesignator::*;
        use userid_designator::UserIDDesignatorSemantics::*;
        match designator {
            UserID(_semantics, userid) => {
                (Some(&userid[..]), false)
            }
            Email(Exact | Add, email) => {
                // Exactly the email address.
                userid_ = format!("<{}>", email);
                (Some(&userid_[..]), false)
            }
            Email(By, email) => {
                // Match all user IDs with the specified email
                // address.
                (Some(&email[..]), true)
            }
            Name(_semantics, _name) => {
                unimplemented!("--name not implement");
            }
        }
    } else {
        (None, false)
    };

    let mut bindings: Vec<(Fingerprint, Option<UserID>)> = Vec::new();
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
                .map(|userid| (fingerprint.clone(), Some(userid)))
                .collect::<Vec<_>>()
        } else {
            n.lookup_synopses_by_email(&email)
                .into_iter()
                .map(|(fp, userid)| (fp, Some(userid)))
                .collect()
        };

        let email_normalized = userid_check.email_normalized()
            .expect("checked").expect("checked");
        bindings = bindings.into_iter()
            .filter_map(|(fingerprint, userid_other)| {
                if let Some(email_other_normalized)
                    = userid_other.as_ref()
                    .and_then(|u| u.email_normalized().ok())
                    .flatten()
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
            bindings.push((fingerprint.clone(), Some(UserID::from(userid))));
        } else {
            // Fingerprint, no User ID.
            t!("Authenticating {}", fingerprint);
            bindings = n.certified_userids_of(&fingerprint)
                .into_iter()
                .map(|userid| (fingerprint.clone(), Some(userid)))
                .collect();
        }
    } else if let Some(userid) = userid {
        // The caller did not specify a certificate.  Find all
        // bindings with the User ID.
        t!("Authenticating user ID: {:?}", userid);
        bindings = n.lookup_synopses_by_userid(UserID::from(userid))
            .into_iter()
            .map(|fpr| (fpr, Some(UserID::from(userid))))
            .collect();
    } else if let Some(certs) = &certs {
        // List all certs.
        t!("Authenticating given certs");
        bindings = certs.iter().flat_map(|cert| {
            let fp = cert.fingerprint();
            let userids = n.certified_userids_of(&fp);
            if userids.is_empty() {
                Box::new(std::iter::once((fp, None)))
                    as Box<dyn Iterator<Item = (Fingerprint, Option<UserID>)>>
            } else {
                Box::new(userids.into_iter()
                         .map(move |uid| (fp.clone(), Some(uid))))
            }
        }).collect();
    } else {
        // No User ID, no Fingerprint.
        // List everything.
        t!("Authenticating everything");

        bindings = n.certified_userids()
            .into_iter()
            .map(|(fp, userid)| (fp, Some(userid)))
            .collect();

        if let Some(ref pattern) = list_pattern {
            // Or rather, just User IDs that match the pattern.
            let pattern = pattern.to_lowercase();

            bindings = bindings
                .into_iter()
                .filter(|(_fingerprint, userid)| {
                    if email {
                        // Compare with the normalized email address,
                        // and the raw email address.
                        if let Some(email) = userid.as_ref()
                            .and_then(|u| u.email_normalized().ok())
                            .flatten()
                        {
                            // A normalized email is already lowercase.
                            if email.contains(&pattern) {
                                return true;
                            }
                        }

                        if let Some(email) = userid.as_ref()
                            .and_then(|u| u.email2().ok())
                            .flatten()
                        {
                            if email.to_lowercase().contains(&pattern) {
                                return true;
                            }
                        }

                        return false;
                    } else if let Some(userid) = userid.as_ref()
                        .and_then(|u| std::str::from_utf8(u.value()).ok())
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
        o, &sq, required_amount, show_paths);

    for (fingerprint, userid) in bindings.iter() {
        let userid = if let Some(u) = userid {
            u
        } else {
            // A cert without bindings.  This was provided explicitly
            // via `certs`, is therefore authenticated, and we want to
            // display it.
            output.add_cert(fingerprint)?;
            bindings_shown += 1;
            authenticated += 1;
            continue;
        };

        let paths = if gossip {
            n.gossip(fingerprint.clone(), userid.clone())
        } else {
            n.authenticate(
                userid.clone(), fingerprint.clone(), required_amount)
        };

        let aggregated_amount = paths.amount();
        if (certificate.is_some()
            || certs.as_ref().map(|c| ! c.is_empty()).unwrap_or(false))
            && userid_designator.is_none()
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

        output.add_cert(fingerprint)?;
        output.add_paths(paths, fingerprint, userid, aggregated_amount)?;
    }

    output.finalize()?;

    // We didn't show anything.  Try to figure out what was wrong.
    if lint_input {
        // See if the target certificate exists.
        for cert in certificate.iter().cloned().chain(certs.iter().flatten()) {
            match cert.with_policy(sq.policy, sq.time) {
                Ok(vc) => {
                    // The certificate is valid under the current
                    // policy.

                    // Check if the certificate has expired.
                    if let Err(err) = vc.alive() {
                        weprintln!("Warning: {} is not live: {}.",
                                   cert.fingerprint(), err);
                    }
                }
                Err(err) => {
                    weprintln!("Warning: {} is not valid according to \
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
                    weprintln!("Warning: {} is revoked: {}{}",
                               cert.fingerprint(),
                               reason,
                               ui::Safe(message));
                } else {
                    weprintln!("Warning: {} is revoked: unspecified reason",
                               cert.fingerprint());
                }
            }

            // See if there is a matching self-signed User ID.
            if let Some(userid) = userid {
                if ! have_self_signed_userid(cert, &UserID::from(userid), email) {
                    weprintln!("Warning: {} is not a \
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
                    weprintln!("Warning: {} has no valid certifications.",
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
                        weprintln!("WARNING: {} appears to be a bare \
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
                    weprintln!("Looking up trust root ({}): {}.",
                               fpr, err);
                    true
                } else {
                    false
                }
            })
            {
                weprintln!("No trust roots found.");
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
            weprintln!("After checking that a user ID really belongs to \
                        a certificate, use `sq pki link add` to mark \
                        the binding as authenticated, or use \
                        `sq network search FINGERPRINT|EMAIL` to look for \
                        new certifications.");
        }
    } else if bindings.is_empty() {
        // There are no matching bindings.  Tell the user about `sq
        // network fetch`.
        if let Some(pattern) = pattern() {
            weprintln!("No bindings match.");

            sq.hint(format_args!(
                "Try searching public directories:"))
                .sq().arg("network").arg("search")
                .arg(pattern)
                .done();
        } else if n.iter_fingerprints().next().is_none() {
            weprintln!("The certificate store does not contain any \
                        certificates.");

            sq.hint(format_args!(
                "Consider creating a key for yourself:"))
                .sq().arg("key").arg("generate")
                .arg_value("--name", "your-name")
                .arg_value("--email", "your-email-address")
                .arg("--own-key")
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

            // We're listing everything and we have nothing.  That's
            // not actually an error.
            return Ok(());
        }
    } else if bindings.len() - bindings_shown > 0 {
        // Some of the matching bindings were not shown.  Tell the
        // user about the `--gossip` option.
        let bindings = bindings.len();
        assert!(bindings > 0);
        let bindings_not_shown = bindings - bindings_shown;

        if bindings == 1 {
            weprintln!("1 binding found.");
        } else {
            weprintln!("{} bindings found.", bindings);
        }

        if bindings_not_shown == 1 {
            weprintln!("Skipped 1 binding, which could not be authenticated.");
            weprintln!("Pass `--gossip` to see the unauthenticated binding.");
        } else {
            weprintln!("Skipped {} bindings, which could not be authenticated.",
                      bindings_not_shown);
            weprintln!("Pass `--gossip` to see the unauthenticated bindings.");
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
