use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::KeyID;
use openpgp::Fingerprint;
use openpgp::KeyHandle;
use openpgp::Result;
use openpgp::packet::UserID;

use sequoia_cert_store as cert_store;
use cert_store::store::StatusListener;
use cert_store::store::StatusUpdate;
use cert_store::store::StoreError;

use sequoia_wot as wot;
use wot::store::Backend;
use wot::store::Store;

pub mod certify;
pub mod link;
pub mod output;

use crate::cli;
#[cfg(feature = "dot-writer")]
use cli::output::OutputFormat;
use cli::types::TrustAmount;

use output::print_path;
use output::print_path_header;
use output::print_path_error;
#[allow(unused_imports)]
use output::OutputType as _;

use crate::Sq;

fn required_trust_amount(trust_amount: Option<TrustAmount<usize>>,
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
fn have_self_signed_userid(cert: &wot::CertSynopsis,
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
fn authenticate<'store, 'rstore>(
    sq: Sq<'store, 'rstore>,
    precompute: bool,
    list_pattern: Option<String>,
    email: bool,
    gossip: bool,
    certification_network: bool,
    trust_amount: Option<TrustAmount<usize>>,
    userid: Option<&UserID>,
    certificate: Option<&KeyHandle>,
    show_paths: bool,
) -> Result<()>
    where 'store: 'rstore,
{
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

    let mut n = if gossip {
        wot::NetworkBuilder::rootless(cert_store)
    } else {
        wot::NetworkBuilder::rooted(cert_store,
                                    &*sq.trust_roots())
    };
    if certification_network {
        n = n.certification_network();
    }
    let n = n.build();

    let required_amount =
        required_trust_amount(trust_amount, certification_network)?;

    let mut certificate_dealiased = None;
    let fingerprint: Option<Fingerprint> = if let Some(kh) = certificate {
        match sq.lookup(std::iter::once(kh), None, true, true) {
            Ok(certs) => {
                assert!(certs.len() >= 1);

                if certs.len() > 1 {
                    return Err(anyhow::anyhow!(
                        "The key ID {} is ambiguous.  \
                         It could refer to any of the following \
                         certificates: {}.",
                        kh,
                        certs.into_iter()
                            .map(|c| c.fingerprint().to_hex())
                            .collect::<Vec<String>>()
                            .join(", ")));
                }

                let fpr = certs[0].fingerprint();
                if ! KeyHandle::from(&fpr).aliases(kh) {
                    // XXX: If the subkey does not have a backsig,
                    // then it doesn't authenticate the primary key,
                    // and thus the authentication confidence must be
                    // 0, and the certificate should only be shown
                    // when `--gossip` is passed.
                    eprintln!("Certificate {} contains the subkey {}.",
                              fpr, kh);
                }
                certificate_dealiased = Some(KeyHandle::from(&fpr));
                Some(fpr)
            }
            Err(err) => {
                if let Some(StoreError::NotFound(_)) = err.downcast_ref() {
                    wprintln!("There are no certificates with the \
                               specified {}.  \
                               Run `sq network fetch {}` to look for \
                               matching certificates on public \
                               directories.",
                              if let KeyHandle::Fingerprint(_) = kh {
                                  "fingerprint"
                              } else {
                                  "key ID"
                              },
                              kh);
                }
                return Err(err);
            }
        }
    } else {
        None
    };

    let mut bindings = Vec::new();
    if matches!(userid, Some(_)) && email {
        let userid = userid.expect("required");

        // First, we check that the supplied User ID is a bare
        // email address.
        let email = String::from_utf8(userid.value().to_vec())
            .context("email address must be valid UTF-8")?;

        let userid_check = UserID::from(format!("<{}>", email));
        if let Ok(Some(email_check)) = userid_check.email2() {
            if &email != email_check {
                println!("{:?} does not appear to be an email address",
                         email);
                std::process::exit(1);
            }
        } else {
            println!("{:?} does not appear to be an email address",
                     email);
            std::process::exit(1);
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
    } else if let Some(fingerprint) = fingerprint {
        if let Some(userid) = userid {
            bindings.push((fingerprint, userid.clone()));
        } else {
            // Fingerprint, no User ID.
            bindings = n.certified_userids_of(&fingerprint)
                .into_iter()
                .map(|userid| (fingerprint.clone(), userid))
                .collect();
        }
    } else if let Some(userid) = userid {
        // The caller did not specify a certificate.  Find all
        // bindings with the User ID.
        bindings = n.lookup_synopses_by_userid(userid.clone())
            .into_iter()
            .map(|fpr| (fpr, userid.clone()))
            .collect();
    } else {
        // No User ID, no Fingerprint.
        // List everything.

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
    let mut lint_input = true;

    let mut output = match sq.output_format {
        #[cfg(feature = "dot-writer")]
        OutputFormat::DOT => {
            Box::new(output::DotOutputNetwork::new(
                required_amount,
                n.roots(),
                gossip,
                certification_network,
            ))
            as Box<dyn output::OutputType>
        }
        _ => {
            if show_paths {
                Box::new(
                    output::HumanReadableOutputNetwork::new(
                        required_amount, gossip))
                    as Box<dyn output::OutputType>
            } else {
                Box::new(
                    output::ConciseHumanReadableOutputNetwork::new(
                        &sq, required_amount))
                    as Box<dyn output::OutputType>
            }
        }
    };

    for (fingerprint, userid) in bindings.iter() {
        let mut aggregated_amount = 0;

        let paths = if gossip {
            // Gossip.
            let paths = n.gossip(
                fingerprint.clone(), userid.clone());

            // Sort so the shortest paths come first.
            let mut paths: Vec<_> = paths
                .into_values()
                .map(|(path, _amount)| path)
                .collect();
            paths.sort_by_key(|path| path.len());

            // This means: exit code is 0, which is what we want when
            // we've found at least one path.
            if paths.len() > 0 {
                authenticated += 1;
                lint_input = false;
            }

            paths.into_iter()
                .map(|p| (p, 0))
                .collect::<Vec<(wot::Path, usize)>>()
        } else {
            let paths = n.authenticate(
                userid.clone(), fingerprint.clone(), required_amount);

            aggregated_amount = paths.amount();
            if aggregated_amount == 0 {
                continue;
            }
            lint_input = false;
            if aggregated_amount >= required_amount {
                authenticated += 1;
            }

            paths.into_iter().collect::<Vec<(wot::Path, usize)>>()
        };

        output.add_paths(paths, fingerprint, userid, aggregated_amount)?;
    }

    output.finalize()?;

    // We didn't show anything.  Try to figure out what was wrong.
    if lint_input {
        // See if the target certificate exists.
        if let Some(kh) = certificate_dealiased {
            match n.lookup_synopses(&kh) {
                Err(err) => {
                    wprintln!("Looking up target certificate ({}): {}",
                             kh, err);
                }
                Ok(certs) => {
                    for cert in certs.iter() {
                        let fpr = cert.fingerprint();
                        let kh = if certs.len() == 1 {
                            KeyHandle::KeyID(KeyID::from(&fpr))
                        } else {
                            KeyHandle::Fingerprint(fpr.clone())
                        };

                        // Check if the certificate was revoke.
                        use wot::RevocationStatus;
                        match cert.revocation_status() {
                            RevocationStatus::Soft(_)
                            | RevocationStatus::Hard => {
                                wprintln!("Warning: {} is revoked.", kh);
                            }
                            RevocationStatus::NotAsFarAsWeKnow => (),
                        }

                        // Check if the certificate has expired.
                        if let Some(e) = cert.expiration_time() {
                            if e <= n.reference_time() {
                                wprintln!("Warning: {} is expired.", kh);
                            }
                        }

                        // See if there is a matching self-signed User ID.
                        if let Some(userid) = userid {
                            if ! have_self_signed_userid(cert, userid, email) {
                                wprintln!("Warning: {} is not a \
                                          self-signed User ID for {}.",
                                         userid, kh);
                            }
                        }

                        // See if there are any certifications made on
                        // this certificate.
                        if let Ok(cs) = n.certifications_of(&fpr, 0.into()) {
                            if cs.iter().all(|cs| {
                                cs.certifications()
                                    .all(|(_userid, certifications)| {
                                        certifications.is_empty()
                                    })
                            })
                            {
                                wprintln!("Warning: {} has no valid \
                                          certifications.",
                                         kh);
                            }
                        }
                    }
                }
            }
        }

        // Perhaps the caller specified an email address, but forgot
        // to add --email.  If --email is not present and the
        // specified User ID looks like an email, try and be helpful.
        if ! email {
            if let Some(userid) = userid {
                if let Ok(email) = std::str::from_utf8(userid.value()) {
                    let userid_check = UserID::from(format!("<{}>", email));
                    if let Ok(Some(email_check)) = userid_check.email2() {
                        if email == email_check {
                            wprintln!("WARNING: {} appears to be a bare \
                                      email address.  Perhaps you forgot \
                                      to specify --email.",
                                     email);
                        }
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
                String::from_utf8_lossy(u.value()).to_string()
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
            wprintln!("No bindings match.  Try using \
                       `sq network fetch {:?}` to search public directories \
                       for matching certificates.",
                      pattern);
        } else {
            wprintln!("The certificate store does not contain any \
                       certificates.");
        }
    } else if bindings.len() - authenticated > 0 {
        // Some of the matching bindings are unauthenticated.  Tell
        // the user about the `--gossip` option.
        let bindings = bindings.len();
        assert!(bindings > 0);
        let unauthenticated = bindings - authenticated;

        if bindings == 1 {
            wprintln!("1 binding found.");
        } else {
            wprintln!("{} bindings found.", bindings);
        }

        if unauthenticated == 1 {
            wprintln!("Skipped 1 binding, which could not be authenticated.");
            wprintln!("Pass `--gossip` to see the unauthenticated binding.");
        } else {
            wprintln!("Skipped {} bindings, which could not be authenticated.",
                      unauthenticated);
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

// For `sq-wot path`.
fn check_path(sq: &Sq,
              gossip: bool,
              certification_network: bool,
              trust_amount: Option<TrustAmount<usize>>,
              path: cli::pki::PathArg)
    -> Result<()>
{
    tracer!(TRACE, "check_path");

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

    let mut n = if gossip {
        wot::NetworkBuilder::rootless(cert_store)
    } else {
        wot::NetworkBuilder::rooted(cert_store,
                                    &*sq.trust_roots())
    };
    if certification_network {
        n = n.certification_network();
    }
    let q = n.build();

    let required_amount =
        required_trust_amount(trust_amount, certification_network)?;

    let (khs, userid) = (path.certs()?, path.userid()?);
    assert!(khs.len() > 0, "guaranteed by clap");

    let r = q.lint_path(&khs, &userid, required_amount, sq.policy);

    let target_kh = khs.last().expect("have one");

    match r {
        Ok(path) => {
            match sq.output_format {
                #[cfg(feature = "dot-writer")]
                OutputFormat::DOT => {
                    wprintln!(
                        "DOT output for \"sq pki path\" is not yet \
                         implemented!");
                }
                _ => {
                    print_path_header(
                        target_kh,
                        &userid,
                        path.amount(),
                        required_amount,
                    );
                    print_path(&path, &userid, "  ")?;
                }
            };

            if path.amount() >= required_amount {
                std::process::exit(0);
            }
        }
        Err(err) => {
            match sq.output_format {
                #[cfg(feature = "dot-writer")]
                OutputFormat::DOT => {
                    wprintln!(
                        "DOT output for \"sq pki path\" is not yet \
                         implemented!");
                }
                _ => {
                    print_path_header(
                        target_kh,
                        &userid,
                        0,
                        required_amount,
                    );
                    print_path_error(err);
                }
            };
        }
    }

    std::process::exit(1);
}

struct KeyServerUpdate {
}

impl StatusListener for KeyServerUpdate {
    fn update(&self, update: &StatusUpdate) {
        wprintln!("{}", update);
    }
}

pub fn dispatch(sq: Sq, cli: cli::pki::Command) -> Result<()> {
    tracer!(TRACE, "pki::dispatch");

    use cli::pki::*;
    match cli.subcommand {
        // Authenticate a given binding.
        Subcommands::Authenticate(AuthenticateCommand {
            email, gossip, certification_network, trust_amount,
            cert, userid, show_paths,
        }) => authenticate(
            sq, false, None,
            *email, *gossip, *certification_network, *trust_amount,
            Some(&userid), Some(&cert), *show_paths,
        )?,

        // Find all authenticated bindings for a given User ID, list
        // the certificates.
        Subcommands::Lookup(LookupCommand {
            email, gossip, certification_network, trust_amount,
            userid, show_paths,
        }) => authenticate(
            sq, false, None,
            *email, *gossip, *certification_network, *trust_amount,
            Some(&userid), None, *show_paths)?,

        // Find and list all authenticated bindings for a given
        // certificate.
        Subcommands::Identify(IdentifyCommand {
            gossip, certification_network, trust_amount,
            cert, show_paths,
        }) => authenticate(
            sq, false, None,
            false, *gossip, *certification_network, *trust_amount,
            None, Some(&cert), *show_paths)?,

        // List all authenticated bindings.
        Subcommands::List(ListCommand {
            email, gossip, certification_network, trust_amount,
            pattern, show_paths,
        }) => if let Some(handle) = pattern.as_ref()
            .and_then(|p| p.parse().ok())
            .iter().filter(|_| ! *email).next()
        {
            // A key handle was given as pattern and --email was not
            // given.  Act like `sq pki identify`.
            authenticate(
                sq, false, None,
                false, *gossip, *certification_network, *trust_amount,
                None, Some(&handle), *show_paths)?;
        } else {
            authenticate(
                sq, pattern.is_none(), pattern,
                *email, *gossip, *certification_network, *trust_amount,
                None, None, *show_paths)?;
        },

        // Authenticates a given path.
        Subcommands::Path(PathCommand {
            gossip, certification_network, trust_amount,
            path,
        }) => check_path(
            &sq, *gossip, *certification_network, *trust_amount,
            path)?,

        Subcommands::Certify(command) =>
            self::certify::certify(sq, command)?,

        Subcommands::Link(command) =>
            self::link::link(sq, command)?,
    }

    Ok(())
}
