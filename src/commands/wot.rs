use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::KeyID;
use openpgp::Fingerprint;
use openpgp::KeyHandle;
use openpgp::Result;
use openpgp::packet::UserID;
use openpgp::policy::Policy;

use sequoia_cert_store as cert_store;
use cert_store::store::StatusListener;
use cert_store::store::StatusUpdate;
use cert_store::store::StoreError;

use sequoia_wot as wot;
use wot::store::CertStore;
use wot::store::Backend;

pub mod output;

use crate::cli;

use crate::commands::wot as wot_cmd;
use wot_cmd::output::print_path;
use wot_cmd::output::print_path_header;
use wot_cmd::output::print_path_error;
use wot_cmd::output::OutputType;

use crate::Config;

fn trust_amount(cli: &cli::wot::Command)
    -> Result<usize>
{
    let amount = if let Some(v) = cli.trust_amount {
        v as usize
    } else if cli.full {
        wot::FULLY_TRUSTED
    } else if cli.partial {
        wot::PARTIALLY_TRUSTED
    } else if cli.double {
        2 * wot::FULLY_TRUSTED
    } else {
        if cli.certification_network {
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
fn authenticate<S>(
    config: &Config,
    cli: &cli::wot::Command,
    q: &wot::Query<'_, S>,
    gossip: bool,
    userid: Option<&UserID>,
    certificate: Option<&KeyHandle>,
) -> Result<()>
    where S: wot::store::Store
{
    let required_amount = trust_amount(cli)?;

    let fingerprint: Option<Fingerprint> = if let Some(kh) = certificate {
        Some(match kh {
            KeyHandle::Fingerprint(fpr) => fpr.clone(),
            kh @ KeyHandle::KeyID(_) => {
                let certs = q.network().lookup_synopses(kh)?;
                if certs.is_empty() {
                    return Err(StoreError::NotFound(kh.clone()).into());
                }
                if certs.len() > 1 {
                    return Err(anyhow::anyhow!(
                        "The Key ID {} is ambiguous.  \
                         It could refer to any of the following \
                         certificates: {}.",
                        kh,
                        certs.into_iter()
                            .map(|c| c.fingerprint().to_hex())
                            .collect::<Vec<String>>()
                            .join(", ")));
                }

                certs[0].fingerprint()
            }
        })
    } else {
        None
    };

    let email = cli.subcommand.email();

    let mut bindings = Vec::new();
    if matches!(userid, Some(_)) && email {
        let userid = userid.expect("required");

        // First, we check that the supplied User ID is a bare
        // email address.
        let email = String::from_utf8(userid.value().to_vec())
            .context("email address must be valid UTF-8")?;

        let userid_check = UserID::from(format!("<{}>", email));
        if let Ok(Some(email_check)) = userid_check.email() {
            if email != email_check {
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
            q.network().certified_userids_of(fingerprint)
                .into_iter()
                .map(|userid| (fingerprint.clone(), userid))
                .collect::<Vec<_>>()
        } else {
            q.network().lookup_synopses_by_email(&email)
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
            bindings = q.network().certified_userids_of(&fingerprint)
                .into_iter()
                .map(|userid| (fingerprint.clone(), userid))
                .collect();
        }
    } else if let Some(userid) = userid {
        // The caller did not specify a certificate.  Find all
        // bindings with the User ID.
        bindings = q.network().lookup_synopses_by_userid(userid.clone())
            .into_iter()
            .map(|fpr| (fpr, userid.clone()))
            .collect();
    } else {
        // No User ID, no Fingerprint.
        // List everything.

        bindings = q.network().certified_userids();

        if let cli::wot::Subcommand::List { pattern: Some(pattern), .. } = &cli.subcommand {
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

                        if let Ok(Some(email)) = userid.email() {
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

    let mut authenticated = false;
    let mut lint_input = true;

    let mut output = match config.output_format {
        #[cfg(feature = "dot-writer")]
        crate::output::OutputFormat::DOT => {
            Box::new(output::DotOutputNetwork::new(
                required_amount,
                q.roots(),
                gossip,
                cli.certification_network,
            ))
            as Box<dyn output::OutputType>
        }
        _ => {
            Box::new(
                output::HumanReadableOutputNetwork::new(required_amount, gossip)
            )
        }
    };

    for (fingerprint, userid) in bindings.iter() {
        let mut aggregated_amount = 0;

        let paths = if gossip {
            // Gossip.
            let paths = q.gossip(
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
                authenticated = true;
                lint_input = false;
            }

            paths.into_iter()
                .map(|p| (p, 0))
                .collect::<Vec<(wot::Path, usize)>>()
        } else {
            let paths = q.authenticate(
                userid.clone(), fingerprint.clone(), required_amount);

            aggregated_amount = paths.amount();
            if aggregated_amount == 0 {
                continue;
            }
            lint_input = false;
            if aggregated_amount >= required_amount {
                authenticated = true;
            }

            paths.into_iter().collect::<Vec<(wot::Path, usize)>>()
        };

        output.add_paths(paths, fingerprint, userid, aggregated_amount)?;

    }

    output.finalize()?;

    // We didn't show anything.  Try to figure out what was wrong.
    if lint_input {
        // See if the target certificate exists.
        if let Some(kh) = certificate {
            match q.network().lookup_synopses(kh) {
                Err(err) => {
                    eprintln!("Looking up target certificate ({}): {}",
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
                                eprintln!("Warning: {} is revoked.", kh);
                            }
                            RevocationStatus::NotAsFarAsWeKnow => (),
                        }

                        // Check if the certificate has expired.
                        if let Some(e) = cert.expiration_time() {
                            if e <= q.network().reference_time() {
                                eprintln!("Warning: {} is expired.", kh);
                            }
                        }

                        // See if there is a matching self-signed User ID.
                        if let Some(userid) = userid {
                            if ! have_self_signed_userid(cert, userid, email) {
                                eprintln!("Warning: {} is not a \
                                          self-signed User ID for {}.",
                                         userid, kh);
                            }
                        }

                        // See if there are any certifications made on
                        // this certificate.
                        if let Ok(cs) = q.network()
                            .certifications_of(&fpr, 0.into())
                        {
                            if cs.iter().all(|cs| {
                                cs.certifications()
                                    .all(|(_userid, certifications)| {
                                        certifications.is_empty()
                                    })
                            })
                            {
                                eprintln!("Warning: {} has no valid \
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
                    if let Ok(Some(email_check)) = userid_check.email() {
                        if email == email_check {
                            eprintln!("WARNING: {} appears to be a bare \
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
            if q.roots().iter().all(|r| {
                let fpr = r.fingerprint();
                if let Err(err) = q.network().lookup_synopsis_by_fpr(&fpr) {
                    eprintln!("Looking up trust root ({}): {}.",
                             fpr, err);
                    true
                } else {
                    false
                }
            })
            {
                eprintln!("No trust roots found.");
            }
        }
    }

    if ! authenticated {
        if ! lint_input {
            eprintln!("Could not authenticate any paths.");
        } else {
            eprintln!("No paths found.");
        }
        std::process::exit(1);
    }

    Ok(())
}

// For `sq-wot path`.
fn check_path<'a: 'b, 'b, S>(config: &Config,
                             cli: &cli::wot::Command,
                             q: &wot::Query<'b, S>,
                             policy: &dyn Policy)
    -> Result<()>
where S: wot::store::Store + wot::store::Backend<'a>
{
    tracer!(TRACE, "check_path");

    let required_amount = trust_amount(cli)?;

    let (khs, userid) = if let cli::wot::Subcommand::Path { path, .. } = &cli.subcommand {
        (path.certs()?, path.userid()?)
    } else {
        unreachable!("checked");
    };

    assert!(khs.len() > 0, "guaranteed by clap");

    let r = q.lint_path(&khs, &userid, required_amount, policy);

    let target_kh = khs.last().expect("have one");

    match r {
        Ok(path) => {
            match config.output_format {
                #[cfg(feature = "dot-writer")]
                crate::output::OutputFormat::DOT => {
                    eprintln!(
                        "DOT output for \"sq wot path\" is not yet \
                         implemented!");
                }
                _ => {
                    print_path_header(
                        target_kh,
                        &userid,
                        path.amount(),
                        required_amount,
                    );
                    print_path(&path, &userid, "  ");
                }
            };

            if path.amount() >= required_amount {
                std::process::exit(0);
            }
        }
        Err(err) => {
            match config.output_format {
                #[cfg(feature = "dot-writer")]
                crate::output::OutputFormat::DOT => {
                    eprintln!(
                        "DOT output for \"sq wot path\" is not yet \
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
        eprintln!("{}", update);
    }
}

pub fn dispatch(config: Config, cli: cli::wot::Command) -> Result<()> {
    tracer!(TRACE, "wot::dispatch");

    // Build the network.
    let cert_store = match config.cert_store() {
        Ok(Some(cert_store)) => cert_store,
        Ok(None) => {
            return Err(anyhow::anyhow!("Certificate store has been disabled"));
        }
        Err(err) => {
            return Err(err).context("Opening certificate store");
        }
    };

    let mut cert_store = CertStore::from_store(
        cert_store, &config.policy, config.time);
    if let cli::wot::Subcommand::List { pattern: None, .. } = cli.subcommand {
        cert_store.precompute();
    }

    let n = wot::Network::new(cert_store)?;

    let mut q = wot::QueryBuilder::new(&n);
    if ! cli.gossip {
        q.roots(wot::Roots::new(config.trust_roots()));
    }
    if cli.certification_network {
        q.certification_network();
    }
    let q = q.build();

    match &cli.subcommand {
        cli::wot::Subcommand::Authenticate { cert, userid, .. } => {
            // Authenticate a given binding.
            authenticate(
                &config, &cli, &q, cli.gossip, Some(userid), Some(cert))?;
        }
        cli::wot::Subcommand::Lookup { userid, .. } => {
            // Find all authenticated bindings for a given
            // User ID, list the certificates.
            authenticate(
                &config, &cli, &q, cli.gossip, Some(userid), None)?;
        }
        cli::wot::Subcommand::Identify { cert, .. } => {
            // Find and list all authenticated bindings for a given
            // certificate.
            authenticate(
                &config, &cli, &q, cli.gossip, None, Some(cert))?;
        }
        cli::wot::Subcommand::List { .. } => {
            // List all authenticated bindings.
            authenticate(
                &config, &cli, &q, cli.gossip, None, None)?;
        }
        cli::wot::Subcommand::Path { .. } => {
            check_path(
                &config, &cli, &q, &config.policy)?;
        }
    }

    Ok(())
}
