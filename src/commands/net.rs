//! Network services.

use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::{
    Result,
    KeyHandle,
    cert::{
        Cert,
        CertParser,
    },
    crypto::Signer,
    Packet,
    packet::{
        signature::SignatureBuilder,
        UserID,
    },
    parse::Parse,
    policy::NullPolicy,
    types::SignatureType,
};
use sequoia_net as net;
use net::{
    KeyServer,
    wkd,
    dane,
};

use sequoia_cert_store as cert_store;
use cert_store::StoreUpdate;
use cert_store::store::UserIDQueryParams;

use crate::{
    commands::{
        active_certification,
        get_certification_keys,
    },
    Config,
    Model,
    serialize_keyring,
    output::WkdUrlVariant,
    print_error_chain,
};

use crate::cli;

const NP: NullPolicy = NullPolicy::new();

// Import the certificates into the local certificate store.
//
// This does not certify the certificates.
fn import_certs(config: &mut Config, certs: Vec<Cert>) -> Result<()> {
    // Once we get a mutable reference to the cert_store, we're locked
    // out of config.  Gather the information we need first.
    let certs = certs.into_iter()
        .map(|cert| {
            let fpr = cert.fingerprint();
            let userid = cert.with_policy(&config.policy, config.time)
                .or_else(|_| cert.with_policy(&NP, config.time))
                .and_then(|vc| vc.primary_userid())
                .map(|userid| {
                    String::from_utf8_lossy(userid.value())
                        .to_string()
                })
                .unwrap_or_else(|_| "<unknown>".to_string());

            (fpr, userid, cert)
        })
        .collect::<Vec<_>>();

    let cert_store = config.cert_store_mut_or_else()
        .context("Inserting results")?;

    let mut stats
        = cert_store::store::MergePublicCollectStats::new();

    eprintln!("Importing {} certificates into the certificate store:\n", certs.len());
    for (i, (fpr, userid, cert)) in certs.into_iter().enumerate() {
        cert_store.update_by(Cow::Owned(cert.into()), &mut stats)
            .with_context(|| format!("Inserting {}, {}", fpr, userid))?;
        eprintln!("  {}. {} {}", i + 1, fpr, userid);
    }

    eprintln!("\nImported {} new certificates, \
               updated {} certificates, \
               {} certificates unchanged, \
               {} errors.",
              stats.new, stats.updated, stats.unchanged,
              stats.errors);

    eprintln!("\nAfter checking that a certificate really belongs to the \
               stated owner, use \"sq link add FINGERPRINT\" to \
               mark the certificate as authenticated.");

    Ok(())
}

/// Creates a non-exportable certification for the specified bindings.
///
/// This does not import the certification or the certificate into
/// the certificate store.
fn certify(config: &Config,
           signer: &mut dyn Signer, cert: &Cert, userids: &[UserID],
           creation_time: Option<SystemTime>, depth: u8, amount: usize)
    -> Result<Cert>
{
    let mut builder = SignatureBuilder::new(SignatureType::GenericCertification);

    if depth != 0 || amount != 120 {
        builder = builder.set_trust_signature(depth, amount.min(255) as u8)?;
    }

    builder = builder.set_exportable_certification(true)?;

    if let Some(creation_time) = creation_time {
        builder = builder.set_signature_creation_time(creation_time)?;
    }

    let certifications = active_certification(
            config, &cert.fingerprint(),
            userids.iter().cloned().collect(),
            signer.public())
        .into_iter()
        .map(|(userid, active_certification)| {
            if let Some(_) = active_certification {
                eprintln!("Provenance information for {}, {:?} \
                           exists and is current, not updating it",
                          cert.fingerprint(),
                          String::from_utf8_lossy(userid.value()));
                return vec![];
            }

            match builder.clone().sign_userid_binding(
                signer,
                cert.primary_key().key(),
                &userid)
                .with_context(|| {
                    format!("Creating certification for {} {:?}",
                            cert.fingerprint(),
                            String::from_utf8_lossy(userid.value()))
                })
            {
                Ok(sig) => {
                    eprintln!("Recorded provenance information \
                               for {}, {:?}",
                              cert.fingerprint(),
                              String::from_utf8_lossy(userid.value()));
                    vec![ Packet::from(userid.clone()), Packet::from(sig) ]
                }
                Err(err) => {
                    let err = err.context(format!(
                        "Warning: recording provenance information \
                         for {}, {:?}",
                        cert.fingerprint(),
                        String::from_utf8_lossy(userid.value())));
                    print_error_chain(&err);
                    vec![]
                }
            }
        })
        .collect::<Vec<Vec<Packet>>>()
        .into_iter()
        .flatten()
        .collect::<Vec<Packet>>();

    if certifications.is_empty() {
        Ok(cert.clone())
    } else {
        Ok(cert.clone().insert_packets(certifications)?)
    }
}

/// Gets the specified CA.
///
/// The ca is found in the specified special (e.g. `_wkd.pgp`, or
/// `_keyserver_keys.openpgp.org.pgp`).  If the CA does not exist, it
/// is created with the specified User ID (e.g., `Downloaded from a
/// WKD`, or `Downloaded from keys.openpgp.org`), and the specified
/// trust amount.
fn get_ca(config: &mut Config,
          ca_special: &str, ca_userid: &str, ca_trust_amount: usize)
    -> Result<Cert>
{
    let (created, ca) = config.get_special(ca_special, ca_userid, true)?;
    if ! created {
        // We didn't create it, and don't want to change how it is
        // setup.
        return Ok(ca);
    }

    // We just created the certificate.  Make it a CA by having
    // the local trust root certify it.
    match config.local_trust_root() {
        Err(err) => {
            Err(anyhow::anyhow!(
                "Failed to certify {:?} using the local trust root: {}",
                ca_userid, err))
        }
        Ok(trust_root) => {
            let keys = get_certification_keys(
                &[trust_root], &config.policy, None, Some(config.time), None)
                .context("Getting trust root's certification key")?;
            assert!(
                keys.len() == 1,
                "Expect exactly one result from get_certification_keys()"
            );
            let mut signer = keys.into_iter().next().unwrap().0;

            match certify(config, &mut signer, &ca, &[UserID::from(ca_userid)],
                          Some(config.time), 1, ca_trust_amount)
            {
                Err(err) => {
                    Err(err).context(format!(
                        "Error certifying {:?} with the local trust root",
                        ca_userid))
                }
                Ok(cert) => {
                    // Save it.
                    let cert_store = config.cert_store_mut_or_else()?;
                    cert_store.update(Cow::Owned(cert.clone().into()))
                        .with_context(|| {
                            format!("Saving {:?}", ca_userid)
                        })?;

                    eprintln!("Created the local CA {:?} for certifying \
                               certificates downloaded from this service.  \
                               The CA's trust amount is set to {} of {}.  \
                               Use `sq link add --ca '*' --amount N {}` \
                               to override it.  Or `sq link retract {}` to \
                               disable it.",
                              ca_userid,
                              ca_trust_amount, sequoia_wot::FULLY_TRUSTED,
                              cert.fingerprint(), cert.fingerprint());

                    Ok(cert)
                }
            }
        }
    }
}

// Certify the certificates using the specified CA.
//
// The certificates are certified for User IDs with the specified
// email address.  If no email address is specified, then all valid
// User IDs are certified.  The results are returned; they are not
// imported into the certificate store.
//
// If a certificate cannot be certified for whatever reason, a
// diagnostic is emitted, and the certificate is returned as is.
fn certify_downloads(config: &mut Config,
                     ca_special: &str, ca_userid: &str, ca_trust_amount: usize,
                     certs: Vec<Cert>, email: Option<String>)
    -> Vec<Cert>
{
    let mut ca = || -> Result<_> {
        let ca = get_ca(config, ca_special, ca_userid, ca_trust_amount)?;

        let keys = get_certification_keys(
            &[ca], &config.policy, None, Some(config.time), None)?;
            assert!(
                keys.len() == 1,
                "Expect exactly one result from get_certification_keys()"
            );
        Ok(keys.into_iter().next().unwrap().0)
    };
    let mut ca_signer = match ca() {
        Ok(signer) => signer,
        Err(err) => {
            let err = err.context(
                "Warning: not recording provenance information, \
                 failed to load CA key");
            print_error_chain(&err);
            return certs;
        }
    };

    // Normalize the email.  If it is not valid, just return it as is.
    let email = email.map(|email| {
        match UserIDQueryParams::is_email(&email) {
            Ok(email) => email,
            Err(_) => email,
        }
    });

    let certs: Vec<Cert> = certs.into_iter().map(|cert| {
        let vc = match cert.with_policy(&config.policy, config.time) {
            Err(err) => {
                let err = err.context(format!(
                    "Warning: not recording provenance information \
                     for {}, not valid",
                    cert.fingerprint()));
                print_error_chain(&err);
                return cert;
            }
            Ok(vc) => vc,
        };

        let userids = if let Some(email) = email.as_ref() {
            // Only the specified email address is authenticated.
            let userids = vc.userids()
                .filter_map(|ua| {
                    if let Ok(Some(e)) = ua.userid().email_normalized() {
                        if &e == email {
                            return Some(ua.userid().clone());
                        }
                    }
                    None
                })
                .collect::<Vec<UserID>>();

            if userids.is_empty() {
                eprintln!("Warning: not recording provenance information \
                           for {}, it does not contain a valid User ID with \
                           the specified email address ({:?})",
                          cert.fingerprint(),
                          email);
                return cert;
            }

            userids
        } else {
            vc.userids().map(|ua| ua.userid().clone()).collect()
        };

        match certify(
            config, &mut ca_signer, &cert, &userids[..],
            Some(config.time), 0, sequoia_wot::FULLY_TRUSTED)
        {
            Ok(cert) => cert,
            Err(err) => {
                let err = err.context(format!(
                    "Warning: not recording provenance information \
                     for {}, failed to certify it",
                    cert.fingerprint()));
                print_error_chain(&err);

                cert
            }
        }
    }).collect();

    certs
}

#[derive(Clone)]
enum Query {
    Handle(KeyHandle),
    Address(String),
}

impl fmt::Display for Query {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Query::Handle(h) => write!(f, "{}", h),
            Query::Address(a) => write!(f, "{}", a),
        }
    }
}

pub fn dispatch_keyserver(mut config: Config, c: cli::keyserver::Command)
    -> Result<()>
{
    let uri = &c.server[..];

    // Get the filename for the CA's key and the default User ID.
    let ca = || -> Option<(String, String)> {
        if let Some(server) = uri.strip_prefix("hkps://") {
            // We only certify the certificate if the transport was
            // encrypted and authenticated.

            let server = server.strip_suffix("/").unwrap_or(server);
            // A basic sanity check on the name, which we are about to
            // use as a filename: it can't start with a dot, no
            // slashes, and no colons are allowed.
            if server.chars().next() == Some('.')
                || server.contains('/')
                || server.contains('\\')
                || server.contains(':') {
                return None;
            }

            let server = server.to_ascii_lowercase();

            // Only record provenance information for certifying
            // keyservers.  Anything else doesn't make sense.
            match &server[..] {
                "keys.openpgp.org" => (),
                "keys.mailvelope.com" => (),
                "mail-api.proton.me" => (),
                _ => {
                    eprintln!("Not recording provenance information, {} is not \
                               known to be a verifying keyserver",
                              server);
                    return None;
                },
            }

            Some((format!("_keyserver_{}.pgp", server),
                  format!("Downloaded from the keyserver {}", server)))
        } else {
            None
        }
    };
    let ca_trust_amount = 1;

    let ks = Arc::new(KeyServer::new(uri)
        .context("Malformed keyserver URI")?);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;

    use crate::cli::keyserver::Subcommands::*;
    match c.subcommand {
        Get(c) => rt.block_on(async {
            let queries = c.query.iter().map(
                |q| if let Ok(h) = q.parse::<KeyHandle>() {
                    Ok(Query::Handle(h))
                } else if let Ok(Some(addr)) = UserID::from(q.as_str()).email2() {
                    Ok(Query::Address(addr.to_string()))
                } else {
                    Err(anyhow::anyhow!(
                        "Query must be a fingerprint, a keyid, \
                         or an email address: {:?}", q))
                }).collect::<Result<Vec<Query>>>()?;

            let mut requests = tokio::task::JoinSet::new();
            queries.into_iter().for_each(|query| {
                let ks = ks.clone();
                requests.spawn(async move {
                    let certs = match query.clone() {
                        Query::Handle(h) => ks.get(h).await?,
                        Query::Address(a) => ks.search(a).await?,
                    };
                    Result::Ok((query, certs))
                });
            });

            let mut certs = Vec::new();
            while let Some(response) = requests.join_next().await {
                let (query, returned_certs) = response??;
                for c in returned_certs {
                    match c {
                        Ok(c) => certs.push(c),
                        Err(e) => eprintln!("{}: {}", query, e),
                    }
                }
            }

            if let Some(file) = &c.output {
                let mut output = file.create_safe(config.force)?;
                serialize_keyring(&mut output, &certs, c.binary)?;
            } else {
                let certs = if let Some((ca_filename, ca_userid)) = ca() {
                    certify_downloads(
                        &mut config, &ca_filename, &ca_userid,
                        ca_trust_amount,
                        certs, None)
                } else {
                    certs
                };
                import_certs(&mut config, certs)?;
            }


            Result::Ok(())
        })?,
        Send(c) => {
            let mut input = c.input.open()?;
            let cert = Cert::from_reader(&mut input).
                context("Malformed key")?;

            rt.block_on(ks.send(&cert))
                .context("Failed to send key to server")?;
        },
    }

    Ok(())
}

pub fn dispatch_wkd(mut config: Config, c: cli::wkd::Command) -> Result<()> {
    let ca_filename = "_wkd.pgp";
    let ca_userid = "Downloaded from a WKD";
    let ca_trust_amount = 1;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;

    use crate::cli::wkd::Subcommands::*;
    match c.subcommand {
        Url(c) => {
            let wkd_url = wkd::Url::from(&c.email_address)?;
            let advanced = wkd_url.to_url(None)?.to_string();
            let direct = wkd_url.to_url(wkd::Variant::Direct)?.to_string();
            let output = Model::wkd_url(config.output_version,
                                       WkdUrlVariant::Advanced, advanced, direct)?;
            output.write(config.output_format, &mut std::io::stdout())?;
        },
        DirectUrl(c) => {
            let wkd_url = wkd::Url::from(&c.email_address)?;
            let advanced = wkd_url.to_url(None)?.to_string();
            let direct = wkd_url.to_url(wkd::Variant::Direct)?.to_string();
            let output = Model::wkd_url(config.output_version,
                                       WkdUrlVariant::Direct, advanced, direct)?;
            output.write(config.output_format, &mut std::io::stdout())?;
        },
        Get(c) => {
            let email_address = c.email_address;
            // XXX: EmailAddress could be created here to
            // check it's a valid email address, print the error to
            // stderr and exit.
            // Because it might be created a WkdServer struct, not
            // doing it for now.
            let certs = rt.block_on(wkd::get(&net::reqwest::Client::new(), &email_address))?;
            let certs = certs.into_iter().filter_map(Result::ok).collect::<Vec<Cert>>();
            // ```text
            //     The HTTP GET method MUST return the binary representation of the
            //     OpenPGP key for the given mail address.
            // [draft-koch]: https://datatracker.ietf.org/doc/html/draft-koch-openpgp-webkey-service-07
            // ```
            // But to keep the parallelism with `store export` and `keyserver get`,
            // The output is armored if not `--binary` option is given.
            if let Some(file) = c.output {
                let mut output = file.create_safe(config.force)?;
                serialize_keyring(&mut output, &certs, c.binary)?;
            } else {
                let certs = certify_downloads(
                    &mut config, &ca_filename, &ca_userid, ca_trust_amount,
                    certs, Some(email_address));
                import_certs(&mut config, certs)?;
            }
        },
        Generate(c) => {
            let domain = c.domain;
            let skip = c.skip;
            let f = c.input.open()?;
            let base_path = c.base_directory;
            let variant = if c.direct_method {
                wkd::Variant::Direct
            } else {
                wkd::Variant::Advanced
            };
            let parser = CertParser::from_reader(f)?;
            let policy = &config.policy;
            let certs: Vec<Cert> = parser.filter_map(|cert| cert.ok())
                .collect();
            for cert in certs {
                let vc = match cert.with_policy(policy, config.time) {
                    Ok(vc) => vc,
                    e @ Err(_) if !skip => e?,
                    _ => continue,
                };
                if wkd::cert_contains_domain_userid(&domain, &vc) {
                    wkd::insert(&base_path, &domain, variant, &vc)
                        .context(format!("Failed to generate the WKD in \
                        {}.", base_path.display()))?;
                } else if !skip {
                    return Err(openpgp::Error::InvalidArgument(
                        format!("Certificate {} does not contain User IDs in domain {}.",
                        vc.fingerprint(), domain)
                    ).into());
                }
            }
        },
    }

    Ok(())
}

pub fn dispatch_dane(mut config: Config, c: cli::dane::Command) -> Result<()> {
    let ca_filename = "_dane.pgp";
    let ca_userid = "Downloaded from DANE";
    let ca_trust_amount = 1;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;

    use crate::cli::dane::Subcommands::*;
    match c.subcommand {
        Generate(c) => {
            for cert in CertParser::from_reader(c.input.open()?)? {
                let cert = cert?;
                let vc = match cert.with_policy(&config.policy, config.time) {
                    Ok(vc) => vc,
                    e @ Err(_) if ! c.skip => e?,
                    _ => continue,
                };
                match if c.generic {
                    dane::generate_generic(&vc, &c.domain, c.ttl, c.size_limit)
                } else {
                    dane::generate(&vc, &c.domain, c.ttl, c.size_limit)
                } {
                    Ok(records) =>
                        records.iter().for_each(|r| println!("{}", r)),
                    Err(e) =>
                        match e.downcast::<openpgp::Error>() {
                            // Ignore cert with no user ID in domain.
                            Ok(openpgp::Error::InvalidArgument(_))
                                if c.skip => (),
                            Ok(e) => Err(e)?,
                            Err(e) => Err(e)?,
                        },
                }
            }
        },
        Get(c) => {
            let email_address = c.email_address;
            // XXX: EmailAddress could be created here to
            // check it's a valid email address, print the error to
            // stderr and exit.
            // Because it might be created a WkdServer struct, not
            // doing it for now.
            let certs = rt.block_on(dane::get(&email_address))?;
            let certs = certs.into_iter().filter_map(Result::ok).collect::<Vec<Cert>>();
            if let Some(file) = c.output {
                let mut output = file.create_safe(config.force)?;
                serialize_keyring(&mut output, &certs, c.binary)?;
            } else {
                let certs = certify_downloads(
                    &mut config, &ca_filename, &ca_userid, ca_trust_amount,
                    certs, Some(email_address));
                import_certs(&mut config, certs)?;
            }
        },
    }

    Ok(())
}
