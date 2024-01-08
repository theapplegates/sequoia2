//! Network services.

use std::fmt;
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Context;
use tokio::task::JoinSet;

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
    types::SignatureType,
};
use sequoia_net as net;
use net::{
    KeyServer,
    wkd,
    dane,
};

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;
use cert_store::StoreUpdate;
use cert_store::store::UserIDQueryParams;

use crate::{
    commands::{
        FileOrStdout,
        active_certification,
        get_certification_keys,
    },
    output::{
        pluralize::Pluralize,
        sanitize::Safe,
    },
    Config,
    Model,
    best_effort_primary_uid,
    merge_keyring,
    serialize_keyring,
    output::WkdUrlVariant,
    print_error_chain,
};

use crate::cli;

pub fn dispatch(config: Config, c: cli::network::Command)
                -> Result<()>
{
    use cli::network::Subcommands;
    match c.subcommand {
        Subcommands::Fetch(command) =>
            dispatch_fetch(config, command),

        Subcommands::Keyserver(command) =>
            dispatch_keyserver(config, command),

        Subcommands::Wkd(command) =>
            dispatch_wkd(config, command),

        Subcommands::Dane(command) =>
            dispatch_dane(config, command),
    }
}


/// Import the certificates into the local certificate store.
///
/// This does not certify the certificates.
pub fn import_certs(config: &mut Config, certs: Vec<Cert>) -> Result<()> {
    if certs.is_empty() {
        // No need to do and say anything.
        return Ok(());
    }

    // Once we get a mutable reference to the cert_store, we're locked
    // out of config.  Gather the information we need first.
    let certs = merge_keyring(certs)?.into_values()
        .map(|cert| {
            let fpr = cert.fingerprint();
            let userid =
                best_effort_primary_uid(&cert, &config.policy, config.time)
                .clone();

            (fpr, userid, cert)
        })
        .collect::<Vec<_>>();

    let cert_store = config.cert_store_mut_or_else()
        .context("Inserting results")?;

    let mut stats
        = cert_store::store::MergePublicCollectStats::new();

    wprintln!("\nImporting {} into the certificate store:\n",
              certs.len().of("certificate"));
    for (i, (fpr, userid, cert)) in certs.into_iter().enumerate() {
        cert_store.update_by(Arc::new(cert.into()), &mut stats)
            .with_context(|| format!("Inserting {}, {}", fpr, Safe(&userid)))?;
        wprintln!("  {}. {} {}", i + 1, fpr, Safe(&userid));
    }

    wprintln!("\nImported {}, updated {}, {} unchanged, {}.",
              stats.new.of("new certificate"),
              stats.updated.of("certificate"),
              stats.unchanged.of("certificate"),
              stats.errors.of("error"));

    wprintln!("\nAfter checking that a certificate really belongs to the \
               stated owner, you can mark the certificate as authenticated \
               using: \n\
               \n    sq link add FINGERPRINT\n");

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
                config.info(format_args!(
                          "Provenance information for {}, {:?} \
                           exists and is current, not updating it",
                          cert.fingerprint(),
                          String::from_utf8_lossy(userid.value())));
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
                config.info(format_args!(
                              "Recorded provenance information \
                               for {}, {:?}",
                              cert.fingerprint(),
                              String::from_utf8_lossy(userid.value())));
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

/// Certify the certificates using the specified CA.
///
/// The certificates are certified for User IDs with the specified
/// email address.  If no email address is specified, then all valid
/// User IDs are certified.  The results are returned; they are not
/// imported into the certificate store.
///
/// If a certificate cannot be certified for whatever reason, a
/// diagnostic is emitted, and the certificate is returned as is.
pub fn certify_downloads<'store>(config: &mut Config<'store>,
                                 ca: Arc<LazyCert<'store>>,
                                 certs: Vec<Cert>, email: Option<&str>)
    -> Vec<Cert>
{
    let ca = || -> Result<_> {
        let ca = ca.to_cert()?;

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
            Err(_) => email.to_string(),
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
                config.info(format_args!(
                          "Warning: not recording provenance information \
                           for {}, it does not contain a valid User ID with \
                           the specified email address ({:?})",
                          cert.fingerprint(),
                          email));
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

impl Query {
    /// Parses command line arguments to queries.
    fn parse(args: &[String]) -> Result<Vec<Query>> {
        args.iter().map(
            |q| if let Ok(h) = q.parse::<KeyHandle>() {
                Ok(Query::Handle(h))
            } else if let Ok(Some(addr)) = UserID::from(q.as_str()).email2() {
                Ok(Query::Address(addr.to_string()))
            } else {
                Err(anyhow::anyhow!(
                    "Query must be a fingerprint, a keyid, \
                     or an email address: {:?}", q))
            }).collect::<Result<Vec<Query>>>()
    }

    /// Parses command line arguments to queries that only contain
    /// email addresses.
    fn parse_addresses(args: &[String]) -> Result<Vec<Query>> {
        args.iter().map(
            |q| if let Ok(Some(addr)) = UserID::from(q.as_str()).email2() {
                Ok(Query::Address(addr.to_string()))
            } else {
                Err(anyhow::anyhow!(
                    "Query must be a an email address: {:?}", q))
            }).collect::<Result<Vec<Query>>>()
    }

    /// Returns the email address, if any.
    fn as_address(&self) -> Option<&str> {
        if let Query::Address(a) = self {
            Some(a)
        } else {
            None
        }
    }
}

#[derive(Clone)]
enum Method {
    KeyServer(String),
    WKD,
    DANE,
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Method::KeyServer(url) => write!(f, "{}", url),
            Method::WKD => write!(f, "WKD"),
            Method::DANE => write!(f, "DANE"),
        }
    }
}

impl Method {
    // Returns the CA's certificate.
    //
    // This doesn't return an error, because not all methods have
    // shadow CAs, and a missing CA is not a hard error.
    fn ca<'store>(&self, config: &Config<'store>) -> Option<Arc<LazyCert<'store>>> {
        let ca = || -> Result<_> {
            let certd = config.certd_or_else()?;
            let (cert, created) = match self {
                Method::KeyServer(url) => {
                    let result = certd.shadow_ca_keyserver(url)?;

                    match result {
                        Some((cert, created)) => (cert, created),
                        None => {
                            if config.verbose {
                                wprintln!(
                                    "Not recording provenance information: \
                                     {} is not known to be a verifying \
                                     keyserver",
                                    url);
                            }
                            return Ok(None);
                        }
                    }
                }
                Method::WKD => certd.shadow_ca_wkd()?,
                Method::DANE => certd.shadow_ca_dane()?,
            };

            // Check that the data is a valid certificate.  If not,
            // bail sooner rather than later.
            let _ = cert.to_cert()?;

            Ok(Some((cert, created)))
        };

        let (cert, created) = match ca() {
            Ok(Some((cert, created))) => (cert, created),
            Ok(None) => return None,
            Err(err) => {
                let print_err = || {
                    wprintln!(
                        "Not recording provenance information: {}",
                        err);
                };

                if config.verbose {
                    print_err();
                } else {
                    use std::sync::Once;
                    static MSG: Once = Once::new();
                    MSG.call_once(print_err);
                }

                return None;
            }
        };

        if ! created {
            // We didn't create it.
            return Some(cert);
        }

        if config.verbose {
            let invalid = UserID::from(&b"invalid data"[..]);

            wprintln!(
                "Created the local CA {:?} for certifying \
                 certificates downloaded from this service.  \
                 Use `sq link add --ca '*' --amount N {}` \
                 to change how much it is trusted.  Or \
                 `sq link retract {}` to disable it.",
                if let Ok(cert) = cert.to_cert() {
                    best_effort_primary_uid(
                        cert, &config.policy, None)
                } else {
                    &invalid
                },
                cert.fingerprint(), cert.fingerprint());
        } else {
            use std::sync::Once;
            static MSG: Once = Once::new();
            MSG.call_once(|| {
                wprintln!("Note: Created a local CA to record \
                           provenance information.\n\
                           Note: See `sq link list --ca` \
                           and `sq link --help` for more \
                           information.");
            });
        }

        Some(cert)
    }
}

struct Response {
    query: Query,
    method: Method,
    results: Result<Vec<Result<Cert>>>,
}

impl Response {
    /// Collects the responses, displays failures, and either writes
    /// out a keyring or imports the certs.
    ///
    /// If `silent_errors` is given, then failure messages are
    /// suppressed unless --verbose is given, or there was not a
    /// single successful result.
    async fn collect(mut config: Config<'_>,
                     output: Option<FileOrStdout>,
                     binary: bool,
                     mut responses: JoinSet<Response>,
                     silent_errors: bool)
                     -> Result<()> {
        let mut certs = Vec::new();
        let mut errors = Vec::new();
        while let Some(response) = responses.join_next().await {
            let response = response?;
            match response.results {
                Ok(returned_certs) => for cert in returned_certs {
                    match cert {
                        Ok(cert) => if output.is_some() {
                            certs.push(cert);
                        } else {
                            if let Some(ca) = response.method.ca(&config)
                            {
                                certs.append(&mut certify_downloads(
                                    &mut config, ca, vec![cert], None));
                            } else {
                                certs.push(cert);
                            }
                        },
                        Err(e) =>
                            errors.push((response.method.clone(),
                                         response.query.clone(), e)),
                    }
                },
                Err(e) =>
                    errors.push((response.method, response.query, e)),
            }
        }

        if ! silent_errors || config.verbose || certs.is_empty() {
            for (method, query, e) in errors {
                wprintln!("{}: {}: {}", method, query, e);
            }
        }

        if certs.is_empty() {
            return Err(anyhow::anyhow!("No cert found."));
        }

        if let Some(file) = &output {
            let mut output = file.create_safe(config.force)?;
            serialize_keyring(&mut output, certs, binary)?;
        } else {
            import_certs(&mut config, certs)?;
        }

        Ok(())
    }
}

pub fn dispatch_fetch(config: Config, c: cli::network::fetch::Command)
                      -> Result<()>
{
    let default_servers = default_keyservers_p(&c.servers);
    let servers = c.servers.iter().map(
        |uri| KeyServer::new(uri)
            .with_context(|| format!("Malformed keyserver URI: {}", uri))
            .map(Arc::new))
        .collect::<Result<Vec<_>>>()?;

    let queries = Query::parse(&c.query)?;
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let mut requests = JoinSet::new();
        queries.into_iter().for_each(|query| {
            for ks in servers.iter().cloned() {
                let query = query.clone();
                requests.spawn(async move {
                    let results = match query.clone() {
                        Query::Handle(h) => ks.get(h).await,
                        Query::Address(a) => ks.search(a).await,
                    };
                    Response {
                        query,
                        results,
                        method: Method::KeyServer(
                            ks.url().as_str().to_string()),
                    }
                });
            }

            if let Some(address) = query.as_address() {
                let a = address.to_string();
                requests.spawn(async move {
                    let results =
                        wkd::get(&net::reqwest::Client::new(), &a).await;
                    Response {
                        query: Query::Address(a),
                        results,
                        method: Method::WKD,
                    }
                });

                let a = address.to_string();
               requests.spawn(async move {
                    let results = dane::get(&a).await;
                    Response {
                        query: Query::Address(a),
                        results,
                        method: Method::DANE,
                    }
                });
            }
        });

        Response::collect(
            config, c.output, c.binary, requests, default_servers).await?;
        Result::Ok(())
    })
}

/// Figures out whether the given set of key servers is the default
/// set.
fn default_keyservers_p(servers: &[String]) -> bool {
    // XXX: This could be nicer, maybe with a custom clap parser
    // that encodes it in the type.  For now we live with the
    // false positive if someone explicitly provides the same set
    // of servers.
    use crate::cli::network::keyserver::DEFAULT_KEYSERVERS;
    servers.len() == DEFAULT_KEYSERVERS.len()
        && servers.iter().zip(DEFAULT_KEYSERVERS.iter())
        .all(|(a, b)| a == b)
}

pub fn dispatch_keyserver(config: Config, c: cli::network::keyserver::Command)
    -> Result<()>
{
    let default_servers = default_keyservers_p(&c.servers);
    let servers = c.servers.iter().map(
        |uri| KeyServer::new(uri)
            .with_context(|| format!("Malformed keyserver URI: {}", uri))
            .map(Arc::new))
        .collect::<Result<Vec<_>>>()?;

    let rt = tokio::runtime::Runtime::new()?;

    use crate::cli::network::keyserver::Subcommands::*;
    match c.subcommand {
        Fetch(c) => rt.block_on(async {
            let queries = Query::parse(&c.query)?;

            let mut requests = tokio::task::JoinSet::new();
            queries.into_iter().for_each(|query| {
                for ks in servers.iter().cloned() {
                    let query = query.clone();
                    requests.spawn(async move {
                        let results = match query.clone() {
                            Query::Handle(h) => ks.get(h).await,
                            Query::Address(a) => ks.search(a).await,
                        };
                        Response {
                            query,
                            results,
                            method: Method::KeyServer(
                                ks.url().as_str().to_string()),
                        }
                    });
                }
            });

            Response::collect(
                config, c.output, c.binary, requests, default_servers).await?;
            Result::Ok(())
        })?,
        Publish(c) => rt.block_on(async {
            let mut input = c.input.open()?;
            let cert = Arc::new(Cert::from_reader(&mut input).
                context("Malformed key")?);

            let mut requests = tokio::task::JoinSet::new();
            for ks in servers.iter().cloned() {
                let cert = cert.clone();
                requests.spawn(async move {
                    let response = ks.send(&cert).await;
                    (ks.url().to_string(), response)
                });
            }

            let mut one_ok = false;
            let mut result = Ok(());
            while let Some(response) = requests.join_next().await {
                let (url, response) = response?;
                match response {
                    Ok(()) => {
                        wprintln!("{}: ok", url);
                        one_ok = true;
                    },
                    Err(e) if default_servers
                        && url == "hkps://mail-api.proton.me" =>
                    {
                        // Currently, the Proton keyserver is
                        // read-only, but may change to accept updates
                        // in the future.  We still send them updates
                        // by default, but we will not consider this
                        // an error, and only print the message in
                        // verbose mode.
                        if config.verbose {
                            wprintln!("{}: {}", url, e);
                        }
                    },
                    Err(e) => {
                        if result.is_ok() {
                            result = Err((url, e));
                        } else {
                            wprintln!("{}: {}", url, e);
                        }
                    },
                }
            }

            if ! c.require_all && one_ok && result.is_err() {
                // We don't require all requests to be successful,
                // there was a successful one, but also at least one
                // error that we didn't yet report.  Report that now,
                // and clear it.
                let (url, e) = result.unwrap_err();
                wprintln!("{}: {}", url, e);
                result = Ok(());
            }

            result.map_err(|(_url, e)| e)
        })?,
    }

    Ok(())
}

pub fn dispatch_wkd(config: Config, c: cli::network::wkd::Command) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;

    use crate::cli::network::wkd::Subcommands::*;
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
        Fetch(c) => rt.block_on(async {
            let queries = Query::parse_addresses(&c.addresses)?;
            let mut requests = tokio::task::JoinSet::new();
            queries.into_iter().for_each(|query| {
                requests.spawn(async move {
                    let results = wkd::get(
                        &net::reqwest::Client::new(),
                        query.as_address().expect("parsed only addresses"))
                        .await;
                    Response {
                        query,
                        results,
                        method: Method::WKD,
                    }
                });
            });

            Response::collect(
                config, c.output, c.binary, requests, false).await?;
            Result::Ok(())
        })?,
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

pub fn dispatch_dane(config: Config, c: cli::network::dane::Command) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;

    use crate::cli::network::dane::Subcommands::*;
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
        Fetch(c) => rt.block_on(async {
            let queries = Query::parse_addresses(&c.addresses)?;
            let mut requests = tokio::task::JoinSet::new();
            queries.into_iter().for_each(|query| {
                requests.spawn(async move {
                    let results = dane::get(
                        query.as_address().expect("parsed only addresses"))
                        .await;
                    Response {
                        query,
                        results,
                        method: Method::DANE,
                    }
                });
            });

            Response::collect(
                config, c.output, c.binary, requests, false).await?;
            Result::Ok(())
        })?,
    }

    Ok(())
}
