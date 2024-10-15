//! Network services.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::fs::{self, DirEntry};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Context;
use indicatif::ProgressBar;
use tokio::task::JoinSet;

use sequoia_openpgp as openpgp;
use openpgp::{
    Fingerprint,
    Result,
    KeyHandle,
    armor,
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
    serialize::Serialize,
    types::{
        KeyFlags,
        SignatureType,
    },
};
use sequoia_net as net;
use net::{
    KeyServer,
    wkd,
    dane,
    reqwest::{StatusCode, Url},
};

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;
use cert_store::Store;
use cert_store::StoreUpdate;
use cert_store::store::UserIDQueryParams;

use crate::{
    commands::{
        FileOrStdout,
        active_certification,
    },
    output::{
        pluralize::Pluralize,
    },
    Sq,
    print_error_chain,
    utils::cert_exportable,
};

use crate::cli;

/// User agent for http communications.
pub const USER_AGENT: &'static str = concat!("sq/", env!("CARGO_PKG_VERSION"));

/// How long to wait for the initial http connection.
pub const CONNECT_TIMEOUT: Duration = Duration::new(5, 0);

/// How long to wait for each individual http request.
pub const REQUEST_TIMEOUT: Duration = Duration::new(5, 0);

pub fn dispatch(sq: Sq, c: cli::network::Command)
                -> Result<()>
{
    use cli::network::Subcommands;
    match c.subcommand {
        Subcommands::Search(command) =>
            dispatch_search(sq, command),

        Subcommands::Keyserver(command) =>
            dispatch_keyserver(sq, command),

        Subcommands::Wkd(command) =>
            dispatch_wkd(sq, command),

        Subcommands::Dane(command) =>
            dispatch_dane(sq, command),
    }
}


/// Import the certificates into the local certificate store.
///
/// This does not certify the certificates.
pub fn import_certs(sq: &Sq, certs: Vec<Cert>) -> Result<()> {
    make_qprintln!(sq.quiet);

    if certs.is_empty() {
        // No need to do and say anything.
        return Ok(());
    }

    let cert_store = sq.cert_store_or_else()
        .context("Inserting results")?;

    let mut stats
        = cert_store::store::MergePublicCollectStats::new();

    for cert in certs.iter() {
        cert_store.update_by(Arc::new(cert.clone().into()), &mut stats)
            .with_context(|| {
                let sanitized_userid = sq.best_userid(&cert, true);

                format!("Inserting {}, {}",
                        cert.fingerprint(), sanitized_userid)
            })?;
    }

    qprintln!("\nImported {}, updated {}, {} unchanged, {}.",
              stats.new_certs().of("new certificate"),
              stats.updated_certs().of("certificate"),
              stats.unchanged_certs().of("certificate"),
              stats.errors().of("error"));

    for vcert in certs.iter()
        .filter_map(|cert| cert.with_policy(sq.policy, sq.time).ok())
    {
        let mut hint = sq.hint(format_args!(
            "After checking that the certificate {} really belongs to the \
             stated owner, you can mark the certificate as authenticated.  \
             Each stated user ID can be marked individually using:",
            vcert.fingerprint()));

        let mut count = 0;
        for uid in vcert.userids()
            .filter_map(|uid| std::str::from_utf8(uid.value())
                        .map(ToString::to_string).ok())
        {
            hint = hint
                .sq().arg("pki").arg("link").arg("add")
                .arg(vcert.fingerprint())
                .arg_value("--userid", uid)
                .done();

            count += 1;
        }

        if count > 1 {
            hint.hint(format_args!(
                "Alternatively, all user IDs can be marked as authenticated \
                 using:"))
                .sq().arg("pki").arg("link").arg("add")
                .arg(vcert.fingerprint())
                .arg("--all")
                .done();
        }
    }

    Ok(())
}

/// Serializes a keyring, adding descriptive headers if armored.
fn serialize_keyring(sq: &Sq, file: &FileOrStdout, certs: Vec<Cert>,
                     binary: bool)
                     -> openpgp::Result<()> {
    let mut output = file.create_safe(&sq)?;

    if certs.len() > 1 {
        let mut hint = sq.hint(format_args!(
            "To extract a particular certificate from {}, use any of:",
            file.path().map(|p| p.display().to_string())
                .unwrap_or_else(|| "the stream".into())));

        let path = file.path().map(|p| p.display().to_string())
                .unwrap_or_else(|| "...".into());
        for cert in &certs {
            hint = hint.sq()
                .arg("cert").arg("export")
                .arg_value("--keyring", &path)
                .arg_value("--cert", cert.fingerprint())
                .done();
        }
    }

    // Handle the easy options first.  No armor no cry:
    if binary {
        for cert in certs {
            cert.serialize(&mut output)?;
        }
        return Ok(());
    }

    // Just one Cert?  Ez:
    if certs.len() == 1 {
        return certs[0].armored().serialize(&mut output);
    }

    // Then, collect the headers.
    let mut headers = Vec::new();
    for (i, cert) in certs.iter().enumerate() {
        headers.push(format!("Key #{}", i));
        headers.append(&mut cert.armor_headers());
    }

    let headers: Vec<_> = headers.iter()
        .map(|value| ("Comment", value.as_str()))
        .collect();
    let mut output = armor::Writer::with_headers(&mut output,
                                                 armor::Kind::PublicKey,
                                                 headers)?;
    for cert in certs {
        cert.serialize(&mut output)?;
    }
    output.finalize()?;
    Ok(())
}

/// Creates a non-exportable certification for the specified bindings.
///
/// This does not import the certification or the certificate into
/// the certificate store.
fn certify(sq: &Sq,
           signer: &mut dyn Signer, cert: &Cert, userids: &[UserID],
           creation_time: Option<SystemTime>, depth: u8, amount: usize)
    -> Result<Cert>
{
    let mut builder = SignatureBuilder::new(SignatureType::GenericCertification);

    if depth != 0 || amount != 120 {
        builder = builder.set_trust_signature(depth, amount.min(255) as u8)?;
    }

    builder = builder.set_exportable_certification(false)?;

    if let Some(creation_time) = creation_time {
        builder = builder.set_signature_creation_time(creation_time)?;
    }

    let certifications = active_certification(
            sq, cert,
            userids.iter().cloned().collect(),
            signer.public())
        .into_iter()
        .map(|(userid, active_certification)| {
            if let Some(_) = active_certification {
                sq.info(format_args!(
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
                sq.info(format_args!(
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
pub fn certify_downloads<'store, 'rstore>(sq: &mut Sq<'store, 'rstore>,
                                          ca: Arc<LazyCert<'store>>,
                                          certs: Vec<Cert>, email: Option<&str>)
    -> Vec<Cert>
    where 'store: 'rstore
{
    let ca = || -> Result<_> {
        let ca = ca.to_cert()?;

        Ok(sq.get_certification_key(ca, None)?)
    };
    let mut ca_signer = match ca() {
        Ok(signer) => signer,
        Err(err) => {
            let err = err.context(
                "Warning: not recording provenance information, \
                 failed to load CA key");
            if sq.verbose {
                print_error_chain(&err);
            }
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
        let vc = match cert.with_policy(sq.policy, sq.time) {
            Err(err) => {
                let err = err.context(format!(
                    "Warning: not recording provenance information \
                     for {}, not valid",
                    cert.fingerprint()));
                if sq.verbose {
                    print_error_chain(&err);
                }
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
                if sq.verbose {
                    sq.info(format_args!(
                        "Warning: not recording provenance information \
                         for {}, it does not contain a valid User ID with \
                         the specified email address ({:?})",
                        cert.fingerprint(),
                        email));
                }
                return cert;
            }

            userids
        } else {
            vc.userids().map(|ua| ua.userid().clone()).collect()
        };

        match certify(
            sq, &mut ca_signer, &cert, &userids[..],
            Some(sq.time), 0, sequoia_wot::FULLY_TRUSTED)
        {
            Ok(cert) => cert,
            Err(err) => {
                let err = err.context(format!(
                    "Warning: not recording provenance information \
                     for {}, failed to certify it",
                    cert.fingerprint()));
                if sq.verbose {
                    print_error_chain(&err);
                }

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
    Url(Url),
}

impl From<Fingerprint> for Query {
    fn from(fp: Fingerprint) -> Query {
        Query::Handle(fp.into())
    }
}

impl fmt::Display for Query {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Query::Handle(h) => write!(f, "{}", h),
            Query::Address(a) => write!(f, "{}", a),
            Query::Url(u) => write!(f, "{}", u),
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
            } else if let Ok(url) = Url::parse(q.as_str()) {
                Ok(Query::Url(url))
            } else {
                Err(anyhow::anyhow!(
                    "Query must be a fingerprint, a keyid, \
                     an http or https Url, or an email address: {:?}", q))
            }).collect::<Result<Vec<Query>>>()
    }

    /// Parses command line arguments to queries suitable for key
    /// servers.
    fn parse_keyserver_queries(args: &[String]) -> Result<Vec<Query>> {
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

    /// Returns all known addresses and fingerprints of exportable
    /// certificates as queries.
    fn all_certs(sq: &Sq) -> Result<Vec<Query>> {
        if let Some(store) = sq.cert_store()? {
            let mut fingerprints = HashSet::new();
            let mut addresses = HashSet::new();
            for cert in store.certs().filter(
                |c| c.to_cert().map(|c| cert_exportable(c)).unwrap_or(false))
            {
                fingerprints.insert(cert.fingerprint());
                for address in cert.userids().filter_map(
                    |uid| uid.email2().ok().flatten().map(|s| s.to_string()))
                {
                    addresses.insert(address);
                }
            }

            Ok(fingerprints.into_iter().map(|fp| Query::Handle(fp.into()))
               .chain(addresses.into_iter().map(Query::Address))
               .collect())
        } else {
            Err(anyhow::anyhow!("no known certificates"))
        }
    }


    /// Returns all known addresses of exportable certificates as
    /// queries.
    fn all_addresses(sq: &Sq) -> Result<Vec<Query>> {
        if let Some(store) = sq.cert_store()? {
            let mut addresses = store.certs()
                .filter(
                    |c| c.to_cert().map(|c| cert_exportable(c)).unwrap_or(false))
                .flat_map(|cert| cert.userids().filter_map(
                    |uid| uid.email2().ok().flatten().map(|s| s.to_string()))
                          .collect::<Vec<_>>())
                .collect::<Vec<_>>();
            addresses.sort_unstable();
            addresses.dedup();
            Ok(addresses.into_iter().map(Query::Address).collect())
        } else {
            Err(anyhow::anyhow!("no known certificates"))
        }
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

    /// Returns the query if suitable for keyservers.
    fn as_keyserver_query(&self) -> Option<&Query> {
        match self {
            Query::Address(_) => Some(self),
            Query::Handle(_) => Some(self),
            _ => None,
        }
    }
}

#[derive(Clone)]
enum Method {
    KeyServer(String),
    WKD,
    DANE,
    Http(Url),
    CertStore,
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Method::KeyServer(url) => write!(f, "{}", url),
            Method::WKD => write!(f, "WKD"),
            Method::DANE => write!(f, "DANE"),
            Method::Http(_) => write!(f, "http"),
            Method::CertStore => write!(f, "CertStore"),
        }
    }
}

impl Method {
    // Returns the CA's certificate.
    //
    // This doesn't return an error, because not all methods have
    // shadow CAs, and a missing CA is not a hard error.
    fn ca<'store, 'rstore>(&self, sq: &Sq<'store, 'rstore>)
        -> Option<Arc<LazyCert<'store>>>
        where 'store: 'rstore
    {
        make_qprintln!(sq.quiet);

        let ca = || -> Result<_> {
            let certd = sq.certd_or_else()?;
            let (cert, created) = match self {
                Method::KeyServer(url) => {
                    let result = certd.shadow_ca_keyserver(url)?;

                    match result {
                        Some((cert, created)) => (cert, created),
                        None => {
                            if sq.verbose {
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
                Method::Http(url) =>
                    if let Some(r) = certd.shadow_ca_for_url(&url.to_string())? {
                        r
                    } else {
                        return Ok(None);
                    },
                Method::CertStore => return Ok(None),
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

                if sq.verbose {
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

        if sq.verbose {
            let invalid = "invalid data".to_string();

            wprintln!(
                "Created the local CA {} for certifying \
                 certificates downloaded from this service.  \
                 Use `sq pki link add --ca '*' --amount N {}` \
                 to change how much it is trusted.  Or \
                 `sq pki link retract {}` to disable it.",
                if let Ok(cert) = cert.to_cert() {
                    // We really want the self-signed, primary user
                    // ID.
                    sq.best_userid(cert, false).to_string()
                } else {
                    invalid
                },
                cert.fingerprint(), cert.fingerprint());
        } else {
            use std::sync::Once;
            static MSG: Once = Once::new();
            MSG.call_once(|| {
                qprintln!("Note: Created a local CA to record \
                           provenance information.\n\
                           Note: See `sq pki link list --ca` \
                           and `sq pki link --help` for more \
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
    /// Creates a progress bar.
    fn progress_bar(sq: &Sq) -> ProgressBar {
        if sq.verbose {
            ProgressBar::hidden()
        } else {
            ProgressBar::new(0)
        }
    }

    /// Collects the responses, and displays failures.
    ///
    /// Certs are collected into `certs`, and references to all newly
    /// discovered certs are returned.
    ///
    /// If `silent_errors` is given, then failure messages are
    /// suppressed unless --verbose is given, or there was not a
    /// single successful result.
    async fn collect<'store, 'rstore>(
        sq: &mut Sq<'store, 'rstore>,
        mut responses: JoinSet<Response>,
        certs: &mut BTreeMap<Fingerprint, Cert>,
        certify: bool,
        silent_errors: bool,
        pb: &mut ProgressBar,
    )
        -> Result<Vec<Fingerprint>>
    where
        'store: 'rstore
    {
        let mut new = Vec::new();

        /// Merges `cert` into `acc`, adding its fingerprint to `new`
        /// if the cert is new, or there are new user IDs.
        fn merge(acc: &mut BTreeMap<Fingerprint, Cert>,
                 new: &mut Vec<Fingerprint>,
                 cert: Cert)
                 -> Result<()>
        {
            use std::collections::btree_map::Entry;
            match acc.entry(cert.fingerprint()) {
                Entry::Occupied(e) => {
                    let e = e.into_mut();
                    let n_uids = e.userids().count();
                    *e = e.clone().merge_public(cert)?;
                    if e.userids().count() > n_uids {
                        new.push(e.fingerprint());
                    }
                },
                Entry::Vacant(e) => {
                    new.push(cert.fingerprint());
                    e.insert(cert);
                },
            }
            Ok(())
        }

        let mut errors = Vec::new();
        while let Some(response) = responses.join_next().await {
            pb.inc(1);
            let response = response?;
            match response.results {
                Ok(returned_certs) => for cert in returned_certs {
                    match cert {
                        Ok(cert) => if ! certify {
                            merge(certs, &mut new, cert)?;
                        } else { pb.suspend(|| -> Result<()> {
                            if let Some(ca) = response.method.ca(sq)
                            {
                                for cert in certify_downloads(
                                    sq, ca, vec![cert], None)
                                {
                                    merge(certs, &mut new, cert)?;
                                }
                            } else {
                                merge(certs, &mut new, cert)?;
                            }
                            Ok(())
                        })?},
                        Err(e) =>
                            errors.push((response.method.clone(),
                                         response.query.clone(), e)),
                    }
                },
                Err(e) =>
                    errors.push((response.method, response.query, e)),
            }
        }

        if ! silent_errors || sq.verbose || certs.is_empty() {
            for (method, query, e) in errors {
                pb.suspend(|| wprintln!("{}: {}: {}", method, query, e));
            }
        }

        if certs.is_empty() {
            Err(anyhow::anyhow!("No cert found."))
        } else {
            Ok(new)
        }
    }

    /// Either writes out a keyring or imports the certs.
    fn import_or_emit(mut sq: Sq<'_, '_>,
                      output: Option<FileOrStdout>,
                      binary: bool,
                      certs: BTreeMap<Fingerprint, Cert>)
                      -> Result<()>
    {
        make_qprintln!(sq.quiet);

        qprintln!("\nFound {} related to the query:\n",
                  certs.len().of("certificate"));

        let mut certs = certs.into_values()
            .map(|cert| {
                let userid = sq.best_userid(&cert, true);
                (userid, cert)
            })
            .collect::<Vec<_>>();

        // Reverse sort, i.e., most authenticated first.
        certs.sort_unstable_by_key(|cert| usize::MAX - cert.0.trust_amount());

        for (i, (userid, cert)) in certs.iter().enumerate() {
            qprintln!("  {}. {} {}", i + 1, cert.fingerprint(), userid);
        }

        let certs = certs.into_iter().map(|(_, cert)| cert).collect();

        if let Some(file) = &output {
            serialize_keyring(&sq, file, certs, binary)?;
        } else {
            import_certs(&mut sq, certs)?;
        }

        Ok(())
    }
}

/// How many times to iterate to discover related certificates.
const SEARCH_MAX_QUERY_ITERATIONS: usize = 3;

pub fn dispatch_search(mut sq: Sq, c: cli::network::search::Command)
                      -> Result<()>
{
    let default_servers = default_keyservers_p(&c.servers);
    let http_client = http_client()?;
    let servers = c.servers.iter().map(
        |uri| KeyServer::with_client(uri, http_client.clone())
            .with_context(|| format!("Malformed keyserver URI: {}", uri))
            .map(Arc::new))
        .collect::<Result<Vec<_>>>()?;

    let mut seen_emails = HashSet::new();
    let mut seen_fps = HashSet::new();
    let mut seen_ids = HashSet::new();
    let mut seen_urls = HashSet::new();
    let mut queries = if c.all {
        Query::all_certs(&sq)?
    } else {
        Query::parse(&c.query)?
    };
    let mut results = Default::default();
    let mut pb = Response::progress_bar(&sq);

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
      for _ in 0..SEARCH_MAX_QUERY_ITERATIONS {
        let mut requests = JoinSet::new();
        let mut converged = true;
        std::mem::take(&mut queries).into_iter().for_each(|query| {
            let new = match &query {
                Query::Handle(KeyHandle::Fingerprint(fp)) =>
                    seen_fps.insert(fp.clone()),
                Query::Handle(KeyHandle::KeyID(id)) =>
                    seen_ids.insert(id.clone()),
                Query::Address(addr) =>
                    seen_emails.insert(addr.clone()),
                Query::Url(url) =>
                    seen_urls.insert(url.clone()),
            };

            // Skip queries that we already did.
            if ! new {
                return;
            }
            converged = false;

            if let Some(query) = query.as_keyserver_query() {
                for ks in servers.iter().cloned() {
                    pb.inc_length(1);
                    let query = query.clone();
                    requests.spawn(async move {
                        let results = match query.clone() {
                            Query::Handle(h) => ks.get(h).await,
                            Query::Address(a) => ks.search(a).await,
                            Query::Url(_) => unreachable!(),
                        };
                        Response {
                            query,
                            results,
                            method: Method::KeyServer(
                                ks.url().as_str().to_string()),
                        }
                    });
                }
            }

            if let Some(address) = query.as_address() {
                let a = address.to_string();
                let http_client = http_client.clone();
                pb.inc_length(1);
                requests.spawn(async move {
                    let results =
                        wkd::get(&http_client, &a).await;
                    Response {
                        query: Query::Address(a),
                        results,
                        method: Method::WKD,
                    }
                });

                let a = address.to_string();
                pb.inc_length(1);
                requests.spawn(async move {
                    let results = dane::get(&a).await;
                    Response {
                        query: Query::Address(a),
                        results,
                        method: Method::DANE,
                    }
                });
            }

            if let Query::Url(url) = &query {
                let query = query.clone();
                let http_client = http_client.clone();
                let url = url.clone();
                pb.inc_length(1);
                requests.spawn(async move {
                    Response {
                        query,
                        results: match http_client.get(url.clone()).send().await
                        {
                            Ok(response) =>
                                response.bytes().await
                                .map_err(Into::into)
                                .and_then(|b| CertParser::from_bytes(&b)
                                          .map(|cp| cp.collect())),
                            Err(e) => Err(e.into()),
                        },
                        method: Method::Http(url),
                    }
                });
            }

            // Finally, we also consult the certificate store to
            // discover more identifiers.  This is sync, but we use
            // the same mechanism to merge the result back in.
            if let Ok(Some(store)) = sq.cert_store() {
                pb.inc_length(1);
                let mut email_query = UserIDQueryParams::new();
                email_query.set_email(true);
                email_query.set_ignore_case(true);

                let results = match &query {
                    Query::Handle(h) => store.lookup_by_cert(h),
                    Query::Address(a) => store.select_userid(&email_query, a),
                    Query::Url(_) => return,
                }.map(|r| r.into_iter().map(|c| c.to_cert().cloned()).collect());
                requests.spawn(async move {
                    Response {
                        query,
                        results,
                        method: Method::CertStore,
                    }
                });
            }
        });

        if converged {
            return Result::Ok(());
        }

        let new = Response::collect(
            &mut sq, requests, &mut results, c.output.is_none(),
            default_servers, &mut pb).await?;

        // Expand certs to discover new identifiers to query.
        for cert in new.iter().filter_map(|fp| results.get(fp)) {
            queries.push(Query::Handle(cert.key_handle()));

            for uid in cert.userids() {
                if let Ok(Some(addr)) = uid.email2() {
                    queries.push(Query::Address(addr.into()));
                }
            }
        }
      }

      Result::Ok(())
    })?;
    drop(pb);

    // Release all thread pool resources.
    drop(rt);

    Response::import_or_emit(sq, c.output, c.binary, results)?;
    Ok(())
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

pub fn dispatch_keyserver(mut sq: Sq,
                          c: cli::network::keyserver::Command)
    -> Result<()>
{
    make_qprintln!(sq.quiet);

    let default_servers = default_keyservers_p(&c.servers);
    let servers = c.servers.iter().map(
        |uri| KeyServer::with_client(uri, http_client()?)
            .with_context(|| format!("Malformed keyserver URI: {}", uri))
            .map(Arc::new))
        .collect::<Result<Vec<_>>>()?;

    let rt = tokio::runtime::Runtime::new()?;

    use crate::cli::network::keyserver::Subcommands::*;
    match c.subcommand {
        Search(c) => rt.block_on(async {
            let mut pb = Response::progress_bar(&sq);
            let queries = if c.all {
                Query::all_certs(&sq)?
            } else {
                Query::parse_keyserver_queries(&c.query)?
            };

            let mut requests = tokio::task::JoinSet::new();
            queries.into_iter().for_each(|query| {
                for ks in servers.iter().cloned() {
                    let query = query.clone();
                    pb.inc_length(1);
                    requests.spawn(async move {
                        let results = match query.clone() {
                            Query::Handle(h) => ks.get(h).await,
                            Query::Address(a) => ks.search(a).await,
                            Query::Url(_) => unreachable!(),
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

            let mut certs = Default::default();
            Response::collect(&mut sq, requests, &mut certs, c.output.is_none(),
                              default_servers, &mut pb).await?;
            drop(pb);
            Response::import_or_emit(sq, c.output, c.binary, certs)?;
            Result::Ok(())
        })?,

        Publish(c) => rt.block_on(async {
            let (certs, errors) = sq.resolve_certs(
                &c.certs, sequoia_wot::FULLY_TRUSTED)?;
            for error in errors.iter() {
                print_error_chain(error);
            }
            if ! errors.is_empty() {
                return Err(anyhow::anyhow!("Failed to resolve certificates"));
            }

            let mut requests = tokio::task::JoinSet::new();
            for ks in servers.iter() {
                for cert in certs.iter().cloned() {
                    let ks = ks.clone();
                    requests.spawn(async move {
                        let response = ks.send(&cert).await;
                        (ks.url().to_string(), cert, response)
                    });
                }
            }

            let mut result = Ok(());
            while let Some(response) = requests.join_next().await {
                let (url, cert, response) = response?;
                match response {
                    Ok(()) => {
                        qprintln!("{}: ok", url);
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
                        if sq.verbose {
                            wprintln!("{}: {}", url, e);
                        }
                    },
                    Err(e) => {
                        if url == "hkps://keys.mailvelope.com"
                            && matches!(e.downcast_ref(),
                                        Some(net::Error::HttpStatus(
                                            StatusCode::BAD_REQUEST)))
                            && cert.keys().with_policy(sq.policy, sq.time)
                            .key_flags(KeyFlags::empty()
                                       .set_transport_encryption()
                                       .set_storage_encryption())
                            .next().is_none()
                        {
                            sq.hint(format_args!(
                                "The Mailvelope key server rejects \
                                 certificates that are not \
                                 encryption-capable."));
                        }

                        wprintln!("{}: {}", url, e);
                        if result.is_ok() {
                            result = Err((url, e));
                        }
                    },
                }
            }

            result.map_err(|(_url, e)| e)
        })?,
    }

    Ok(())
}

pub fn dispatch_wkd(mut sq: Sq, c: cli::network::wkd::Command)
                    -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;

    use crate::cli::network::wkd::Subcommands::*;
    match c.subcommand {
        Search(c) => rt.block_on(async {
            let mut pb = Response::progress_bar(&sq);
            let http_client = http_client()?;
            let queries = if c.all {
                Query::all_addresses(&sq)?
            } else {
                Query::parse_addresses(&c.addresses)?
            };
            let mut requests = tokio::task::JoinSet::new();
            queries.into_iter().for_each(|query| {
                pb.inc_length(1);
                let http_client = http_client.clone();
                requests.spawn(async move {
                    let results = wkd::get(
                        &http_client,
                        query.as_address().expect("parsed only addresses"))
                        .await;
                    Response {
                        query,
                        results,
                        method: Method::WKD,
                    }
                });
            });

            let mut certs = Default::default();
            Response::collect(&mut sq, requests, &mut certs, c.output.is_none(),
                              false, &mut pb).await?;
            drop(pb);
            Response::import_or_emit(sq, c.output, c.binary, certs)?;
            Result::Ok(())
        })?,

        Publish(c) => {
            use wkd::Variant;
            let cert_store = sq.cert_store_or_else()?;

            let (insert, errors) = sq.resolve_certs(
                &c.certs, sequoia_wot::FULLY_TRUSTED)?;
            for error in errors.iter() {
                print_error_chain(error);
            }
            if ! errors.is_empty() {
                return Err(anyhow::anyhow!("Failed to resolve certificates"));
            }

            // Strategy: We transfer the WKD to a temporary directory,
            // read all the certs, update them from the local cert
            // store, re-create the WKD hierarchy, then transfer it
            // back.
            let wd = tempfile::TempDir::new()?;

            // First, fetch the WKD.
            let fetch = wd.path().join("fetch");
            fs::create_dir(&fetch)?;
            let r = transfer(&c.rsync,
                  &format!("{}/.well-known/openpgpkey", c.destination),
                  &fetch.display().to_string())
                .context("failed to copy the remote WKD hierarchy \
                          to the local system");
            if r.is_err() && c.create.is_none() {
                return r;
            }

            // Detect the variant by locating the policy file.
            let fetch = fetch.join("openpgpkey");
            let direct_policy = fetch.join("policy");
            let advanced_policy = fetch.join(&c.domain).join("policy");

            if c.create.is_some() && (direct_policy.exists()
                                      || advanced_policy.exists())
            {
                return Err(anyhow::anyhow!(
                    "Cannot create WKD because {} already contains one",
                    c.destination));
            }

            let (variant, policy) = match (direct_policy.exists(),
                                           advanced_policy.exists())
            {
                (true, false) => (Variant::Direct, Some(direct_policy)),
                (false, true) => (Variant::Advanced, Some(advanced_policy)),
                (false, false) => if let Some(m) = c.create {
                    (m.into(), None)
                } else {
                    return Err(anyhow::anyhow!("No policy file found")
                               .context("Neither direct nor advanced \
                                         WKD detected, consider using \
                                         --create"))
                },
                (true, true) =>
                    return Err(anyhow::anyhow!("Two policy files found")
                               .context("Both direct and advanced \
                                         WKD detected")),
            };
            let hu = match variant {
                Variant::Direct => fetch.join("hu"),
                Variant::Advanced => fetch.join(&c.domain).join("hu"),
            };

            // Now re-create the WKD hierarchy while updating the certs.
            let push = wd.path().join("push");
            let push_wk = push.join(".well-known");
            let push_openpgpkey = push_wk.join("openpgpkey");
            fs::create_dir(&push)?;
            visit_dirs(&hu, &|entry: &DirEntry| -> Result<()> {
                let p = entry.path();
                for cert in CertParser::from_reader(fs::File::open(p)?)? {
                    let mut cert = cert?;
                    if let Ok(update) =
                        cert_store.lookup_by_cert_fpr(&cert.fingerprint())
                    {
                        cert = cert.merge_public(update.to_cert()?.clone())?;
                    }

                    wkd::insert(&push, &c.domain, variant, &cert)?;
                }
                Ok(())
            })?;

            // Insert the new ones, if any.
            for cert in insert {
                wkd::insert(&push, &c.domain, variant, &cert)?;
            }

            // Preserve the original policy file, if any.
            if let Some(policy) = policy {
                match variant {
                    Variant::Direct => fs::copy(
                        policy,
                        push_openpgpkey.join("policy"))?,
                    Variant::Advanced => fs::copy(
                        policy,
                        push_openpgpkey.join(&c.domain).join("policy"))?,
                };
            }

            // Finally, transfer the WKD hierarchy back.
            transfer(&c.rsync, &push_wk.display().to_string(),
                     &format!("{}", c.destination))
                .context("failed to copy the local WKD hierarchy \
                          to the remote system")?;
        },
    }

    Ok(())
}

fn transfer(rsync_bin: &Option<String>, source: &str, destination: &str)
            -> Result<()>
{
    if let Some(r) = rsync_bin {
        rsync(r, source, destination)
    } else {
        copy(source, destination)
    }
}

fn copy(source: &str, destination: &str) -> Result<()> {
    let options = fs_extra::dir::CopyOptions::new()
        .overwrite(true);

    std::fs::create_dir_all(destination)?;
    fs_extra::dir::copy(source, destination, &options)?;
    Ok(())
}

fn rsync(rsync: &str, source: &str, destination: &str) -> Result<()> {
    use std::process::Command;

    let status = Command::new(rsync)
        .arg("--recursive")
        .arg(source)
        .arg(destination)
        .spawn()?
        .wait()?;

    if status.success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("rsync failed"))
    }
}

// one possible implementation of walking a directory only visiting files
fn visit_dirs(dir: &Path, cb: &dyn Fn(&DirEntry) -> Result<()>) -> Result<()> {
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                visit_dirs(&path, cb)?;
            } else {
                cb(&entry)?;
            }
        }
    }
    Ok(())
}

pub fn dispatch_dane(mut sq: Sq, c: cli::network::dane::Command)
                     -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;

    use crate::cli::network::dane::Subcommands::*;
    match c.subcommand {
        Generate(c) => {
            let (certs, errors) = sq.resolve_certs(
                &c.certs, sequoia_wot::FULLY_TRUSTED)?;
            for error in errors.iter() {
                print_error_chain(error);
            }
            if ! errors.is_empty() {
                return Err(anyhow::anyhow!("Failed to resolve certificates"));
            }

            for cert in certs {
                let vc = match cert.with_policy(sq.policy, sq.time) {
                    Ok(vc) => vc,
                    e @ Err(_) if ! c.skip => e?,
                    _ => continue,
                };

                use cli::network::dane::ResourceRecordType;
                let r = match c.typ {
                    ResourceRecordType::OpenPGP =>
                        dane::generate(&vc, &c.domain, c.ttl, c.size_limit),
                    ResourceRecordType::Generic =>
                        dane::generate_generic(&vc, &c.domain, c.ttl,
                                               c.size_limit),
                };

                match r {
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
        Search(c) => rt.block_on(async {
            let mut pb = Response::progress_bar(&sq);
            let queries = if c.all {
                Query::all_addresses(&sq)?
            } else {
                Query::parse_addresses(&c.addresses)?
            };
            let mut requests = tokio::task::JoinSet::new();
            queries.into_iter().for_each(|query| {
                pb.inc_length(1);
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

            let mut certs = Default::default();
            Response::collect(&mut sq, requests, &mut certs, c.output.is_none(),
                              false, &mut pb).await?;
            drop(pb);
            Response::import_or_emit(sq, c.output, c.binary, certs)?;
            Result::Ok(())
        })?,
    }

    Ok(())
}

/// Makes a http client.
fn http_client() -> Result<net::reqwest::Client> {
    Ok(net::reqwest::Client::builder()
        .user_agent(USER_AGENT)
	.connect_timeout(CONNECT_TIMEOUT)
	.timeout(REQUEST_TIMEOUT)
        .build()?)
}
