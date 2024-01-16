#![doc(html_favicon_url = "https://docs.sequoia-pgp.org/favicon.png")]
#![doc(html_logo_url = "https://docs.sequoia-pgp.org/logo.svg")]

#![allow(rustdoc::invalid_rust_codeblocks)]
#![allow(rustdoc::broken_intra_doc_links)]
#![allow(rustdoc::bare_urls)]
#![doc = include_str!("../README.md")]

use anyhow::Context as _;

use std::borrow::Borrow;
use std::cell::OnceCell;
use std::collections::btree_map::{BTreeMap, Entry};
use std::fmt;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime};
use std::sync::Arc;

use sequoia_openpgp as openpgp;

use openpgp::{
    KeyHandle,
    Result,
};
use openpgp::{armor, Cert};
use openpgp::cert::raw::RawCertParser;
use openpgp::crypto::Password;
use openpgp::Fingerprint;
use openpgp::packet::prelude::*;
use openpgp::parse::Parse;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::packet::signature::subpacket::NotationDataFlags;
use openpgp::serialize::Serialize;
use openpgp::cert::prelude::*;
use openpgp::policy::{Policy, StandardPolicy as P};
use openpgp::serialize::SerializeInto;
use openpgp::types::KeyFlags;
use openpgp::types::RevocationStatus;
use openpgp::types::SignatureType;

use sequoia_cert_store as cert_store;
use cert_store::Store;
use cert_store::store::StoreError;
use cert_store::store::StoreUpdate;
use cert_store::store::UserIDQueryParams;

use sequoia_wot as wot;
use wot::store::Store as _;

use clap::FromArgMatches;

#[macro_use] mod macros;
#[macro_use] mod log;

mod common;

mod cli;
use cli::SECONDS_IN_DAY;
use cli::SECONDS_IN_YEAR;
use cli::SqSubcommands;
use cli::types::Time;
use cli::output::{OutputFormat, OutputVersion};

mod commands;
pub mod output;
pub use output::{wkd::WkdUrlVariant, Model};

/// Converts sequoia_openpgp types for rendering.
pub trait Convert<T> {
    /// Performs the conversion.
    fn convert(self) -> T;
}

impl Convert<humantime::FormattedDuration> for std::time::Duration {
    fn convert(self) -> humantime::FormattedDuration {
        humantime::format_duration(self)
    }
}

impl Convert<humantime::FormattedDuration> for openpgp::types::Duration {
    fn convert(self) -> humantime::FormattedDuration {
        humantime::format_duration(self.into())
    }
}

impl Convert<chrono::DateTime<chrono::offset::Utc>> for std::time::SystemTime {
    fn convert(self) -> chrono::DateTime<chrono::offset::Utc> {
        chrono::DateTime::<chrono::offset::Utc>::from(self)
    }
}

impl Convert<chrono::DateTime<chrono::offset::Utc>> for openpgp::types::Timestamp {
    fn convert(self) -> chrono::DateTime<chrono::offset::Utc> {
        std::time::SystemTime::from(self).convert()
    }
}

/// Loads one TSK from every given file.
fn load_keys<'a, I>(files: I) -> openpgp::Result<Vec<Cert>>
    where I: Iterator<Item=&'a Path>
{
    let mut certs = vec![];
    for f in files {
        let cert = Cert::from_file(f)
            .context(format!("Failed to load key from file {:?}", f))?;
        if ! cert.is_tsk() {
            return Err(anyhow::anyhow!(
                "Cert in file {:?} does not contain secret keys", f));
        }
        certs.push(cert);
    }
    Ok(certs)
}

/// Loads one or more certs from every given file.
fn load_certs<'a, I>(files: I) -> openpgp::Result<Vec<Cert>>
    where I: Iterator<Item=&'a Path>
{
    let mut certs = vec![];
    for f in files {
        for maybe_cert in CertParser::from_file(f)
            .context(format!("Failed to load certs from file {:?}", f))?
        {
            certs.push(maybe_cert.context(
                format!("A cert from file {:?} is bad", f)
            )?);
        }
    }
    Ok(certs)
}

/// Merges duplicate certs in a keyring.
fn merge_keyring<C>(certs: C) -> Result<BTreeMap<Fingerprint, Cert>>
where
    C: IntoIterator<Item = Cert>,
{
    let mut merged = BTreeMap::new();
    for cert in certs {
        match merged.entry(cert.fingerprint()) {
            Entry::Vacant(e) => {
                e.insert(cert);
            },
            Entry::Occupied(mut e) => {
                let old = e.get().clone();
                e.insert(old.merge_public(cert)?);
            },
        }
    }
    Ok(merged)
}

/// Serializes a keyring, adding descriptive headers if armored.
#[allow(dead_code)]
fn serialize_keyring(mut output: &mut dyn io::Write, certs: Vec<Cert>,
                     binary: bool)
                     -> openpgp::Result<()> {
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

    // Otherwise, merge the certs.
    let merged = merge_keyring(certs)?;

    // Then, collect the headers.
    let mut headers = Vec::new();
    for (i, cert) in merged.values().enumerate() {
        headers.push(format!("Key #{}", i));
        headers.append(&mut cert.armor_headers());
    }

    let headers: Vec<_> = headers.iter()
        .map(|value| ("Comment", value.as_str()))
        .collect();
    let mut output = armor::Writer::with_headers(&mut output,
                                                 armor::Kind::PublicKey,
                                                 headers)?;
    for cert in merged.values() {
        cert.serialize(&mut output)?;
    }
    output.finalize()?;
    Ok(())
}

/// Best-effort heuristic to compute the primary User ID of a given cert.
pub fn best_effort_primary_uid<'u, T>(cert: &'u Cert,
                                      policy: &'u dyn Policy,
                                      time: T)
                                      -> &'u UserID
where
    T: Into<Option<SystemTime>>,
{
    let time = time.into();

    // Try to be more helpful by including a User ID in the
    // listing.  We'd like it to be the primary one.  Use
    // decreasingly strict policies.
    let mut primary_uid = None;

    // First, apply our policy.
    if let Ok(vcert) = cert.with_policy(policy, time) {
        if let Ok(primary) = vcert.primary_userid() {
            primary_uid = Some(primary.userid());
        }
    }

    // Second, apply the null policy.
    if primary_uid.is_none() {
        const NULL: openpgp::policy::NullPolicy =
            openpgp::policy::NullPolicy::new();
        if let Ok(vcert) = cert.with_policy(&NULL, time) {
            if let Ok(primary) = vcert.primary_userid() {
                primary_uid = Some(primary.userid());
            }
        }
    }

    // As a last resort, pick the first user id.
    if primary_uid.is_none() {
        if let Some(primary) = cert.userids().next() {
            primary_uid = Some(primary.userid());
        } else {
            // Special case, there is no user id.
            use std::sync::OnceLock;
            static FALLBACK: OnceLock<UserID> = OnceLock::new();
            primary_uid =
                Some(FALLBACK.get_or_init(|| UserID::from("<unknown>")));
        }
    }

    primary_uid.expect("set at this point")
}

// Decrypts a key, if possible.
//
// The passwords in `passwords` are tried first.  If the key can't be
// decrypted using those, the user is prompted.  If a valid password
// is entered, it is added to `passwords`.
fn decrypt_key<R>(key: Key<key::SecretParts, R>, passwords: &mut Vec<Password>)
    -> Result<Key<key::SecretParts, R>>
    where R: key::KeyRole + Clone
{
    let key = key.parts_as_secret()?;
    match key.secret() {
        SecretKeyMaterial::Unencrypted(_) => {
            Ok(key.clone())
        }
        SecretKeyMaterial::Encrypted(e) => {
            if ! e.s2k().is_supported() {
                return Err(anyhow::anyhow!(
                    "Unsupported key protection mechanism"));
            }

            for p in passwords.iter() {
                if let Ok(key)
                    = key.clone().decrypt_secret(&p)
                {
                    return Ok(key);
                }
            }

            loop {
                // Prompt the user.
                match common::password::prompt_to_unlock_or_cancel(&format!(
                    "key {}", key.keyid(),
                )) {
                    Ok(None) => break, // Give up.
                    Ok(Some(p)) => {
                        if let Ok(key) = key
                            .clone()
                            .decrypt_secret(&p)
                        {
                            passwords.push(p.into());
                            return Ok(key);
                        }

                        wprintln!("Incorrect password.");
                    }
                    Err(err) => {
                        wprintln!("While reading password: {}", err);
                        break;
                    }
                }
            }

            Err(anyhow::anyhow!("Key {}: Unable to decrypt secret key material",
                                key.keyid().to_hex()))
        }
    }
}

/// Prints a warning if the user supplied "help" or "-help" to an
/// positional argument.
///
/// This should be used wherever a positional argument is followed by
/// an optional positional argument.
#[allow(dead_code)]
fn help_warning(arg: &str) {
    if arg == "help" {
        wprintln!("Warning: \"help\" is not a subcommand here.  \
                   Did you mean --help?");
    }
}

pub struct Config<'a> {
    verbose: bool,
    force: bool,
    output_format: OutputFormat,
    output_version: Option<OutputVersion>,
    policy: P<'a>,
    time: SystemTime,
    // --no-cert-store
    no_rw_cert_store: bool,
    cert_store_path: Option<PathBuf>,
    pep_cert_store_path: Option<PathBuf>,
    keyrings: Vec<PathBuf>,
    // This will be set if --no-cert-store is not passed, OR --keyring
    // is passed.
    cert_store: OnceCell<cert_store::CertStore<'a>>,

    // The value of --trust-root.
    trust_roots: Vec<Fingerprint>,
    // The local trust root, as set in the cert store.
    trust_root_local: OnceCell<Option<Fingerprint>>,
}

impl<'store> Config<'store> {
    /// Returns the cert store's base directory, if it is enabled.
    fn cert_store_base(&self) -> Option<PathBuf> {
        if self.no_rw_cert_store {
            None
        } else if let Some(path) = self.cert_store_path.as_ref() {
            Some(path.clone())
        } else {
            // XXX: openpgp-cert-d doesn't yet export this:
            // https://gitlab.com/sequoia-pgp/pgp-cert-d/-/issues/34
            // Remove this when it does.
            let pathbuf = dirs::data_dir()
                .expect("Unsupported platform")
                .join("pgp.cert.d");
            Some(pathbuf)
        }
    }

    /// Returns the cert store.
    ///
    /// If the cert store is disabled, returns `Ok(None)`.  If it is not yet
    /// open, opens it.
    fn cert_store(&self) -> Result<Option<&cert_store::CertStore<'store>>> {
        if self.no_rw_cert_store
            && self.keyrings.is_empty()
            && self.pep_cert_store_path.is_none()
        {
            // The cert store is disabled.
            return Ok(None);
        }

        if let Some(cert_store) = self.cert_store.get() {
            // The cert store is already initialized, return it.
            return Ok(Some(cert_store));
        }

        let create_dirs = |path: &Path| -> Result<()> {
            use std::fs::DirBuilder;

            let mut b = DirBuilder::new();
            b.recursive(true);

            // Create the parent with the normal umask.
            if let Some(parent) = path.parent() {
                // Note: since recursive is turned on, it is not an
                // error if the directory exists, which is exactly
                // what we want.
                b.create(parent)
                    .with_context(|| {
                        format!("Creating the directory {:?}", parent)
                    })?;
            }

            // Create path with more restrictive permissions.
            platform!{
                unix => {
                    use std::os::unix::fs::DirBuilderExt;
                    b.mode(0o700);
                },
                windows => {
                },
            }

            b.create(path)
                .with_context(|| {
                    format!("Creating the directory {:?}", path)
                })?;

            Ok(())
        };

        // We need to initialize the cert store.
        let mut cert_store = if ! self.no_rw_cert_store {
            // Open the cert-d.

            let path = self.cert_store_base()
                .expect("just checked that it is configured");

            create_dirs(&path)
                .and_then(|_| cert_store::CertStore::open(&path))
                .with_context(|| {
                    format!("While opening the certificate store at {:?}",
                            &path)
                })?
        } else {
            cert_store::CertStore::empty()
        };

        let mut keyring = cert_store::store::Certs::empty();
        let mut error = None;
        for filename in self.keyrings.iter() {
            let f = std::fs::File::open(filename)
                .with_context(|| format!("Open {:?}", filename))?;
            let parser = RawCertParser::from_reader(f)
                .with_context(|| format!("Parsing {:?}", filename))?;

            for cert in parser {
                match cert {
                    Ok(cert) => {
                        keyring.update(Arc::new(cert.into()))
                            .expect("implementation doesn't fail");
                    }
                    Err(err) => {
                        eprint!("Parsing certificate in {:?}: {}",
                                filename, err);
                        error = Some(err);
                    }
                }
            }
        }

        if let Some(err) = error {
            return Err(err).context("Parsing keyrings");
        }

        cert_store.add_backend(
            Box::new(keyring),
            cert_store::AccessMode::Always);

        if let Some(ref pep_cert_store) = self.pep_cert_store_path {
            let pep_cert_store = if pep_cert_store.is_dir() {
                pep_cert_store.join("keys.db")
            } else {
                match pep_cert_store.try_exists() {
                    Ok(true) => {
                        PathBuf::from(pep_cert_store)
                    }
                    Ok(false) => {
                        return Err(anyhow::anyhow!(
                            "{:?} does not exist", pep_cert_store));
                    }
                    Err(err) => {
                        return Err(anyhow::anyhow!(
                            "Accessing {:?}: {}", pep_cert_store, err));
                    }
                }
            };

            let pep = cert_store::store::pep::Pep::open(Some(&pep_cert_store))?;

            cert_store.add_backend(
                Box::new(pep),
                cert_store::AccessMode::Always);
        }

        let _ = self.cert_store.set(cert_store);

        Ok(Some(self.cert_store.get().expect("just configured")))
    }

    /// Returns the cert store.
    ///
    /// If the cert store is disabled, returns an error.
    fn cert_store_or_else(&self) -> Result<&cert_store::CertStore<'store>> {
        self.cert_store().and_then(|cert_store| cert_store.ok_or_else(|| {
            anyhow::anyhow!("Operation requires a certificate store, \
                             but the certificate store is disabled")
        }))
    }

    /// Returns a mutable reference to the cert store.
    ///
    /// If the cert store is disabled, returns None.  If it is not yet
    /// open, opens it.
    fn cert_store_mut(&mut self)
        -> Result<Option<&mut cert_store::CertStore<'store>>>
    {
        if self.no_rw_cert_store {
            return Err(anyhow::anyhow!(
                "Operation requires a certificate store, \
                 but the certificate store is disabled"));
        }

        // self.cert_store() will do any required initialization, but
        // it will return an immutable reference.
        self.cert_store()?;
        Ok(self.cert_store.get_mut())
    }

    /// Returns a mutable reference to the cert store.
    ///
    /// If the cert store is disabled, returns an error.
    fn cert_store_mut_or_else(&mut self) -> Result<&mut cert_store::CertStore<'store>> {
        self.cert_store_mut().and_then(|cert_store| cert_store.ok_or_else(|| {
            anyhow::anyhow!("Operation requires a certificate store, \
                             but the certificate store is disabled")
        }))
    }

    /// Looks up an identifier.
    ///
    /// This matches on both the primary key and the subkeys.
    ///
    /// If `keyflags` is not `None`, then only returns certificates
    /// where the matching key has at least one of the specified key
    /// flags.  If `or_by_primary` is set, then certificates with the
    /// specified key handle and a subkey with the specified flags
    /// also match.
    ///
    /// If `allow_ambiguous` is true, then all matching certificates
    /// are returned.  Otherwise, if an identifier matches multiple
    /// certificates an error is returned.
    ///
    /// An error is also returned if any of the identifiers does not
    /// match at least one certificate.
    fn lookup<'a, I>(&self, khs: I,
                     keyflags: Option<KeyFlags>,
                     or_by_primary: bool,
                     allow_ambiguous: bool)
              -> Result<Vec<Cert>>
    where I: IntoIterator,
          I::Item: Borrow<KeyHandle>,
    {
        let mut results = Vec::new();

        for kh in khs {
            let kh = kh.borrow();
            match self.cert_store_or_else()?.lookup_by_cert_or_subkey(&kh) {
                Err(err) => {
                    let err = anyhow::Error::from(err);
                    return Err(err.context(
                        format!("Failed to load {} from certificate store", kh)
                    ));
                }
                Ok(certs) => {
                    let mut certs = certs.into_iter()
                        .filter_map(|cert| {
                            match cert.to_cert() {
                                Ok(cert) => Some(cert.clone()),
                                Err(err) => {
                                    let err = err.context(
                                        format!("Failed to parse {} as loaded \
                                                 from certificate store", kh));
                                    print_error_chain(&err);
                                    None
                                }
                            }
                        })
                        .collect::<Vec<Cert>>();

                    if let Some(keyflags) = keyflags.as_ref() {
                        certs.retain(|cert| {
                            let vc = match cert.with_policy(
                                &self.policy, self.time)
                            {
                                Ok(vc) => vc,
                                Err(err) => {
                                    let err = err.context(
                                        format!("{} is not valid according \
                                                 to the current policy, ignoring",
                                                kh));
                                    print_error_chain(&err);
                                    return false;
                                }
                            };

                            let checked_id = or_by_primary
                                && vc.key_handle().aliases(kh);

                            for ka in vc.keys() {
                                if checked_id || ka.key_handle().aliases(kh) {
                                    if &ka.key_flags().unwrap_or(KeyFlags::empty())
                                        & keyflags
                                        != KeyFlags::empty()
                                    {
                                        return true;
                                    }
                                }
                            }

                            if checked_id {
                                wprintln!("Error: {} does not have a key with \
                                           the required capabilities ({:?})",
                                          cert.keyid(), keyflags);
                            } else {
                                wprintln!("Error: The subkey {} (cert: {}) \
                                           does not the required capabilities \
                                           ({:?})",
                                          kh, cert.keyid(), keyflags);
                            }
                            return false;
                        })
                    }

                    if ! allow_ambiguous && certs.len() > 1 {
                        return Err(anyhow::anyhow!(
                            "{} is ambiguous; it matches: {}",
                            kh,
                            certs.into_iter()
                                .map(|cert| cert.fingerprint().to_string())
                                .collect::<Vec<String>>()
                                .join(", ")));
                    }

                    if certs.len() == 0 {
                        return Err(StoreError::NotFound(kh.clone()).into());
                    }

                    results.extend(certs);
                }
            }
        }

        Ok(results)
    }

    /// Looks up certificates by User ID or email address.
    ///
    /// This only returns certificates that can be authenticate for
    /// the specified User ID (or email address, if `email` is true).
    /// If no certificate can be authenticated for some User ID,
    /// returns an error.  If multiple certificates can be
    /// authenticated for a given User ID or email address, then
    /// returns them all.
    fn lookup_by_userid(&self, userid: &[String], email: bool)
        -> Result<Vec<Cert>>
    {
        if userid.is_empty() {
            return Ok(Vec::new())
        }

        let cert_store = self.cert_store_or_else()?;

        // Build a WoT network.

        let cert_store = wot::store::CertStore::from_store(
            cert_store, &self.policy, self.time);
        let n = wot::Network::new(&cert_store)?;
        let mut q = wot::QueryBuilder::new(&n);
        q.roots(wot::Roots::new(self.trust_roots().iter().cloned()));
        let q = q.build();

        let mut results: Vec<Cert> = Vec::new();
        // We try hard to not just stop at the first error, but lint
        // the input so that the user gets as much feedback as
        // possible.  The first error that we encounter is saved here,
        // and returned.  The rest are printed directly.
        let mut error: Option<anyhow::Error> = None;

        // Iterate over each User ID address, find any certificates
        // associated with the User ID, validate the certificates, and
        // finally authenticate them for the User ID.
        for userid in userid.iter() {
            let matches: Vec<(Fingerprint, UserID)> = if email {
                if let Err(err) = UserIDQueryParams::is_email(userid) {
                    wprintln!("{:?} is not a valid email address", userid);
                    if error.is_none() {
                        error = Some(err);
                    }

                    continue;
                }

                // Get all certificates that are associated with the email
                // address.
                cert_store.lookup_synopses_by_email(userid)
            } else {
                let userid = UserID::from(&userid[..]);
                cert_store.lookup_synopses_by_userid(userid.clone())
                    .into_iter()
                    .map(|fpr| (fpr, userid.clone()))
                    .collect()
            };

            if matches.is_empty() {
                return Err(anyhow::anyhow!(
                    "No certificates are associated with {:?}",
                    userid));
            }

            struct Entry {
                fpr: Fingerprint,
                userid: UserID,
                cert: Result<Cert>,
            }
            let entries = matches.into_iter().map(|(fpr, userid)| {
                // We've got a match, or two, or three...  Lookup the certs.
                let cert = match cert_store.lookup_by_cert_fpr(&fpr) {
                    Ok(cert) => cert,
                    Err(err) => {
                        let err = err.context(format!(
                            "Error fetching {} ({:?})",
                            fpr, String::from_utf8_lossy(userid.value())));
                        return Entry { fpr, userid, cert: Err(err), };
                    }
                };

                // Parse the LazyCerts.
                let cert = match cert.to_cert() {
                    Ok(cert) => cert.clone(),
                    Err(err) => {
                        let err = err.context(format!(
                            "Error parsing {} ({:?})",
                            fpr, String::from_utf8_lossy(userid.value())));
                        return Entry { fpr, userid, cert: Err(err), };
                    }
                };

                // Check the certs for validity.
                let vc = match cert.with_policy(&self.policy, self.time) {
                    Ok(vc) => vc,
                    Err(err) => {
                        let err = err.context(format!(
                            "Certificate {} ({:?}) is invalid",
                            fpr, String::from_utf8_lossy(userid.value())));
                        return Entry { fpr, userid, cert: Err(err) };
                    }
                };

                if let Err(err) = vc.alive() {
                    let err = err.context(format!(
                        "Certificate {} ({:?}) is invalid",
                        fpr, String::from_utf8_lossy(userid.value())));
                    return Entry { fpr, userid, cert: Err(err), };
                }

                if let RevocationStatus::Revoked(_) = vc.revocation_status() {
                    let err = anyhow::anyhow!(
                        "Certificate {} ({:?}) is revoked",
                        fpr, String::from_utf8_lossy(userid.value()));
                    return Entry { fpr, userid, cert: Err(err), };
                }

                if let Some(ua) = vc.userids().find(|ua| {
                    ua.userid() == &userid
                })
                {
                    if let RevocationStatus::Revoked(_) = ua.revocation_status() {
                        let err = anyhow::anyhow!(
                            "User ID {:?} on certificate {} is revoked",
                            String::from_utf8_lossy(userid.value()), fpr);
                        return Entry { fpr, userid, cert: Err(err), };
                    }
                }

                // Authenticate the bindings.
                let paths = q.authenticate(
                    &userid, cert.fingerprint(),
                    // XXX: Make this user configurable.
                    wot::FULLY_TRUSTED);
                let r = if paths.amount() < wot::FULLY_TRUSTED {
                    Err(anyhow::anyhow!(
                        "{}, {:?} cannot be authenticated at the \
                         required level ({} of {}).  After checking \
                         that {} really controls {}, you could certify \
                         their certificate by running \
                         `sq link add {} {:?}`.",
                        cert.fingerprint(),
                        String::from_utf8_lossy(userid.value()),
                        paths.amount(), wot::FULLY_TRUSTED,
                        String::from_utf8_lossy(userid.value()),
                        cert.fingerprint(),
                        cert.fingerprint(),
                        String::from_utf8_lossy(userid.value())))
                } else {
                    Ok(cert)
                };

                Entry { fpr, userid, cert: r, }
            });

            // Partition into good (successfully authenticated) and
            // bad (an error occurred).
            let (good, bad): (Vec<Entry>, _)
                = entries.partition(|entry| entry.cert.is_ok());

            if good.is_empty() {
                // We've only got errors.

                let err = if bad.is_empty() {
                    // We got nothing :/.
                    if email {
                        anyhow::anyhow!(
                            "No known certificates have the email address {:?}",
                            userid)
                    } else {
                        anyhow::anyhow!(
                            "No known certificates have the User ID {:?}",
                            userid)
                    }
                } else {
                    if email {
                        anyhow::anyhow!(
                            "None of the certificates with the email \
                             address {:?} can be authenticated using \
                             the configured trust model",
                            userid)
                    } else {
                        anyhow::anyhow!(
                            "None of the certificates with the User ID \
                             {:?} can be authenticated using \
                             the configured trust model",
                            userid)
                    }
                };

                wprintln!("{:?}:\n", err);
                if error.is_none() {
                    error = Some(err);
                }

                // Print the errors.
                for (i, Entry { fpr, userid, cert }) in bad.into_iter().enumerate() {
                    wprintln!("{}. When considering {} ({}):",
                              i + 1, fpr,
                              String::from_utf8_lossy(userid.value()));
                    let err = match cert {
                        Ok(_) => unreachable!(),
                        Err(err) => err,
                    };

                    print_error_chain(&err);
                }
            } else {
                // We have at least one authenticated certificate.
                // Silently ignore any errors.
                results.extend(
                    good.into_iter().filter_map(|Entry { cert, .. }| {
                        cert.ok()
                    }));
            }
        }

        if let Some(error) = error {
            Err(error)
        } else {
            Ok(results)
        }
    }


    /// Looks up a certificate.
    ///
    /// Like `lookup`, but looks up a certificate, which must be
    /// uniquely identified by `kh` and `keyflags`.
    fn lookup_one(&self, kh: &KeyHandle,
                  keyflags: Option<KeyFlags>, or_by_primary: bool)
        -> Result<Cert>
    {
        self.lookup(std::iter::once(kh), keyflags, or_by_primary, false)
            .map(|certs| {
                assert_eq!(certs.len(), 1);
                certs.into_iter().next().expect("have one")
            })
    }

    /// Returns a special, creating it if necessary.
    ///
    /// Returns whether a key was created, and the key.
    fn get_special(&mut self, name: &str, userid: &str, create: bool)
        -> Result<(bool, Cert)>
    {
        // XXX: openpgp-cert-d only supports a single special,
        // "trust-root", even though the spec allows for other special
        // names.  To workaround this, we open the special files by
        // hand.  This is a bit unfortunate as we don't implement the
        // write lock.

        let filename = if let Some(base) = self.cert_store_base() {
            base.join(name)
        } else {
            return Err(anyhow::anyhow!(
                "A local trust root and other special certificates are \
                 only available when using an OpenPGP certificate \
                 directory"));
        };

        // Read it.
        //
        // XXX: Because we don't lock the cert-d, there is a chance
        // that we only read the first half of the key :/.
        let cert_bytes = match std::fs::read(&filename) {
            Ok(data) => Some(data),
            Err(err) => {
                let err = anyhow::Error::from(err);
                let mut not_found = false;
                if let Some(err) = err.downcast_ref::<std::io::Error>() {
                    if err.kind() == std::io::ErrorKind::NotFound {
                        not_found = true;
                    }
                }

                if ! not_found {
                    return Err(err).context(format!(
                        "Looking up {} ({}) in the certificate directory",
                        name, userid));
                }

                None
            }
        };

        let mut created = false;
        let special: Cert = if let Some(cert_bytes) = cert_bytes {
            Cert::from_bytes(&cert_bytes)
                .with_context(|| format!(
                    "Parsing {} ({}) in the certificate directory",
                    name, userid))?
        } else if ! create {
            return Err(anyhow::anyhow!(
                "Special certificate {} ({}) does not exist",
                name, userid));
        } else {
            // The special doesn't exist, but we should create it.
            let cert_builder = CertBuilder::new()
                .set_primary_key_flags(KeyFlags::empty().set_certification())
                // Set it in the past so that it is possible to use
                // the CA when the reference time is in the past.  Feb
                // 2002.
                .set_creation_time(
                    SystemTime::UNIX_EPOCH + Duration::new(1014235320, 0))
                // CAs should *not* expire.
                .set_validity_period(None)
                .add_userid_with(
                    UserID::from(userid),
                    SignatureBuilder::new(SignatureType::GenericCertification)
                        .set_exportable_certification(false)?,
                )?;

            let (special, _) = cert_builder.generate()?;
            let special_bytes = special.as_tsk().to_vec()?;

            // XXX: Because we don't lock the cert-d, there is a
            // (tiny) chance that we lost the race and the file will
            // now exist.  In that case, we really should try
            // rereading it.
            let mut f = std::fs::File::options()
                .read(true).write(true).create_new(true)
                .open(&filename)
                .with_context(|| format!("Creating {:?}", &filename))?;
            f.write_all(&special_bytes)
                .with_context(|| format!("Writing {:?}", &filename))?;

            created = true;

            // We also need to insert the trust root into the certificate
            // store, just without the secret key material.
            let cert_store = self.cert_store_mut_or_else()?;
            cert_store.update(Arc::new(special.clone().into()))
                .with_context(|| format!("Inserting {}", name))?;

            special
        };

        Ok((created, special))
    }

    const TRUST_ROOT: &'static str = "trust-root";

    /// Returns the local trust root, creating it if necessary.
    fn local_trust_root(&mut self) -> Result<Cert> {
        self.get_special(Self::TRUST_ROOT, "Local Trust Root", true)
            .map(|(_created, cert)| cert)
    }

    /// Returns the trust roots, including the cert store's trust
    /// root, if any.
    fn trust_roots(&self) -> Vec<Fingerprint> {
        let trust_root_local = self.trust_root_local.get_or_init(|| {
            self.cert_store_or_else()
                .ok()
                .and_then(|cert_store| cert_store.certd())
                .and_then(|certd| {
                    match certd.certd().get(Self::TRUST_ROOT) {
                        Ok(Some((_tag, cert_bytes))) => Some(cert_bytes),
                        // Not found.
                        Ok(None) => None,
                        Err(err) => {
                            wprintln!("Error looking up local trust root: {}",
                                      err);
                            None
                        }
                    }
                })
                .and_then(|cert_bytes| {
                    match RawCertParser::from_bytes(&cert_bytes[..]) {
                        Ok(mut parser) => {
                            match parser.next() {
                                Some(Ok(cert)) => Some(cert.fingerprint()),
                                Some(Err(err)) => {
                                    wprintln!("Local trust root is \
                                               corrupted: {}",
                                              err);
                                    None
                                }
                                None =>  {
                                    wprintln!("Local trust root is \
                                               corrupted: no data");
                                    None
                                }
                            }
                        }
                        Err(err) => {
                            wprintln!("Error parsing local trust root: {}",
                                      err);
                            None
                        }
                    }
                })
        });

        if let Some(trust_root_local) = trust_root_local {
            self.trust_roots.iter().cloned()
                .chain(std::iter::once(trust_root_local.clone()))
                .collect()
        } else {
            self.trust_roots.clone()
        }
    }

    /// Prints additional information in verbose mode.
    fn info(&self, msg: fmt::Arguments) {
        if self.verbose {
            wprintln!("{}", msg);
        }
    }
}

// TODO: Use `derive`d command structs. No more values_of
// TODO: Handling (and cli position) of global arguments
fn main() -> Result<()> {
    let c = cli::SqCommand::from_arg_matches(&cli::build().get_matches())?;

    let time: SystemTime = c.time.unwrap_or_else(|| Time::now()).into();

    let mut policy = sequoia_policy_config::ConfiguredStandardPolicy::new();
    policy.parse_default_config()?;
    let mut policy = policy.build();

    let known_notations = c.known_notation
        .iter()
        .map(|n| n.as_str())
        .collect::<Vec<&str>>();
    policy.good_critical_notations(&known_notations);

    let force = c.force;

    let output_version = if let Some(v) = c.output_version {
        Some(OutputVersion::from_str(&v)?)
    } else {
        None
    };

    let config = Config {
        verbose: c.verbose,
        force,
        output_format: c.output_format,
        output_version,
        policy,
        time,
        no_rw_cert_store: c.no_cert_store,
        cert_store_path: c.cert_store.clone(),
        pep_cert_store_path: c.pep_cert_store.clone(),
        keyrings: c.keyring.clone(),
        cert_store: OnceCell::new(),
        trust_roots: c.trust_roots.clone(),
        trust_root_local: Default::default(),
    };

    match c.subcommand {
        SqSubcommands::OutputVersions(command) => {
            if command.default {
                println!("{}", output::DEFAULT_OUTPUT_VERSION);
            } else {
                for v in output::OUTPUT_VERSIONS {
                    println!("{}", v);
                }
            }
        }

        SqSubcommands::Decrypt(command) => {
            commands::decrypt::dispatch(config, command)?
        },
        SqSubcommands::Encrypt(command) => {
            commands::encrypt::dispatch(config, command)?
        },
        SqSubcommands::Sign(command) => {
            commands::sign::dispatch(config, command)?
        },
        SqSubcommands::Verify(command) => {
            commands::verify::dispatch(config, command)?
        },
        SqSubcommands::Autocrypt(command) => {
            commands::autocrypt::dispatch(config, &command)?;
        },
        SqSubcommands::Inspect(command) => {
            commands::inspect::dispatch(config, command)?
        },

        SqSubcommands::Keyring(command) => {
            commands::keyring::dispatch(config, command)?
        },

        SqSubcommands::Import(command) => {
            commands::import::dispatch(config, command)?
        },

        SqSubcommands::Export(command) => {
            commands::export::dispatch(config, command)?
        },

        SqSubcommands::Packet(command) => {
            commands::packet::dispatch(config, command)?
        },

        SqSubcommands::Key(command) => {
            commands::key::dispatch(config, command)?
        }

        SqSubcommands::Link(command) => {
            commands::link::link(config, command)?
        }

        SqSubcommands::Pki(command) => {
            commands::pki::dispatch(config, command)?
        }

        SqSubcommands::Network(command) =>
            commands::net::dispatch(config, command)?,
    }

    Ok(())
}

fn parse_notations<N>(n: N) -> Result<Vec<(bool, NotationData)>>
where
    N: AsRef<[String]>,
{
    let n = n.as_ref();
    assert_eq!(n.len() % 2, 0, "notations must be pairs of key and value");

    // Each --notation takes two values.  Iterate over them in chunks of 2.
    let notations: Vec<(bool, NotationData)> = n
        .chunks(2)
        .map(|arg_pair| {
            let name = &arg_pair[0];
            let value = &arg_pair[1];

            let (critical, name) = match name.strip_prefix('!') {
                Some(name) => (true, name),
                None => (false, name.as_str()),
            };

            let notation_data = NotationData::new(
                name,
                value,
                NotationDataFlags::empty().set_human_readable(),
            );
            (critical, notation_data)
        })
        .collect();

    Ok(notations)
}

// Sometimes the same error cascades, e.g.:
//
// ```
// $ sq-wot --time 20230110T0406   --keyring sha1.pgp path B5FA089BA76FE3E17DC11660960E53286738F94C 231BC4AB9D8CAB86D1622CE02C0CE554998EECDB FABA8485B2D4D5BF1582AA963A8115E774FA9852 "<carol@example.org>"
// [ ] FABA8485B2D4D5BF1582AA963A8115E774FA9852 <carol@example.org>: not authenticated (0%)
//   ◯ B5FA089BA76FE3E17DC11660960E53286738F94C ("<alice@example.org>")
//   │   No adequate certification found.
//   │   No binding signature at time 2023-01-10T04:06:00Z
//   │     No binding signature at time 2023-01-10T04:06:00Z
//   │     No binding signature at time 2023-01-10T04:06:00Z
// ...
// ```
//
// Compress these.
fn error_chain(err: &anyhow::Error) -> Vec<String> {
    let mut errs = std::iter::once(err.to_string())
        .chain(err.chain().map(|source| source.to_string()))
        .collect::<Vec<String>>();
    errs.dedup();
    errs
}

/// Prints the error and causes, if any.
pub fn print_error_chain(err: &anyhow::Error) {
    wprintln!("           {}", err);
    err.chain().skip(1).for_each(|cause| wprintln!("  because: {}", cause));
}
