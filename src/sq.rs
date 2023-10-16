#![doc(html_favicon_url = "https://docs.sequoia-pgp.org/favicon.png")]
#![doc(html_logo_url = "https://docs.sequoia-pgp.org/logo.svg")]

#![allow(rustdoc::invalid_rust_codeblocks)]
#![allow(rustdoc::broken_intra_doc_links)]
#![allow(rustdoc::bare_urls)]
#![doc = include_str!(concat!(env!("OUT_DIR"), "/sq-usage.md"))]

use anyhow::Context as _;
use sq_cli::types::FileOrStdin;
use is_terminal::IsTerminal;

use std::borrow::Borrow;
use std::borrow::Cow;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime};
use chrono::{DateTime, offset::Utc};
use once_cell::unsync::OnceCell;

use terminal_size::terminal_size;

use buffered_reader::{BufferedReader, Dup, File, Limitor};
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
use openpgp::parse::{Parse, PacketParser, PacketParserResult};
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::packet::signature::subpacket::NotationDataFlags;
use openpgp::serialize::Serialize;
use openpgp::cert::prelude::*;
use openpgp::policy::StandardPolicy as P;
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

mod sq_cli;
use sq_cli::packet;
use sq_cli::SqSubcommands;
use sq_cli::SECONDS_IN_DAY;
use sq_cli::SECONDS_IN_YEAR;

mod man;
mod commands;
pub mod output;
pub use output::{wkd::WkdUrlVariant, Model, OutputFormat, OutputVersion};

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

/// Serializes a keyring, adding descriptive headers if armored.
#[allow(dead_code)]
fn serialize_keyring(mut output: &mut dyn io::Write, certs: &[Cert], binary: bool)
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

    // Otherwise, collect the headers first:
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

/// How much data to look at when detecting armor kinds.
const ARMOR_DETECTION_LIMIT: u64 = 1 << 24;

/// Peeks at the first packet to guess the type.
///
/// Returns the given reader unchanged.  If the detection fails,
/// armor::Kind::File is returned as safe default.
fn detect_armor_kind(
    input: Box<dyn BufferedReader<()>>,
) -> (Box<dyn BufferedReader<()>>, armor::Kind) {
    let mut dup =
        Limitor::new(Dup::new(input), ARMOR_DETECTION_LIMIT).as_boxed();
    let kind = match PacketParser::from_reader(&mut dup) {
        Ok(PacketParserResult::Some(pp)) => match pp.next() {
            Ok((Packet::Signature(_), _)) => armor::Kind::Signature,
            Ok((Packet::SecretKey(_), _)) => armor::Kind::SecretKey,
            Ok((Packet::PublicKey(_), _)) => armor::Kind::PublicKey,
            Ok((Packet::PKESK(_), _)) => armor::Kind::Message,
            Ok((Packet::SKESK(_), _)) => armor::Kind::Message,
            _ => armor::Kind::File,
        },
        _ => armor::Kind::File,
    };
    (dup.into_inner().unwrap().into_inner().unwrap(), kind)
}

// Decrypts a key, if possible.
//
// The passwords in `passwords` are tried first.  If the key can't be
// decrypted using those, the user is prompted.  If a valid password
// is entered, it is added to `passwords`.
fn decrypt_key<R>(key: Key<key::SecretParts, R>, passwords: &mut Vec<String>)
    -> Result<Key<key::SecretParts, R>>
    where R: key::KeyRole + Clone
{
    let key = key.parts_as_secret()?;
    match key.secret() {
        SecretKeyMaterial::Unencrypted(_) => {
            Ok(key.clone())
        }
        SecretKeyMaterial::Encrypted(_) => {
            for p in passwords.iter() {
                if let Ok(key)
                    = key.clone().decrypt_secret(&Password::from(&p[..]))
                {
                    return Ok(key);
                }
            }

            if std::io::stdin().is_terminal() {
                let mut first = true;
                loop {
                    // Prompt the user.
                    match rpassword::prompt_password(&format!(
                        "{}Enter password to unlock {} (blank to skip): ",
                        if first { "" } else { "Invalid password. " },
                        key.keyid().to_hex()
                    )) {
                        Ok(p) => {
                            first = false;
                            if p.is_empty() {
                                // Give up.
                                break;
                            }

                            if let Ok(key) = key
                                .clone()
                                .decrypt_secret(&Password::from(&p[..]))
                            {
                                passwords.push(p);
                                return Ok(key);
                            }
                        }
                        Err(err) => {
                            eprintln!("While reading password: {}", err);
                            break;
                        }
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
        eprintln!("Warning: \"help\" is not a subcommand here.  \
                   Did you mean --help?");
    }
}

pub struct Config<'a> {
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
                        keyring.update(Cow::Owned(cert.into()))
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
                        return Err(anyhow::anyhow!(format!(
                            "{:?} does not exist", pep_cert_store)));
                    }
                    Err(err) => {
                        return Err(anyhow::anyhow!(format!(
                            "Accessing {:?}: {}", pep_cert_store, err)));
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
            match self.cert_store_or_else()?.lookup_by_key(&kh) {
                Err(err) => {
                    let err = anyhow::Error::from(err);
                    return Err(err.context(
                        format!("Failed to load {} from certificate store", kh)
                    ));
                }
                Ok(certs) => {
                    let mut certs = certs.into_iter()
                        .filter_map(|cert| {
                            match cert.as_cert() {
                                Ok(cert) => Some(cert),
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
                                eprintln!("Error: {} does not have a key with \
                                           the required capabilities ({:?})",
                                          cert.keyid(), keyflags);
                            } else {
                                eprintln!("Error: The subkey {} (cert: {}) \
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
                    eprintln!("{:?} is not a valid email address", userid);
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
                let cert = match cert.into_owned().into_cert() {
                    Ok(cert) => cert,
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

                eprintln!("{:?}:\n", err);
                if error.is_none() {
                    error = Some(err);
                }

                // Print the errors.
                for (i, Entry { fpr, userid, cert }) in bad.into_iter().enumerate() {
                    eprintln!("{}. When considering {} ({}):",
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
            cert_store.update(Cow::Owned(special.clone().into()))
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
                            eprintln!("Error looking up local trust root: {}",
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
                                    eprintln!("Local trust root is \
                                               corrupted: {}",
                                              err);
                                    None
                                }
                                None =>  {
                                    eprintln!("Local trust root is \
                                               corrupted: no data");
                                    None
                                }
                            }
                        }
                        Err(err) => {
                            eprintln!("Error parsing local trust root: {}",
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
}

// TODO: Use `derive`d command structs. No more values_of
// TODO: Handling (and cli position) of global arguments
fn main() -> Result<()> {
    if let Ok(dirname) = std::env::var("SQ_MAN") {
        let dirname = PathBuf::from(dirname);
        if !dirname.exists() {
            std::fs::create_dir(&dirname)?;
        }
        for man in man::manpages(&sq_cli::build()) {
            std::fs::write(dirname.join(man.filename()), man.troff_source())?;
        }
        return Ok(())
    }

    let c = sq_cli::SqCommand::from_arg_matches(&sq_cli::build().get_matches())?;

    let time = if let Some(time) = c.time {
        SystemTime::from(
            crate::parse_iso8601(
                &time, chrono::NaiveTime::from_hms_opt(0, 0, 0).unwrap())
                .context(format!("Parsing --time {}", time))?)
    } else {
        // Round trip via openpgp::types::Timestamp.
        openpgp::types::Timestamp::try_from(SystemTime::now())
            .context("Current time is out of range")?
            .into()
    };

    let policy = &mut P::at(time);

    let known_notations = c.known_notation
        .iter()
        .map(|n| n.as_str())
        .collect::<Vec<&str>>();
    policy.good_critical_notations(&known_notations);

    let force = c.force;
    let output_format = OutputFormat::from_str(&c.output_format)?;
    let output_version = if let Some(v) = c.output_version {
        Some(OutputVersion::from_str(&v)?)
    } else {
        None
    };

    let config = Config {
        force,
        output_format,
        output_version,
        policy: policy.clone(),
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
            let mut input = command.input.open()?;
            let output = &command.output;
            let detached = command.detached;
            let binary = command.binary;
            let append = command.append;
            let notarize = command.notarize;
            let private_key_store = command.private_key_store.as_deref();
            let secrets =
                load_certs(command.secret_key_file.iter().map(|s| s.as_ref()))?;
            let time = Some(config.time);

            let notations = parse_notations(command.notation)?;

            if let Some(merge) = command.merge {
                let output = output.create_pgp_safe(
                    config.force,
                    binary,
                    armor::Kind::Message,
                )?;
                let data: FileOrStdin = merge.into();
                let mut input2 = data.open()?;
                commands::merge_signatures(&mut input, &mut input2, output)?;
            } else if command.clearsign {
                let output = output.create_safe(config.force)?;
                commands::sign::clearsign(config, private_key_store, input, output, secrets,
                                          time, &notations)?;
            } else {
                commands::sign(commands::sign::SignOpts {
                    config,
                    private_key_store,
                    input: &mut input,
                    output_path: output,
                    secrets,
                    detached,
                    binary,
                    append,
                    notarize,
                    time,
                    notations: &notations
                })?;
            }
        },
        SqSubcommands::Verify(command) => {
            let mut input = command.input.open()?;
            let mut output = command.output.create_safe(config.force)?;
            let mut detached = if let Some(f) = command.detached {
                Some(File::open(f)?)
            } else {
                None
            };
            let signatures = command.signatures;
            // TODO ugly adaptation to load_certs' signature, fix later
            let mut certs = load_certs(
                command.sender_file.iter().map(|s| s.as_ref()))?;
            certs.extend(
                config.lookup(command.sender_certs,
                              Some(KeyFlags::empty().set_signing()),
                              true,
                              false)
                    .context("--sender-cert")?);
            commands::verify(config, &mut input,
                             detached.as_mut().map(|r| r as &mut (dyn io::Read + Sync + Send)),
                             &mut output, signatures, certs)?;
        },

        // TODO: Extract body to commands/armor.rs
        SqSubcommands::Armor(command) => {
            let input = command.input.open()?;
            let mut want_kind: Option<armor::Kind> = command.kind.into();

            // Peek at the data.  If it looks like it is armored
            // data, avoid armoring it again.
            let mut dup = Limitor::new(Dup::new(input), ARMOR_DETECTION_LIMIT);
            let (already_armored, have_kind) = {
                let mut reader =
                    armor::Reader::from_reader(&mut dup,
                                       armor::ReaderMode::Tolerant(None));
                (reader.data(8).is_ok(), reader.kind())
            };
            let mut input =
                dup.as_boxed().into_inner().unwrap().into_inner().unwrap();

            if already_armored
                && (want_kind.is_none() || want_kind == have_kind)
            {
                // It is already armored and has the correct kind.
                let mut output = command.output.create_safe(c.force)?;
                io::copy(&mut input, &mut output)?;
                return Ok(());
            }

            if want_kind.is_none() {
                let (tmp, kind) = detect_armor_kind(input);
                input = tmp;
                want_kind = Some(kind);
            }

            // At this point, want_kind is determined.
            let want_kind = want_kind.expect("given or detected");

            let mut output =
                command.output.create_pgp_safe(config.force, false, want_kind)?;

            if already_armored {
                // Dearmor and copy to change the type.
                let mut reader =
                    armor::Reader::from_reader(input,
                                       armor::ReaderMode::Tolerant(None));
                io::copy(&mut reader, &mut output)?;
            } else {
                io::copy(&mut input, &mut output)?;
            }
            output.finalize()?;
        },
        SqSubcommands::Dearmor(command) => {
            let mut input = command.input.open()?;
            let mut output = command.output.create_safe(config.force)?;
            let mut filter = armor::Reader::from_reader(&mut input, None);
            io::copy(&mut filter, &mut output)?;
        },
        #[cfg(feature = "autocrypt")]
        SqSubcommands::Autocrypt(command) => {
            commands::autocrypt::dispatch(config, &command)?;
        },
        SqSubcommands::Inspect(command) => {
            commands::inspect(config, command)?
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

        SqSubcommands::Packet(command) => match command.subcommand {
            packet::Subcommands::Dump(command) => {
                let mut input = command.input.open()?;
                let output_type = command.output;
                let mut output = output_type.create_unsafe(config.force)?;

                let session_key = command.session_key;
                let width = if let Some((width, _)) = terminal_size() {
                    Some(width.0.into())
                } else {
                    None
                };
                commands::dump(&mut input, &mut output,
                               command.mpis, command.hex,
                               session_key.as_ref(), width)?;
            },

            packet::Subcommands::Decrypt(command) => {
                let mut input = command.input.open()?;
                let mut output = command.output.create_pgp_safe(
                    config.force,
                    command.binary,
                    armor::Kind::Message,
                )?;

                let secrets =
                    load_keys(command.secret_key_file.iter().map(|s| s.as_ref()))?;
                let session_keys = command.session_key;
                commands::decrypt::decrypt_unwrap(
                    config,
                    &mut input, &mut output,
                    secrets,
                    session_keys,
                    command.dump_session_key)?;
                output.finalize()?;
            },

            packet::Subcommands::Split(command) => {
                let mut input = command.input.open()?;
                let prefix =
                // The prefix is either specified explicitly...
                    command.prefix.unwrap_or(
                        // ... or we derive it from the input file...
                        command.input.and_then(|x| {
                            // (but only use the filename)
                            x.file_name().map(|f|
                                String::from(f.to_string_lossy())
                            )
                        })
                        // ... or we use a generic prefix...
                            .unwrap_or_else(|| String::from("output"))
                        // ... finally, add a hyphen to the derived prefix.
                            + "-");
                commands::split(&mut input, &prefix)?;
            },
            packet::Subcommands::Join(command) => commands::join(config, command)?,
        },

        SqSubcommands::Keyserver(command) => {
            commands::net::dispatch_keyserver(config, command)?
        }

        SqSubcommands::Key(command) => {
            commands::key::dispatch(config, command)?
        }

        SqSubcommands::Wkd(command) => {
            commands::net::dispatch_wkd(config, command)?
        }

        SqSubcommands::Dane(command) => {
            commands::net::dispatch_dane(config, command)?
        }

        SqSubcommands::Certify(command) => {
            commands::certify::certify(config, command)?
        }

        SqSubcommands::Link(command) => {
            commands::link::link(config, command)?
        }

        SqSubcommands::Wot(command) => {
            commands::wot::dispatch(config, command)?
        }
    }

    Ok(())
}

fn parse_notations(n: Vec<String>) -> Result<Vec<(bool, NotationData)>> {

    // TODO I'm not sure what to do about this requirement.  Setting
    // number_of_values = 2 for the argument already makes clap bail if the
    // length of the vec is odd.
    assert_eq!(n.len() % 2, 0);

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

// TODO: Replace all uses with CliTime argument type
/// Parses the given string depicting a ISO 8601 timestamp.
fn parse_iso8601(s: &str, pad_date_with: chrono::NaiveTime)
                 -> Result<DateTime<Utc>>
{
    // If you modify this function this function, synchronize the
    // changes with the copy in sqv.rs!
    for f in &[
        "%Y-%m-%dT%H:%M:%S%#z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M%#z",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%dT%H%#z",
        "%Y-%m-%dT%H",
        "%Y%m%dT%H%M%S%#z",
        "%Y%m%dT%H%M%S",
        "%Y%m%dT%H%M%#z",
        "%Y%m%dT%H%M",
        "%Y%m%dT%H%#z",
        "%Y%m%dT%H",
    ] {
        if f.ends_with("%#z") {
            if let Ok(d) = DateTime::parse_from_str(s, *f) {
                return Ok(d.into());
            }
        } else if let Ok(d) = chrono::NaiveDateTime::parse_from_str(s, *f) {
            return Ok(DateTime::from_utc(d, Utc));
        }
    }
    for f in &[
        "%Y-%m-%d",
        "%Y-%m",
        "%Y-%j",
        "%Y%m%d",
        "%Y%m",
        "%Y%j",
        "%Y",
    ] {
        if let Ok(d) = chrono::NaiveDate::parse_from_str(s, *f) {
            return Ok(DateTime::from_utc(d.and_time(pad_date_with), Utc));
        }
    }
    Err(anyhow::anyhow!("Malformed ISO8601 timestamp: {}", s))
}

#[test]
fn test_parse_iso8601() {
    let z = chrono::NaiveTime::from_hms_opt(0, 0, 0).unwrap();
    parse_iso8601("2017-03-04T13:25:35Z", z).unwrap();
    parse_iso8601("2017-03-04T13:25:35+08:30", z).unwrap();
    parse_iso8601("2017-03-04T13:25:35", z).unwrap();
    parse_iso8601("2017-03-04T13:25Z", z).unwrap();
    parse_iso8601("2017-03-04T13:25", z).unwrap();
    // parse_iso8601("2017-03-04T13Z", z).unwrap(); // XXX: chrono doesn't like
    // parse_iso8601("2017-03-04T13", z).unwrap(); // ditto
    parse_iso8601("2017-03-04", z).unwrap();
    // parse_iso8601("2017-03", z).unwrap(); // ditto
    parse_iso8601("2017-031", z).unwrap();
    parse_iso8601("20170304T132535Z", z).unwrap();
    parse_iso8601("20170304T132535+0830", z).unwrap();
    parse_iso8601("20170304T132535", z).unwrap();
    parse_iso8601("20170304T1325Z", z).unwrap();
    parse_iso8601("20170304T1325", z).unwrap();
    // parse_iso8601("20170304T13Z", z).unwrap(); // ditto
    // parse_iso8601("20170304T13", z).unwrap(); // ditto
    parse_iso8601("20170304", z).unwrap();
    // parse_iso8601("201703", z).unwrap(); // ditto
    parse_iso8601("2017031", z).unwrap();
    // parse_iso8601("2017", z).unwrap(); // ditto
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
    eprintln!("           {}", err);
    err.chain().skip(1).for_each(|cause| eprintln!("  because: {}", cause));
}
