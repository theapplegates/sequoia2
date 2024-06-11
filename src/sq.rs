use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::SystemTime;

use anyhow::anyhow;
use anyhow::Context as _;

use once_cell::sync::OnceCell;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::crypto;
use openpgp::crypto::Password;
use openpgp::Fingerprint;
use openpgp::KeyHandle;
use openpgp::Result;
use openpgp::cert::prelude::*;
use openpgp::cert::raw::RawCertParser;
use openpgp::packet::prelude::*;
use openpgp::parse::Parse;
use openpgp::policy::Policy;
use openpgp::policy::StandardPolicy as P;
use openpgp::types::KeyFlags;
use openpgp::types::RevocationStatus;

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;
use cert_store::Store;
use cert_store::store::MergePublicCollectStats;
use cert_store::store::StoreError;
use cert_store::store::StoreUpdate;
use cert_store::store::UserIDQueryParams;

use sequoia_wot as wot;
use wot::store::Store as _;

use sequoia_keystore as keystore;
use keystore::Protection;

use crate::cli::types::FileStdinOrKeyHandle;
use crate::common::password;
use crate::ImportStatus;
use crate::OutputFormat;
use crate::OutputVersion;
use crate::output::hint::Hint;
use crate::PreferredUserID;
use crate::print_error_chain;

/// Flags for Sq::get_keys and related functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GetKeysOptions {
    /// Don't ignore keys that are not alive.
    AllowNotAlive,
    /// Don't ignore keys that are not revoke.
    AllowRevoked,
}

/// Flag for Sq::get_keys and related function.
enum KeyType {
    /// Only consider primary key.
    Primary,
    /// Only consider keys that have at least one of the specified
    /// capabilities.
    KeyFlags(KeyFlags),
}

// A shorthand for our store type.
type WotStore<'store, 'rstore>
    = wot::store::CertStore<'store, 'rstore, cert_store::CertStore<'store>>;

pub struct Sq<'store, 'rstore>
    where 'store: 'rstore
{
    pub verbose: bool,
    pub force: bool,
    pub output_format: OutputFormat,
    pub output_version: Option<OutputVersion>,
    pub policy: &'rstore P<'rstore>,
    pub time: SystemTime,
    pub time_is_now: bool,
    pub home: sequoia_directories::Home,
    // --no-cert-store
    pub no_rw_cert_store: bool,
    pub cert_store_path: Option<PathBuf>,
    pub pep_cert_store_path: Option<PathBuf>,
    pub keyrings: Vec<PathBuf>,
    // Map from key fingerprint to cert fingerprint and the key.
    pub keyring_tsks: OnceCell<BTreeMap<
            Fingerprint,
        (Fingerprint, Key<key::PublicParts, key::UnspecifiedRole>)>>,
    // This will be set if --no-cert-store is not passed, OR --keyring
    // is passed.
    pub cert_store: OnceCell<WotStore<'store, 'rstore>>,

    // The value of --trust-root.
    pub trust_roots: Vec<Fingerprint>,
    // The local trust root, as set in the cert store.
    pub trust_root_local: OnceCell<Option<Fingerprint>>,

    // The key store.
    pub no_key_store: bool,
    pub key_store_path: Option<PathBuf>,
    pub key_store: OnceCell<Mutex<keystore::Keystore>>,

    /// A password cache.  When encountering a locked key, we first
    /// consult the password cache.  The passwords are only tried if
    /// it is safe.  That is, the passwords are only tried if we are
    /// sure that the key is not protected by a retry counter.  If the
    /// password cache doesn't contain the correct password, or the
    /// key is protected by a retry counter, the user is prompted to
    /// unlock the key.  The correct password is added to the cache.
    pub password_cache: Mutex<Vec<Password>>,
}

impl<'store: 'rstore, 'rstore> Sq<'store, 'rstore> {
    /// Returns the cert store's base directory, if it is enabled.
    pub fn cert_store_base(&self) -> Option<PathBuf> {
        if self.no_rw_cert_store {
            None
        } else if let Some(path) = self.cert_store_path.as_ref() {
            Some(path.clone())
        } else if let Ok(path) = std::env::var("PGP_CERT_D") {
            Some(PathBuf::from(path))
        } else {
            Some(self.home.data_dir(sequoia_directories::Component::CertD))
        }
    }

    /// Returns the cert store.
    ///
    /// If the cert store is disabled, returns `Ok(None)`.  If it is not yet
    /// open, opens it.
    pub fn cert_store(&self) -> Result<Option<&WotStore<'store, 'rstore>>> {
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

        let keyring = cert_store::store::Certs::empty();
        let mut tsks = BTreeMap::new();
        let mut error = None;
        for filename in self.keyrings.iter() {
            let f = std::fs::File::open(filename)
                .with_context(|| format!("Open {:?}", filename))?;
            let parser = RawCertParser::from_reader(f)
                .with_context(|| format!("Parsing {:?}", filename))?;

            for cert in parser {
                match cert {
                    Ok(cert) => {
                        for key in cert.keys() {
                            if key.has_secret() {
                                tsks.insert(
                                    key.fingerprint(),
                                    (cert.fingerprint(), key.clone()));
                            }
                        }

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

        self.keyring_tsks.set(tsks).expect("uninitialized");

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

        let cert_store = WotStore::from_store(
            cert_store, self.policy, self.time);

        let _ = self.cert_store.set(cert_store);

        Ok(Some(self.cert_store.get().expect("just configured")))
    }

    /// Returns the cert store.
    ///
    /// If the cert store is disabled, returns an error.
    pub fn cert_store_or_else(&self) -> Result<&WotStore<'store, 'rstore>> {
        self.cert_store().and_then(|cert_store| cert_store.ok_or_else(|| {
            anyhow::anyhow!("Operation requires a certificate store, \
                             but the certificate store is disabled")
        }))
    }

    /// Returns a mutable reference to the cert store.
    ///
    /// If the cert store is disabled, returns None.  If it is not yet
    /// open, opens it.
    pub fn cert_store_mut(&mut self)
        -> Result<Option<&mut WotStore<'store, 'rstore>>>
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
    #[allow(unused)]
    pub fn cert_store_mut_or_else(&mut self)
        -> Result<&mut WotStore<'store, 'rstore>>
    {
        self.cert_store_mut().and_then(|cert_store| cert_store.ok_or_else(|| {
            anyhow::anyhow!("Operation requires a certificate store, \
                             but the certificate store is disabled")
        }))
    }

    /// Returns a reference to the underlying certificate directory,
    /// if it is configured.
    ///
    /// If the cert direcgory is disabled, returns an error.
    pub fn certd_or_else(&self)
        -> Result<&cert_store::store::certd::CertD<'store>>
    {
        const NO_CERTD_ERR: &str =
            "A local trust root and other special certificates are \
             only available when using an OpenPGP certificate \
             directory";

        let cert_store = self.cert_store_or_else()
            .with_context(|| NO_CERTD_ERR.to_string())?;

        cert_store.certd()
            .ok_or_else(|| anyhow::anyhow!(NO_CERTD_ERR))
    }


    /// Returns a web-of-trust query builder.
    ///
    /// The trust roots are already set appropriately.
    pub fn wot_query(&self)
        -> Result<wot::QueryBuilder<&WotStore<'store, 'rstore>>>
    {
        let cert_store = self.cert_store_or_else()?;
        let network = wot::Network::new(cert_store)?;
        let mut query = wot::QueryBuilder::new_owned(network.into());
        query.roots(wot::Roots::new(self.trust_roots()));
        Ok(query)
    }

    /// Returns the key store's path.
    ///
    /// If the key store is disabled, returns `Ok(None)`.
    pub fn key_store_path(&self) -> Result<Option<PathBuf>> {
        if self.no_key_store {
            Ok(None)
        } else if let Some(dir) = self.key_store_path.as_ref() {
            Ok(Some(dir.clone()))
        } else {
            Ok(Some(self.home.data_dir(sequoia_directories::Component::Keystore)))
        }
    }

    /// Returns the key store's path.
    ///
    /// If the key store is disabled, returns an error.
    pub fn key_store_path_or_else(&self) -> Result<PathBuf> {
        const NO_KEY_STORE_ERROR: &str =
            "Operation requires a key store, \
             but the key store is disabled";

        if self.no_key_store {
            Err(anyhow::anyhow!(NO_KEY_STORE_ERROR))
        } else {
            self.key_store_path()?
                .ok_or(anyhow::anyhow!(NO_KEY_STORE_ERROR))
        }
    }

    /// Returns the key store.
    ///
    /// If the key store is disabled, returns `Ok(None)`.  If it is not yet
    /// open, opens it.
    pub fn key_store(&self) -> Result<Option<&Mutex<keystore::Keystore>>> {
        if self.no_key_store {
            return Ok(None);
        }

        self.key_store
            .get_or_try_init(|| {
                let c = keystore::Context::configure()
                    .home(self.key_store_path_or_else()?)
                    .build()?;
                let ks = keystore::Keystore::connect(&c)
                    .context("Connecting to key store")?;

                Ok(Mutex::new(ks))
            })
            .map(Some)
    }

    /// Returns the key store.
    ///
    /// If the key store is disabled, returns an error.
    pub fn key_store_or_else(&self) -> Result<&Mutex<keystore::Keystore>> {
        self.key_store().and_then(|key_store| key_store.ok_or_else(|| {
            anyhow::anyhow!("Operation requires a key store, \
                             but the key store is disabled")
        }))
    }

    /// Returns the secret keys found in any specified keyrings.
    pub fn keyring_tsks(&self)
        -> &BTreeMap<Fingerprint,
                     (Fingerprint, Key<key::PublicParts, key::UnspecifiedRole>)>
    {
        if let Some(keyring_tsks) = self.keyring_tsks.get() {
            keyring_tsks
        } else {
            // This also initializes keyring_tsks.
            let _ = self.cert_store();

            // If something went wrong, we just set it to an empty
            // map.
            self.keyring_tsks.get_or_init(|| BTreeMap::new())
        }
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
    pub fn lookup<'a, I>(&self, handles: I,
                         keyflags: Option<KeyFlags>,
                         or_by_primary: bool,
                         allow_ambiguous: bool)
        -> Result<Vec<Cert>>
    where I: IntoIterator,
          I::Item: Into<FileStdinOrKeyHandle>,
    {
        self.lookup_with_policy(
            handles, keyflags, or_by_primary, allow_ambiguous,
            self.policy, self.time)
    }

    /// Looks up an identifier.
    ///
    /// Like [`Sq::lookup`], but uses an alternate policy and an
    /// alternate reference time.
    pub fn lookup_with_policy<'a, I>(&self, handles: I,
                                     keyflags: Option<KeyFlags>,
                                     or_by_primary: bool,
                                     allow_ambiguous: bool,
                                     policy: &dyn Policy,
                                     time: SystemTime)
        -> Result<Vec<Cert>>
    where I: IntoIterator,
          I::Item: Into<FileStdinOrKeyHandle>,
    {
        let mut results = Vec::new();

        for handle in handles {
            let (kh, mut certs) = match handle.into() {
                FileStdinOrKeyHandle::FileOrStdin(file) => {
                    let br = file.open()?;
                    let cert = Cert::from_buffered_reader(br)?;
                    (cert.key_handle(), vec![ cert ])
                }
                FileStdinOrKeyHandle::KeyHandle(kh) => {
                    let certs = self.cert_store_or_else()?
                        .lookup_by_cert_or_subkey(&kh)
                        .with_context(|| {
                            format!("Failed to load {} from certificate store", kh)
                        })?
                        .into_iter()
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

                    (kh.clone(), certs)
                }
            };

            if let Some(keyflags) = keyflags.as_ref() {
                certs.retain(|cert| {
                    let vc = match cert.with_policy(policy, time)
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
                        && vc.key_handle().aliases(&kh);

                    for ka in vc.keys() {
                        if checked_id || ka.key_handle().aliases(&kh) {
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

        Ok(results)
    }

    /// Looks up a certificate.
    ///
    /// Like [`Sq::lookup`], but looks up a certificate, which must be
    /// uniquely identified by `handle` and `keyflags`.
    pub fn lookup_one<H>(&self, handle: H,
                      keyflags: Option<KeyFlags>, or_by_primary: bool)
        -> Result<Cert>
    where H: Into<FileStdinOrKeyHandle>
    {
        self.lookup_one_with_policy(handle, keyflags, or_by_primary,
                                    self.policy, self.time)
    }

    /// Looks up a certificate.
    ///
    /// Like [`Sq::lookup_one_with_policy`], but uses an alternate
    /// policy and an alternate reference time.
    pub fn lookup_one_with_policy<H>(&self, handle: H,
                                     keyflags: Option<KeyFlags>,
                                     or_by_primary: bool,
                                     policy: &dyn Policy,
                                     time: SystemTime)
        -> Result<Cert>
    where H: Into<FileStdinOrKeyHandle>
    {
        self.lookup_with_policy(std::iter::once(handle.into()),
                                keyflags, or_by_primary, false,
                                policy, time)
            .map(|certs| {
                assert_eq!(certs.len(), 1);
                certs.into_iter().next().expect("have one")
            })
    }


    /// Looks up certificates by User ID or email address.
    ///
    /// This only returns certificates that can be authenticate for
    /// the specified User ID (or email address, if `email` is true).
    /// If no certificate can be authenticated for some User ID,
    /// returns an error.  If multiple certificates can be
    /// authenticated for a given User ID or email address, then
    /// returns them all.
    pub fn lookup_by_userid(&self, userid: &[String], email: bool)
        -> Result<Vec<Cert>>
    {
        if userid.is_empty() {
            return Ok(Vec::new())
        }

        let cert_store = self.cert_store_or_else()?;

        // Build a WoT network.

        let cert_store = wot::store::CertStore::from_store(
            cert_store, self.policy, self.time);
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
                let vc = match cert.with_policy(self.policy, self.time) {
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
                         `sq pki link add {} {:?}`.",
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

    /// Returns the local trust root, creating it if necessary.
    pub fn local_trust_root(&self) -> Result<Arc<LazyCert<'store>>> {
        self.certd_or_else()?.trust_root().map(|(cert, _created)| {
            cert
        })
    }

    /// Returns the trust roots, including the cert store's trust
    /// root, if any.
    pub fn trust_roots(&self) -> Vec<Fingerprint> {
        let trust_root_local = self.trust_root_local.get_or_init(|| {
            self.cert_store_or_else()
                .ok()
                .and_then(|cert_store| cert_store.certd())
                .and_then(|certd| {
                    match certd.certd().get(cert_store::store::openpgp_cert_d::TRUST_ROOT) {
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

    /// Imports the TSK into the soft key backend.
    ///
    /// On success, returns whether the key was imported, updated, or
    /// unchanged.
    pub fn import_key(&self, cert: Cert) -> Result<ImportStatus> {
        if ! cert.is_tsk() {
            return Err(anyhow::anyhow!(
                "Nothing to import: certificate does not contain \
                 any secret key material"));
        }

        let keystore = self.key_store_or_else()?;
        let mut keystore = keystore.lock().unwrap();

        let mut softkeys = None;
        for mut backend in keystore.backends()?.into_iter() {
            if backend.id()? == "softkeys" {
                softkeys = Some(backend);
                break;
            }
        }

        drop(keystore);

        let mut softkeys = if let Some(softkeys) = softkeys {
            softkeys
        } else {
            return Err(anyhow::anyhow!("softkeys backend is not configured."));
        };

        let mut import_status = ImportStatus::Unchanged;
        for (s, key) in softkeys.import(&cert)? {
            self.info(format_args!(
                "Importing {} into key store: {:?}",
                key.fingerprint(), s));

            import_status = import_status.max(s.into());
        }

        // Also insert the certificate into the certificate store.
        // If we can't, we don't fail.  This allows, in
        // particular, `sq --no-cert-store key import` to work.
        let fpr = cert.fingerprint();
        match self.cert_store_or_else() {
            Ok(cert_store) => {
                if let Err(err) = cert_store.update(
                    Arc::new(LazyCert::from(cert)))
                {
                    self.info(format_args!(
                        "While importing {} into cert store: {}",
                        fpr, err));
                }
            }
            Err(err) => {
                self.info(format_args!(
                    "Not importing {} into cert store: {}",
                    fpr, err));
            }
        }

        Ok(import_status)
    }

    /// Imports the certificate into the certificate store.
    ///
    /// On success, returns whether the key was imported, updated, or
    /// unchanged.
    pub fn import_cert(&self, cert: Cert) -> Result<ImportStatus> {
        // Also insert the certificate into the certificate store.
        // If we can't, we don't fail.  This allows, in
        // particular, `sq --no-cert-store key import` to work.
        let fpr = cert.fingerprint();
        let cert_store = self.cert_store_or_else()?;

        let stats = MergePublicCollectStats::new();
        cert_store.update_by(Arc::new(LazyCert::from(cert)), &stats)
            .with_context(|| {
                format!("Failed to import {} into the certificate store",
                        fpr)
            })?;

        let import_status = if stats.new_certs() > 0 {
            ImportStatus::New
        } else if stats.updated_certs() > 0 {
            ImportStatus::Updated
        } else {
            ImportStatus::Unchanged
        };

        Ok(import_status)
    }

    /// Best-effort heuristic to compute the primary User ID of a given cert.
    ///
    /// The returned string is already sanitized, and safe for displaying.
    ///
    /// If `use_wot` is set, then we use the best authenticated user
    /// ID.  If `use_wot` is not set, then we use the primary user ID.
    pub fn best_userid<'u>(&self, cert: &'u Cert, use_wot: bool)
        -> PreferredUserID
    {
        // Try to be more helpful by including a User ID in the
        // listing.  We'd like it to be the primary one.  Use
        // decreasingly strict policies.
        let mut primary_uid = None;

        // First, apply our policy.
        if let Ok(vcert) = cert.with_policy(self.policy, self.time) {
            if let Ok(primary) = vcert.primary_userid() {
                primary_uid = Some(primary.userid());
            }
        }

        // Second, apply the null policy.
        if primary_uid.is_none() {
            const NULL: openpgp::policy::NullPolicy =
                openpgp::policy::NullPolicy::new();
            if let Ok(vcert) = cert.with_policy(&NULL, self.time) {
                if let Ok(primary) = vcert.primary_userid() {
                    primary_uid = Some(primary.userid());
                }
            }
        }

        // As a last resort, pick the first user id.
        if primary_uid.is_none() {
            if let Some(primary) = cert.userids().next() {
                primary_uid = Some(primary.userid());
            }
        }

        if let Some(primary_uid) = primary_uid {
            let fpr = cert.fingerprint();

            let mut candidate: (&UserID, usize) = (primary_uid, 0);

            #[allow(clippy::never_loop)]
            loop {
                // Don't fail if we can't query the user's web of trust.
                if ! use_wot { break; };
                let Ok(q) = self.wot_query() else { break; };
                let q = q.build();
                let authenticate = move |userid: &UserID| {
                    let paths = q.authenticate(userid, &fpr, wot::FULLY_TRUSTED);
                    paths.amount()
                };

                // We're careful to *not* use a ValidCert so that we see all
                // user IDs, even those that are not self signed.

                candidate = (primary_uid, authenticate(primary_uid));

                for userid in cert.userids() {
                    let userid = userid.component();

                    if candidate.1 >= wot::FULLY_TRUSTED {
                        // Done.
                        break;
                    }

                    if userid == primary_uid {
                        // We already considered this one.
                        continue;
                    }

                    let amount = authenticate(&userid);
                    if amount > candidate.1 {
                        candidate = (userid, amount);
                    }
                }

                break;
            }

            let (uid, amount) = candidate;
            PreferredUserID::from_userid(uid.clone(), amount)
        } else {
            // Special case, there is no user id.
            PreferredUserID::unknown()
        }
    }

    /// Best-effort heuristic to compute the primary User ID of a given cert.
    ///
    /// The returned string is already sanitized, and safe for displaying.
    ///
    /// If `use_wot` is set, then we use the best authenticated user
    /// ID.  If `use_wot` is not set, then we use the primary user ID.
    pub fn best_userid_for<'u>(&self, key_handle: &KeyHandle,
                               use_wot: bool)
                              -> PreferredUserID
    {
        if ! use_wot {
            return PreferredUserID::unknown()
        };

        let cert = self.lookup_one(
            key_handle,
            Some(KeyFlags::empty()
                 .set_storage_encryption()
                 .set_transport_encryption()),
            false);

        match cert {
            Ok(cert) => {
                self.best_userid(&cert, true)
            }
            Err(err) => {
                if let Some(StoreError::NotFound(_))
                    = err.downcast_ref()
                {
                    PreferredUserID::from_string("(certificate not found)", 0)
                } else {
                    PreferredUserID::from_string(
                        format!("(error looking up certificate: {})", err), 0)
                }
            }
        }
    }

    /// Caches a password.
    pub fn cache_password(&self, password: Password) {
        let mut cache = self.password_cache.lock().unwrap();

        if ! cache.contains(&password) {
            cache.push(password);
        }
    }

    /// Returns the cached passwords.
    pub fn cached_passwords(&self) -> impl Iterator<Item=Password> {
        self.password_cache.lock().unwrap().clone().into_iter()
    }

    /// Gets a signer for the specified key.
    ///
    /// If `ka` includes secret key material, that is preferred.
    /// Otherwise, we look for the key on the key store.
    ///
    /// If the key is locked, we try to unlock it.  If the key isn't
    /// protected by a retry counter, then the password cache is
    /// tried.  Otherwise, or if that fails, the user is prompted to
    /// unlock the key.  The correct password is added to the password
    /// cache.
    pub fn get_signer<P, R, R2>(&self, ka: &KeyAmalgamation<P, R, R2>)
        -> Result<(Box<dyn crypto::Signer + Send + Sync>, Option<Password>)>
        where P: key::KeyParts + Clone, R: key::KeyRole + Clone
    {
        let try_tsk = |cert: &Cert, key: &Key<_, _>|
            -> Result<(_, _)>
        {
            if let Some(secret) = key.optional_secret() {
                let (unencrypted, password) = match secret {
                    SecretKeyMaterial::Encrypted(ref e) => {
                        // try passwords from already existing keys
                        match self.cached_passwords().find_map(|password| {
                            e.decrypt(key.pk_algo(), &password).ok()
                                .map(|key| (key, password.clone()))
                        }) {
                            Some((unencrypted, password)) =>
                                (unencrypted, Some(password)),
                            None => {
                                let password = password::prompt_to_unlock(
                                    &format!("key {}/{}",
                                             cert.keyid(),
                                             key.keyid()))?;

                                let key = e.decrypt(key.pk_algo(), &password)
                                    .map_err(|_| anyhow!("Incorrect password."))?;

                                self.cache_password(password.clone());

                                (key, Some(password))
                            }
                        }
                    }
                    SecretKeyMaterial::Unencrypted(ref u) => (u.clone(), None),
                };

                Ok((
                    Box::new(
                        crypto::KeyPair::new(
                            key.clone()
                                .parts_into_public()
                                .role_into_unspecified(),
                            unencrypted).unwrap()
                    ),
                    password,
                ))
            } else {
                Err(anyhow!("No secret key material."))
            }
        };
        let try_keyrings = |cert: &Cert, key: &Key<_, _>|
            -> Result<(_, _)>
        {
            let keyring_tsks = self.keyring_tsks();
            if let Some((cert_fpr, key))
                = keyring_tsks.get(&key.fingerprint())
            {
                if cert_fpr == &cert.fingerprint() {
                    return try_tsk(cert, key);
                }
            }

            Err(anyhow!("No secret key material."))
        };
        let try_keystore = |ka: &KeyAmalgamation<_, _, R2>|
            -> Result<(_, _)>
        {
            let ks = self.key_store_or_else()?;

            let mut ks = ks.lock().unwrap();

            let remote_keys = ks.find_key(ka.key_handle())?;

            let uid = self.best_userid(ka.cert(), true);

            // XXX: Be a bit smarter.  If there are multiple
            // keys, sort them so that we try the easiest one
            // first (available, no password).

            'key: for mut key in remote_keys.into_iter() {
                let password = if let Protection::Password(hint) = key.locked()? {
                    if let Some(password) = self.cached_passwords().find(|password| {
                        key.unlock(password.clone()).is_ok()
                    }) {
                        Some(password)
                    } else {
                        if let Some(hint) = hint {
                            eprintln!("{}", hint);
                        }

                        loop {
                            let p = password::prompt_to_unlock(&format!(
                                "Please enter the password to decrypt \
                                 the key {}/{}, {}",
                                ka.cert().keyid(), ka.keyid(), uid))?;

                            if p == "".into() {
                                eprintln!("Giving up.");
                                continue 'key;
                            }

                            match key.unlock(p.clone()) {
                                Ok(()) => {
                                    self.cache_password(p.clone());
                                    break Some(p)
                                }
                                Err(err) => {
                                    eprintln!("Failed to unlock key: {}", err);
                                }
                            }
                        }
                    }
                } else {
                    None
                };

                return Ok((Box::new(key), password));
            }

            Err(anyhow!("Key not managed by keystore."))
        };

        let key = ka.key().parts_as_public().role_as_unspecified();

        if let Ok((key, password)) = try_tsk(ka.cert(), key) {
            Ok((key, password))
        } else if let Ok((key, password)) = try_keyrings(ka.cert(), key) {
            Ok((key, password))
        } else if let Ok((key, password)) = try_keystore(ka) {
            Ok((key, password))
        } else {
            Err(anyhow!("No secret key material."))
        }
    }

    /// Returns a signer for each certificate.
    ///
    /// This returns one key for each certificate.  If a certificate
    /// doesn't have a suitable key, then this returns an error.
    ///
    /// A key is considered suitable if:
    ///
    /// - the certificate is valid
    /// - the key matches the key type specified in `keytype` (it's either
    ///   the primary, or it has one of the key capabilities)
    /// - the key is alive (unless allowed by `options`)
    /// - the key is not revoked (unless allowed by `options`)
    /// - the key's algorithm is supported by the underlying crypto engine.
    ///
    /// If a key is locked, then the user will be prompted to enter
    /// the password.
    fn get_keys<C>(&self, certs: &[C],
                   keytype: KeyType,
                   options: Option<&[GetKeysOptions]>)
        -> Result<Vec<(Box<dyn crypto::Signer + Send + Sync>, Option<Password>)>>
    where C: Borrow<Cert>
    {
        let mut bad = Vec::new();

        let options = options.unwrap_or(&[][..]);
        let allow_not_alive = options.contains(&GetKeysOptions::AllowNotAlive);
        let allow_revoked = options.contains(&GetKeysOptions::AllowRevoked);

        let mut keys: Vec<(Box<dyn crypto::Signer + Send + Sync>,
                           Option<Password>)>
            = vec![];

        'next_cert: for cert in certs {
            let cert = cert.borrow();
            let vc = match cert.with_policy(self.policy, self.time) {
                Ok(vc) => vc,
                Err(err) => {
                    return Err(
                        err.context(format!("Found no suitable key on {}", cert)));
                }
            };

            let keyiter = match keytype {
                KeyType::Primary => {
                    Box::new(
                        std::iter::once(
                            vc.keys()
                                .next()
                                .expect("a valid cert has a primary key")))
                        as Box<dyn Iterator<Item=ValidErasedKeyAmalgamation<openpgp::packet::key::PublicParts>>>
                },
                KeyType::KeyFlags(ref flags) => {
                    Box::new(vc.keys().key_flags(flags.clone()))
                        as Box<dyn Iterator<Item=_>>
                },
            };
            for ka in keyiter {
                let mut bad_ = [
                    ! allow_not_alive && matches!(ka.alive(), Err(_)),
                    ! allow_revoked && matches!(ka.revocation_status(),
                                                RevocationStatus::Revoked(_)),
                    ! ka.pk_algo().is_supported(),
                    false,
                ];
                if bad_.iter().any(|x| *x) {
                    bad.push((ka.fingerprint(), bad_));
                    continue;
                }

                if let Ok((key, password)) = self.get_signer(&ka) {
                    keys.push((key, password));
                    continue 'next_cert;
                } else {
                    bad_[3] = true;
                    bad.push((ka.fingerprint(), bad_));
                    continue;
                }
            }

            // We didn't get a key.  Lint the cert.

            let time = chrono::DateTime::<chrono::offset::Utc>::from(self.time);

            let mut context = Vec::new();
            for (fpr, [not_alive, revoked, not_supported, no_secret_key]) in bad {
                let id: String = if fpr == cert.fingerprint() {
                    fpr.to_string()
                } else {
                    format!("{}/{}", cert.fingerprint(), fpr)
                };

                let preface = if ! self.time_is_now {
                    format!("{} was not considered because\n\
                             at the specified time ({}) it was",
                            id, time)
                } else {
                    format!("{} was not considered because\nit is", fpr)
                };

                let mut reasons = Vec::new();
                if not_alive {
                    reasons.push("not alive");
                }
                if revoked {
                    reasons.push("revoked");
                }
                if not_supported {
                    reasons.push("not supported");
                }
                if no_secret_key {
                    reasons.push("missing the secret key");
                }

                context.push(format!("{}: {}",
                                     preface, reasons.join(", ")));
            }

            if context.is_empty() {
                return Err(anyhow::anyhow!(
                    format!("Found no suitable key on {}", cert)));
            } else {
                let context = context.join("\n");
                return Err(
                    anyhow::anyhow!(
                        format!("Found no suitable key on {}", cert))
                        .context(context));
            }
        }

        Ok(keys)
    }

    /// Returns a signer for each certificate's primary key.
    ///
    /// This returns one key for each certificate.  If a certificate
    /// doesn't have a suitable key, then this returns an error.
    ///
    /// A key is considered suitable if:
    ///
    /// - the certificate is valid
    /// - the key is alive (unless allowed by `options`)
    /// - the key is not revoked (unless allowed by `options`)
    /// - the key's algorithm is supported by the underlying crypto engine.
    ///
    /// If a key is locked, then the user will be prompted to enter
    /// the password.
    pub fn get_primary_keys<C>(&self, certs: &[C],
                               options: Option<&[GetKeysOptions]>)
        -> Result<Vec<(Box<dyn crypto::Signer + Send + Sync>, Option<Password>)>>
    where C: std::borrow::Borrow<Cert>
    {
        self.get_keys(certs, KeyType::Primary, options)
    }

    /// Returns a signer for the certificate's primary key.
    ///
    /// If the certificate doesn't have a suitable key, then this
    /// returns an error.
    ///
    /// A key is considered suitable if:
    ///
    /// - the certificate is valid
    /// - the key is alive (unless allowed by `options`)
    /// - the key is not revoked (unless allowed by `options`)
    /// - the key's algorithm is supported by the underlying crypto engine.
    ///
    /// If a key is locked, then the user will be prompted to enter
    /// the password.
    pub fn get_primary_key<C>(&self, certs: C,
                              options: Option<&[GetKeysOptions]>)
        -> Result<(Box<dyn crypto::Signer + Send + Sync>, Option<Password>)>
    where C: std::borrow::Borrow<Cert>
    {
        let keys = self.get_primary_keys(&[certs], options)?;
        assert!(
            keys.len() == 1,
            "Expected exactly one result from get_primary_keys()"
        );
        Ok(keys.into_iter().next().unwrap())
    }

    /// Returns a signer for a signing-capable key for each
    /// certificate.
    ///
    /// This returns one key for each certificate.  If a certificate
    /// doesn't have a suitable key, then this returns an error.
    ///
    /// A key is considered suitable if:
    ///
    /// - the certificate is valid
    /// - the key is signing capable
    /// - the key is alive (unless allowed by `options`)
    /// - the key is not revoked (unless allowed by `options`)
    /// - the key's algorithm is supported by the underlying crypto engine.
    ///
    /// If a key is locked, then the user will be prompted to enter
    /// the password.
    pub fn get_signing_keys<C>(&self, certs: &[C],
                               options: Option<&[GetKeysOptions]>)
        -> Result<Vec<(Box<dyn crypto::Signer + Send + Sync>, Option<Password>)>>
    where C: Borrow<Cert>
    {
        self.get_keys(certs,
                      KeyType::KeyFlags(KeyFlags::empty().set_signing()),
                      options)
    }

    /// Returns a signer for a signing-capable key for the
    /// certificate.
    ///
    /// If a certificate doesn't have a suitable key, then this
    /// returns an error.
    ///
    /// A key is considered suitable if:
    ///
    /// - the certificate is valid
    /// - the key is signing capable
    /// - the key is alive (unless allowed by `options`)
    /// - the key is not revoked (unless allowed by `options`)
    /// - the key's algorithm is supported by the underlying crypto engine.
    ///
    /// If a key is locked, then the user will be prompted to enter
    /// the password.
    pub fn get_signing_key<C>(&self, certs: C,
                               options: Option<&[GetKeysOptions]>)
        -> Result<(Box<dyn crypto::Signer + Send + Sync>, Option<Password>)>
    where C: Borrow<Cert>
    {
        let keys = self.get_signing_keys(&[certs], options)?;
        assert!(
            keys.len() == 1,
            "Expected exactly one result from get_signing_keys()"
        );
        Ok(keys.into_iter().next().unwrap())
    }

    /// Returns a signer for a certification-capable key for each
    /// certificate.
    ///
    /// This returns one key for each certificate.  If a certificate
    /// doesn't have a suitable key, then this returns an error.
    ///
    /// A key is considered suitable if:
    ///
    /// - the certificate is valid
    /// - the key is certification capable
    /// - the key is alive (unless allowed by `options`)
    /// - the key is not revoked (unless allowed by `options`)
    /// - the key's algorithm is supported by the underlying crypto engine.
    ///
    /// If a key is locked, then the user will be prompted to enter
    /// the password.
    pub fn get_certification_keys<C>(&self, certs: &[C],
                                     options: Option<&[GetKeysOptions]>)
        -> Result<Vec<(Box<dyn crypto::Signer + Send + Sync>, Option<Password>)>>
    where C: std::borrow::Borrow<Cert>
    {
        self.get_keys(certs,
                      KeyType::KeyFlags(KeyFlags::empty().set_certification()),
                      options)
    }

    /// Returns a signer for a certification-capable key for the
    /// certificate.
    ///
    /// This returns one key for each certificate.  If a certificate
    /// doesn't have a suitable key, then this returns an error.
    ///
    /// A key is considered suitable if:
    ///
    /// - the certificate is valid
    /// - the key is certification capable
    /// - the key is alive (unless allowed by `options`)
    /// - the key is not revoked (unless allowed by `options`)
    /// - the key's algorithm is supported by the underlying crypto engine.
    ///
    /// If a key is locked, then the user will be prompted to enter
    /// the password.
    pub fn get_certification_key<C>(&self, cert: C,
                                    options: Option<&[GetKeysOptions]>)
        -> Result<(Box<dyn crypto::Signer + Send + Sync>, Option<Password>)>
    where C: std::borrow::Borrow<Cert>
    {
        let keys = self.get_certification_keys(&[cert], options)?;
        assert!(
            keys.len() == 1,
            "Expected exactly one result from get_certification_keys()"
        );
        Ok(keys.into_iter().next().unwrap())
    }

    /// Prints additional information in verbose mode.
    pub fn info(&self, msg: fmt::Arguments) {
        if self.verbose {
            wprintln!("{}", msg);
        }
    }

    /// Prints a hint for the user.
    pub fn hint(&self, msg: fmt::Arguments) -> Hint {
        // XXX: If we gain a --quiet, pass it to Hint::new.
        Hint::new(false)
            .hint(msg)
    }
}
