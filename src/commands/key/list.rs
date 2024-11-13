use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    fmt,
    time::SystemTime,
};

use sequoia_openpgp::{
    Cert,
    Fingerprint,
    KeyHandle,
    cert::amalgamation::ValidAmalgamation,
    cert::amalgamation::ValidateAmalgamation,
    packet::{Key, key},
    types::RevocationStatus,
};

use sequoia_keystore as keystore;
use keystore::Protection;

use crate::cli;
use crate::Convert;
use crate::Sq;
use crate::Result;
use crate::Time;
use crate::cli::types::cert_designator;

/// Keys may either be grouped into a certificate or be bare.
///
/// We define `Ord` and `Eq`, but only consider fingerprints.  This
/// data structure is meant as a key in a `BTreeMap`.
#[derive(Debug)]
enum Association {
    /// Keys grouped into a certificate.
    Bound(Cert),

    /// Bare keys.
    Bare(Key<key::PublicParts, key::UnspecifiedRole>),
}

impl Association {
    /// Returns the associated certificate, if any.
    pub fn cert(&self) -> Option<&Cert> {
        match self {
            Association::Bound(c) => Some(c),
            Association::Bare(_) => None
        }
    }

    /// Returns the primary or bare key.
    pub fn key(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        match self {
            Association::Bound(c) => c.primary_key().key().into(),
            Association::Bare(k) => k,
        }
    }

    /// Returns the best user ID, if any.
    pub fn best_userid(&self, sq: &Sq) -> String {
        match self {
            Association::Bound(c) => sq.best_userid(c, true).to_string(),
            Association::Bare(_) => "bare key".into(),
        }
    }
}

impl PartialOrd for Association {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (Association::Bound(a), Association::Bound(b)) =>
                a.fingerprint().partial_cmp(&b.fingerprint()),
            (Association::Bound(_), Association::Bare(_)) =>
                Some(Ordering::Less),
            (Association::Bare(_), Association::Bound(_)) =>
                Some(Ordering::Greater),
            (Association::Bare(a), Association::Bare(b)) =>
                a.fingerprint().partial_cmp(&b.fingerprint()),
        }
    }
}

impl Ord for Association {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).expect("total")
    }
}

impl PartialEq for Association {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Association {}

/// A location in the key store.
///
/// A key may reside at different locations, and its availability and
/// protection status are per location.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Location {
    backend: String,
    device: String,
    available: bool,
    protection: &'static str,
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "@{}/{}: {}, {}",
               self.backend,
               self.device,
               if self.available {
                   "available"
               } else {
                   "not available"
               },
               self.protection,
        )
    }
}

/// Metadata associated with a key, notably its locations.
#[derive(Debug, Clone, PartialEq, Eq)]
struct KeyInfo {
    key: Key<key::PublicParts, key::UnspecifiedRole>,
    locations: Vec<Location>,
    signing_capable: bool,
    decryption_capable: bool,
}

impl KeyInfo {
    /// Returns a human-readable description describing how the key
    /// can be used.
    pub fn usable_for(&self) -> &'static str {
        match (self.signing_capable, self.decryption_capable) {
            (true, true) => "for signing and decryption",
            (true, false) => "for signing",
            (false, true) => "for decryption",
            (false, false) => "unusable",
        }
    }
}

/// Returns information about a key.
///
/// If key is `None`, then returns information about the certificate.
///
/// The information that is returned is:
///
/// - If the key is revoked, that it was revoked and why
/// - If the key is invalid, that it is invalid
fn key_validity(sq: &Sq, cert: &Cert, key: Option<&Fingerprint>) -> Vec<String> {
    let revoked = |rs| {
        if let RevocationStatus::Revoked(sigs) = rs {
            let sig = sigs[0];
            let mut reason_;
            let reason = if let Some((reason, message))
                = sig.reason_for_revocation()
            {
                // Be careful to quote the message it is
                // controlled by the certificate holder.
                reason_ = reason.to_string();
                if ! message.is_empty() {
                    reason_.push_str(": ");
                    reason_.push_str(&format!(
                        "{:?}", String::from_utf8_lossy(message)));
                }
                &reason_
            } else {
                "no reason specified"
            };

            Some(format!(
                "revoked on {}, {}",
                sig.signature_creation_time()
                    .unwrap_or(std::time::UNIX_EPOCH)
                    .convert(),
                reason))
        } else {
            None
        }
    };

    let mut info = Vec::new();

    if let Some(key) = key {
        let ka = cert.keys().subkeys().find(|ka| &ka.fingerprint() == key)
            .expect("key is associated with the certificate");

        match ka.clone().with_policy(sq.policy, sq.time) {
            Ok(ka) => {
                if let Some(revoked) = revoked(ka.revocation_status()) {
                    info.push(revoked)
                }

                if let Some(t) = ka.key_expiration_time() {
                    if t < SystemTime::now() {
                        info.push(
                            format!("expired {}",
                                    Time::try_from(t)
                                    .expect("is an OpenPGP timestamp")))
                    } else {
                        info.push(
                            format!("will expire {}",
                                    Time::try_from(t)
                                    .expect("is an OpenPGP timestamp")))
                    }
                }
            }
            Err(err) => {
                if let Some(revoked)
                    = revoked(ka.revocation_status(sq.policy, sq.time))
                {
                    info.push(revoked);
                }

                // Only print that it is invalid if the cert is valid.
                // If the cert is invalid, then we already printed the
                // information when showing the primary key.
                if let Ok(_) = cert.with_policy(sq.policy, sq.time) {
                    info.push(format!(
                        "not valid: {}",
                        crate::one_line_error_chain(err)));
                }
            }
        }
    } else {
        match cert.with_policy(sq.policy, sq.time) {
            Ok(vc) => {
                if let Some(revoked) = revoked(vc.revocation_status()) {
                    info.push(revoked)
                }

                if let Some(t) = vc.primary_key().key_expiration_time() {
                    if t < SystemTime::now() {
                        info.push(
                            format!("expired {}",
                                    Time::try_from(t)
                                    .expect("is an OpenPGP timestamp")))
                    } else {
                        info.push(
                            format!("will expire {}",
                                    Time::try_from(t)
                                    .expect("is an OpenPGP timestamp")))
                    }
                }
            }
            Err(err) => {
                if let Some(revoked)
                    = revoked(cert.revocation_status(sq.policy, sq.time))
                {
                    info.push(revoked);
                }

                info.push(format!(
                    "not valid: {}",
                    crate::one_line_error_chain(err)));
            }
        }
    }
    info
}

pub fn list(sq: Sq, mut cmd: cli::key::list::Command) -> Result<()> {
    // Start and connect to the keystore.
    let ks = if let Some(ks) = sq.key_store()? {
        ks
    } else {
        // The key store is disabled.  Don't fail, just return
        // nothing.
        sq.hint(format_args!(
            "The key store is disabled using --no-key-store."));
        return Ok(());
    };
    let mut ks = ks.lock().unwrap();

    if let Some(pattern) = cmd.pattern {
        let mut d = None;
        if let Ok(kh) = pattern.parse::<KeyHandle>() {
            if matches!(kh, KeyHandle::Fingerprint(Fingerprint::Invalid(_))) {
                let hex = pattern.chars()
                    .map(|c| {
                        if c == ' ' { 0 } else { 1 }
                    })
                    .sum::<usize>();
                eprintln!("{} hex characters", hex);

                if hex >= 16 {
                    wprintln!("Warning: {} looks like a fingerprint or key ID, \
                               but its invalid.  Treating it as a text pattern.",
                              pattern);
                }
            } else {
                d = Some(cert_designator::CertDesignator::Cert(kh));
            }
        };

        cmd.certs.push(d.unwrap_or_else(|| {
            cert_designator::CertDesignator::Grep(pattern)
        }));
    }

    let certs = if cmd.certs.is_empty() {
        None
    } else {
        Some(sq.resolve_certs_or_fail(&cmd.certs, 0)?
             .into_iter()
             .map(|c| c.fingerprint())
             .collect::<BTreeSet<_>>())
    };

    // First, collect information by iterating over the device tree.
    //
    // We want to display the information later grouped by OpenPGP
    // certificate, and the key store doesn't provide that view.
    let mut the_keys: BTreeMap<Association, BTreeMap<Fingerprint, KeyInfo>> =
        Default::default();

    // Keep track of whether we displayed something so that we can
    // insert empty lines to provide some visual structure.
    let mut dirty = false;

    // Iterate over the tree.  We only emit information about
    // backends (and devices) that have no keys, as this may be
    // information relevant for tracking down problems, and makes
    // backends discoverable.
    let mut backends = ks.backends()?;
    for backend in &mut backends {
        let devices = backend.list()?;
        if devices.len() == 0 {
            wprintln!(initial_indent = " - ", "Backend {} has no keys.",
                      backend.id()?);
            dirty = true;
        }

        for mut device in devices {
            let keys = device.list()?;
            if keys.len() == 0 {
                wprintln!(initial_indent = "   - ", "Device {}/{} has no keys.",
                          backend.id()?, device.id()?);
                dirty = true;
            }

            for mut key in keys.into_iter() {
                let fpr = KeyHandle::from(key.fingerprint());

                let location = Location {
                    backend: backend.id()?,
                    device: device.id()?,
                    available: key.available().unwrap_or(false),
                    protection: match key.locked() {
                        Ok(Protection::Unlocked) => "unlocked",
                        Ok(_) => "locked",
                        Err(_) => "unknown protection",
                    },
                };

                let associations = if let Ok(certs)
                    = sq.lookup(vec![&fpr], None, true, true)
                {
                    certs.into_iter().map(|c| Association::Bound(c)).collect()
                } else {
                    vec![Association::Bare(key.public_key().clone())]
                };

                for a in associations {
                    the_keys.entry(a).or_default()
                        .entry(key.fingerprint())
                        .or_insert_with(|| KeyInfo {
                            key: key.public_key().clone(),
                            locations: Vec::new(),
                            signing_capable:
                            key.signing_capable().unwrap_or(false),
                            decryption_capable:
                            key.decryption_capable().unwrap_or(false),
                        })
                        .locations.push(location.clone());
                }
            }
        }
    }

    // Now display the keys grouped by OpenPGP certificates.
    for (association, keys) in the_keys.iter() {
        if let Some(c) = &certs {
            // Skip the keys the user is not interested in.
            if ! c.contains(&association.key().fingerprint()) {
                continue;
            }
        }

        if dirty {
            wprintln!();
        }
        dirty = true;

        // Emit metadata.
        wprintln!(initial_indent = " - ", "{}",
                  association.key().fingerprint());
        wprintln!(initial_indent = "   - ", "{}", association.best_userid(&sq));
        wprintln!(initial_indent = "   - ", "created {}",
                  association.key().creation_time().convert());

        if let Some(cert) = association.cert() {
            for info in key_validity(&sq, cert, None).into_iter() {
                wprintln!(initial_indent = "   - ", "{}", info);
            }
        }

        // Primary key information, if any.
        if let Some(primary) = keys.get(&association.key().fingerprint()) {
            wprintln!(initial_indent = "   - ", "usable {}", primary.usable_for());
            for loc in &primary.locations {
                wprintln!(initial_indent = "   - ", "{}", loc);
            }
        }

        // Subkey information, if any.
        for (i, (fp, key)) in keys.iter()
            .filter(|(fp, _)| **fp != association.key().fingerprint())
            .enumerate()
        {
            if i == 0 {
                wprintln!();
            }

            wprintln!(initial_indent = "   - ", "{}", fp);
            wprintln!(initial_indent = "     - ", "created {}",
                      key.key.creation_time().convert());

            if let Some(cert) = association.cert() {
                for info in key_validity(&sq, cert, Some(fp)).into_iter() {
                    wprintln!(initial_indent = "     - ", "{}", info);
                }
            }

            wprintln!(initial_indent = "     - ", "usable {}", key.usable_for());
            for loc in &key.locations {
                wprintln!(initial_indent = "     - ", "{}", loc);
            }
        }
    }

    // Add some helpful guidance if there aren't any keys.
    if the_keys.is_empty() {
        let mut hint = sq.hint(format_args!(
            "There are no secret keys."));

        if sq.key_store_path.is_some()
            || ! sq.home.as_ref()
            .map(|h| h.is_default_location()).unwrap_or(false)
        {
            hint = hint.hint(format_args!(
                "The non-default key store location {} is selected \
                 using the `{}` option.  Consider using the default \
                 key store location to access your keys.",
                sq.key_store_path()?.unwrap().display(),
                if sq.key_store_path.is_some() {
                    "--key-store"
                } else {
                    "--home"
                }));
        }

        hint.hint(format_args!(
            "Consider generating a new key like so:"))
            .sq().arg("key").arg("generate")
            .arg_value("--name", "Juliet Capulet")
            .arg_value("--email", "juliet@example.org")
            .done()
            .hint(format_args!(
            "Or, you can import an existing key:"))
            .sq().arg("key").arg("import")
            .arg("juliets-secret-key.pgp")
            .done();

        sq.hint(format_args!(
            "Sequoia calls public keys 'certificates'.  \
             Perhaps you meant to list known certificates, \
             which can be done using:"))
            .sq().arg("cert").arg("list").done();
    }

    Ok(())
}
