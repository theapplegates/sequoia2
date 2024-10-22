use std::{
    cmp::Ordering,
    collections::BTreeMap,
    fmt,
};

use sequoia_openpgp::{
    Cert,
    Fingerprint,
    KeyHandle,
    packet::{Key, key},
};

use sequoia_keystore as keystore;
use keystore::Protection;

use crate::cli;
use crate::Convert;
use crate::Sq;
use crate::Result;

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

pub fn list(sq: Sq, _command: cli::key::list::Command) -> Result<()> {
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

        if sq.key_store_path.is_some() || ! sq.home.is_default_location() {
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
