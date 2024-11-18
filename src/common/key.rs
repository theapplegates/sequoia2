use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Result;
use openpgp::cert::amalgamation::key::PrimaryKey;
use openpgp::packet::key;
use openpgp::packet::Key;

use sequoia_keystore as keystore;

use crate::Sq;
use crate::cli::types::CertDesignators;
use crate::cli::types::FileStdinOrKeyHandle;
use crate::cli::types::KeyDesignators;
use crate::cli::types::cert_designator;


mod expire;
pub use expire::expire;

pub mod delete;
pub use delete::delete;

pub mod password;
pub use password::password;

/// Looks up the certificate and returns the specified keys.
///
/// If `keys` is empty, all keys are returned.
///
/// If the keys are loaded from the certificate store, then a handle
/// to the key is returned for each key.  Otherwise, the secret key is
/// returned.
///
/// An error is returned if a key is not found, or there is no known
/// secret key material.
///
/// The returned keys are not unlocked.
pub fn get_keys<CA, CP, CO, CD, KO, KD>(
    sq: &Sq,
    cert: &CertDesignators<CA, CP, CO, CD>,
    keys: Option<&KeyDesignators<KO, KD>>)
    -> Result<(Cert,
               FileStdinOrKeyHandle,
               Vec<(Key<key::PublicParts, key::UnspecifiedRole>,
                    bool,
                    Option<Vec<keystore::Key>>)>)>
where CP: cert_designator::ArgumentPrefix,
      KO: typenum::Unsigned,
{
    let mut ks = None;

    assert_eq!(cert.len(), 1);
    if let Some(keys) = keys {
        assert!(keys.len() > 0);
    }

    let (cert, cert_source)
        = sq.resolve_cert(&cert, sequoia_wot::FULLY_TRUSTED)?;

    match cert_source {
        FileStdinOrKeyHandle::FileOrStdin(ref file) => {
            // If it is not a TSK, there is nothing to do.
            if ! cert.is_tsk() {
                return Err(anyhow::anyhow!(
                    "{} (read from {}) does not contain any secret \
                     key material.",
                    cert.fingerprint(), file));
            }
        }
        FileStdinOrKeyHandle::KeyHandle(ref _kh) => {
            ks = Some(sq.key_store_or_else()?);
        }
    };

    let vc = Cert::with_policy(&cert, sq.policy, sq.time)
        .with_context(|| {
            format!("The certificate {} is not valid under the \
                     current policy.",
                    cert.fingerprint())
        })?;

    let kas = if let Some(keys) = keys {
        sq.resolve_keys(&vc, &cert_source, &keys, true)?
    } else {
        vc.keys().collect::<Vec<_>>()
    };

    let mut ks = ks.map(|ks| ks.lock().unwrap());

    let mut list: Vec<(Key<_, _>, bool, Option<_>)> = Vec::new();

    let mut no_secret_key_material_count = 0;
    for ka in kas.into_iter() {
        let (no_secret_key_material, remote_keys)
            = if let Some(ks) = ks.as_mut()
        {
            let remote_keys = ks.find_key(ka.key_handle())?;
            (remote_keys.is_empty(), Some(remote_keys))
        } else {
            (! ka.has_secret(), None)
        };

        if no_secret_key_material {
            wprintln!("{} does not contain any secret key material",
                      ka.fingerprint());
            no_secret_key_material_count += 1;
            continue;
        }

        list.push((ka.key().clone(), ka.primary(), remote_keys));
    }

    if no_secret_key_material_count > 1 {
        // Plural.
        return Err(anyhow::anyhow!(
            "{} of the specified keys don't have secret key material",
            no_secret_key_material_count));
    } else if no_secret_key_material_count > 0 {
        // Singular.
        return Err(anyhow::anyhow!(
            "{} of the specified keys doesn't have secret key material",
            no_secret_key_material_count));
    }

    assert!(! list.is_empty());

    Ok((cert, cert_source, list))
}
