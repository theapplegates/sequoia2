use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::KeyHandle;
use openpgp::Result;
use openpgp::cert::amalgamation::key::PrimaryKey;
use openpgp::parse::Parse;
use openpgp::packet::key;
use openpgp::packet::Key;

use sequoia_keystore as keystore;

use crate::cli::types::FileStdinOrKeyHandle;
use crate::Sq;


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
pub fn get_keys<'a>(sq: &'a Sq,
                    cert_handle: FileStdinOrKeyHandle,
                    keys: Vec<KeyHandle>)
    -> Result<(Cert, Vec<(Key<key::PublicParts, key::UnspecifiedRole>,
                          bool,
                          Option<Vec<keystore::Key>>)>)>
{
    let mut ks = None;

    let cert = match cert_handle {
        FileStdinOrKeyHandle::FileOrStdin(ref file) => {
            let input = file.open()?;
            let cert = Cert::from_buffered_reader(input)?;

            // If it is not a TSK, there is nothing to do.
            if ! cert.is_tsk() {
                return Err(anyhow::anyhow!(
                    "{} does not contain any secret key material.",
                    cert.fingerprint()));
            }

            cert
        }
        FileStdinOrKeyHandle::KeyHandle(ref kh) => {
            ks = Some(sq.key_store_or_else()?);
            sq.lookup_one(kh, None, true)?
        }
    };

    let mut ks = ks.map(|ks| ks.lock().unwrap());

    let list: Vec<(Key<_, _>, bool, Option<_>)> = if keys.is_empty() {
        // Get all secret key material.
        let list: Vec<_>
            = cert.keys().filter_map(|ka| {
                if let Some(ks) = ks.as_mut() {
                    let remote_keys = ks.find_key(ka.key_handle()).ok()?;
                    if remote_keys.is_empty() {
                        None
                    } else {
                        Some((ka.key().clone(), ka.primary(), Some(remote_keys)))
                    }
                } else {
                    if ka.has_secret() {
                        Some((ka.key().clone(), ka.primary(), None))
                    } else {
                        None
                    }
                }
            }).collect();

        // Make the primary last so that if something goes wrong it
        // is still possible to generate a revocation certificate.
        list.into_iter().rev().collect()
    } else {
        // Get only the specified secret key material.
        let mut list = Vec::new();

        let mut not_found_key_count = 0;
        let mut no_secret_key_material_count = 0;
        for key in keys.into_iter() {
            let ka = if let Some(ka)
                = cert.keys().find(|ka| ka.fingerprint().aliases(&key))
            {
                ka
            } else {
                wprintln!("{} does not contain {}",
                          cert.fingerprint(), key);
                not_found_key_count += 1;
                continue;
            };

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
                          key);
                no_secret_key_material_count += 1;
                continue;
            }

            list.push((ka.key().clone(), ka.primary(), remote_keys));
        }

        if not_found_key_count > 1 {
            // Plural.
            return Err(anyhow::anyhow!(
                "{} keys not found", not_found_key_count));
        } else if not_found_key_count > 0 {
            // Singular.
            return Err(anyhow::anyhow!(
                "{} key not found", not_found_key_count));
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

        list
    };

    assert!(! list.is_empty());

    Ok((cert, list))
}
