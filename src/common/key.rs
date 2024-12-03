use sequoia_openpgp as openpgp;
use openpgp::Result;
use openpgp::cert::amalgamation::key::ValidErasedKeyAmalgamation;
use openpgp::packet::key::KeyParts;

use sequoia_keystore as keystore;

use crate::Sq;
use crate::cli::types::FileStdinOrKeyHandle;


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
pub fn get_keys<'a, P>(
    sq: &Sq,
    cert_source: &FileStdinOrKeyHandle,
    kas: &[&'a ValidErasedKeyAmalgamation<'a, P>],
    ignore_missing: bool)
    -> Result<Vec<(&'a ValidErasedKeyAmalgamation<'a, P>,
                   Option<Vec<keystore::Key>>)>>
where
    P: 'a + KeyParts,
{
    let mut list: Vec<(&ValidErasedKeyAmalgamation<'a, P>, Option<_>)>
        = Vec::new();

    let mut no_secret_key_material_count = 0;

    let warning = if ignore_missing {
        "Warning: "
    } else {
        ""
    };

    match cert_source {
        FileStdinOrKeyHandle::FileOrStdin(ref _file) => {
            // If it is not a TSK, there is nothing to do.
            for ka in kas.into_iter() {
                let no_secret_key_material = ! ka.has_secret();
                if no_secret_key_material {
                    weprintln!("{}{} does not contain any secret key material",
                               warning, ka.fingerprint());
                    no_secret_key_material_count += 1;
                    continue;
                }

                list.push((ka, None));
            }
        }
        FileStdinOrKeyHandle::KeyHandle(ref _kh) => {
            let ks = sq.key_store_or_else()?;
            let mut ks = ks.lock().unwrap();

            for ka in kas.into_iter() {
                let remote_keys = ks.find_key(ka.key_handle())?;
                let no_secret_key_material = remote_keys.is_empty();

                if no_secret_key_material {
                    weprintln!("{}{} does not contain any secret key material",
                               warning, ka.fingerprint());
                    no_secret_key_material_count += 1;
                    continue;
                }

                list.push((ka, Some(remote_keys)));
            }
        }
    }

    if ! ignore_missing {
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
    }

    Ok(list)
}
