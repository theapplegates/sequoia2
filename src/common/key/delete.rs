//! Deletes secret key material.
use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::KeyHandle;
use openpgp::Packet;
use openpgp::Result;
use openpgp::cert::amalgamation::key::PrimaryKey;
use openpgp::parse::Parse;
use openpgp::serialize::Serialize;

use crate::cli::types::FileOrStdout;
use crate::cli::types::FileStdinOrKeyHandle;
use crate::Sq;

pub fn delete(sq: Sq,
              cert_handle: FileStdinOrKeyHandle,
              keys: Vec<KeyHandle>,
              output: Option<FileOrStdout>,
              binary: bool)
    -> Result<()>
{
    let (cert, mut ks) = match cert_handle {
        FileStdinOrKeyHandle::FileOrStdin(ref file) => {
            let input = file.open()?;
            let cert = Cert::from_buffered_reader(input)?;

            // If it is not a TSK, there is nothing to strip.
            if ! cert.is_tsk() {
                return Err(anyhow::anyhow!(
                    "{} does not contain any secret key material.",
                    cert.fingerprint()));
            }

            (cert, None)
        }
        FileStdinOrKeyHandle::KeyHandle(ref kh) => {
            let cert = sq.lookup_one(kh, None, true)?;

            let ks = sq.key_store_or_else()?;
            let ks = ks.lock().unwrap();

            (cert, Some(ks))
        }
    };

    let to_delete: Vec<(_, _)> = if keys.is_empty() {
        // Delete all secret key material.
        let to_delete: Vec<_>
            = cert.keys().filter_map(|ka| {
                if let Some(ks) = ks.as_mut() {
                    let remote_keys = ks.find_key(ka.key_handle()).ok()?;
                    if remote_keys.is_empty() {
                        None
                    } else {
                        Some((ka, Some(remote_keys)))
                    }
                } else {
                    if ka.has_secret() {
                        Some((ka, None))
                    } else {
                        None
                    }
                }
            }).collect();

        // Delete the primary last so that if something goes wrong it
        // is still possible to generate a revocation certificate.
        to_delete.into_iter().rev().collect()
    } else {
        // Delete only the specified secret key material.
        let mut to_delete = Vec::new();

        let mut missing_key_count = 0;
        let mut no_secret_key_material_count = 0;
        for key in keys.into_iter() {
            let ka = if let Some(ka)
                = cert.keys().find(|ka| ka.fingerprint().aliases(&key))
            {
                ka
            } else {
                eprintln!("{} does not contain {}",
                          cert.fingerprint(), key);
                missing_key_count += 1;
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
                eprintln!("{} does not contain any secret key material",
                          key);
                no_secret_key_material_count += 1;
                continue;
            }

            to_delete.push((ka, remote_keys));
        }

        if missing_key_count > 1 {
            // Plural.
            return Err(anyhow::anyhow!(
                "{} keys not found", missing_key_count));
        } else if missing_key_count > 0 {
            // Singular.
            return Err(anyhow::anyhow!(
                "{} key not found", missing_key_count));
        }

        if no_secret_key_material_count > 1 {
            // Plural.
            return Err(anyhow::anyhow!(
                "{} of the keys to delete don't have secret key material",
                no_secret_key_material_count));
        } else if no_secret_key_material_count > 0 {
            // Singular.
            return Err(anyhow::anyhow!(
                "{} of the keys to delete doesn't have secret key material",
                no_secret_key_material_count));
        }

        to_delete
    };

    assert!(! to_delete.is_empty());

    if ks.is_some() {
        // Delete the secret key material from the key store.
        for (ka, remote_keys) in to_delete.into_iter() {
            let remote_keys = remote_keys.expect("have remote keys");
            assert!(! remote_keys.is_empty());
            for mut kh in remote_keys.into_iter() {
                kh.delete_secret_key_material().with_context(|| {
                    format!("Deleting {}", ka.fingerprint())
                })?;
            }
        }
    } else {
        // Strip the secret key material from the certificate.
        let mut stripped: Vec<Packet> = Vec::new();

        for (ka, _) in to_delete.into_iter() {
            let pk = ka.key().clone().take_secret().0;
            if ka.primary() {
                stripped.push(
                    Packet::PublicKey(pk.role_into_primary()));
            } else {
                stripped.push(
                    Packet::PublicSubkey(pk.role_into_subordinate()));
            }
        }

        let cert = cert.insert_packets(
            stripped.into_iter().map(|stripped| Packet::from(stripped)))?;

        let output = output.unwrap_or_else(|| FileOrStdout::new(None));
        let mut output = output.for_secrets().create_safe(sq.force)?;
        if binary {
            cert.as_tsk().serialize(&mut output)?;
        } else {
            cert.as_tsk().armored().serialize(&mut output)?;
        }
    }

    Ok(())
}
