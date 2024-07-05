use std::path::Path;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::crypto::Password;
use openpgp::serialize::Serialize;
use openpgp::Packet;
use openpgp::Result;

use sequoia_keystore as keystore;
use keystore::Protection;

use crate::common;
use crate::Sq;
use crate::cli::types::FileOrStdout;
use crate::cli::types::FileStdinOrKeyHandle;
use crate::common::password;

pub fn password(sq: Sq,
                cert_handle: FileStdinOrKeyHandle,
                clear_password: bool,
                new_password_file: Option<&Path>,
                output: Option<FileOrStdout>,
                binary: bool)
    -> Result<()>
{
    let mut new_password_ = None;
    // Some(password) => new password
    // None => clear password
    let mut get_new_password = || -> Result<Option<Password>> {
        if new_password_.is_none() {
            new_password_ = if clear_password {
                Some(None)
            } else if let Some(path) = new_password_file.as_ref() {
                Some(Some(std::fs::read(path)?.into()))
            } else {
                Some(common::password::prompt_for_new("key")?)
            };
        }

        Ok(new_password_.clone().unwrap())
    };

    let ks = matches!(cert_handle, FileStdinOrKeyHandle::KeyHandle(_));

    let (cert, mut list) = super::get_keys(&sq, cert_handle, vec![])?;
    let uid = sq.best_userid(&cert, true);

    if ks {
        // Change the password of the secret key material on the key
        // store.
        for (key, _primary, remote_keys) in list.into_iter() {
            let remote_keys = remote_keys.expect("have remote keys");
            assert!(! remote_keys.is_empty());
            for mut remote_key in remote_keys.into_iter() {
                let provide_password
                    = if let Protection::Password(hint) = remote_key.locked()?
                {
                    let mut unlocked = false;
                    for p in sq.cached_passwords() {
                        if remote_key.unlock(p).is_ok() {
                            unlocked = true;
                            break;
                        }
                    }

                    if ! unlocked {
                        if let Some(hint) = hint {
                            eprintln!("{}", hint);
                        }

                        loop {
                            let p = password::prompt_to_unlock(&format!(
                                "{}/{}, {}",
                                cert.keyid(), key.keyid(), uid))?;

                            match remote_key.unlock(p.clone()) {
                                Ok(()) => {
                                    sq.cache_password(p.clone());
                                    break;
                                }
                                Err(err) => {
                                    eprintln!("Failed to unlock key: {}", err);
                                }
                            }
                        }
                    }
                    true
                } else {
                    remote_key.password_source()?.is_inline()
                };

                let password = if provide_password {
                    if let Some(password) = get_new_password()? {
                        Some(password)
                    } else {
                        // change_password interprets None as prompt for
                        // password, and "" as clear password.
                        Some("".into())
                    }
                } else {
                    None
                };

                remote_key.change_password(password.as_ref())
                    .with_context(|| {
                        format!("Changing {}'s password", key.fingerprint())
                    })?;
            }
        }
    } else {
        // First, decrypt all secrets.
        for (key, _primary, _remote_keys) in list.iter_mut() {
            *key = sq.decrypt_key(
                Some(&cert),
                key.clone().parts_into_secret()?,
                true, // May prompt.
                false, // Don't allow skipping.
            )?.0.parts_into_public();
        }

        let mut packets: Vec<Packet> = Vec::new();
        if let Some(new) = get_new_password()? {
            for (key, primary, _remote_keys) in list.into_iter() {
                let key = key.parts_into_secret()
                    .expect("have secret key amterial")
                    .encrypt_secret(&new)?
                    .parts_into_public();

                if primary {
                    packets.push(
                        Packet::PublicKey(key.role_into_primary()));
                } else {
                    packets.push(
                        Packet::PublicSubkey(key.role_into_subordinate()));
                }
            }
        } else {
            for (key, primary, _remote_keys) in list.into_iter() {
                let key = key.parts_into_public();
                if primary {
                    packets.push(
                        Packet::PublicKey(key.role_into_primary()));
                } else {
                    packets.push(
                        Packet::PublicSubkey(key.role_into_subordinate()));
                }
            }
        }

        let cert = cert.insert_packets(packets)?;

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
