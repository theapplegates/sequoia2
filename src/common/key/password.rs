use std::path::Path;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::crypto::Password;
use openpgp::packet::key;
use openpgp::packet::Key;
use openpgp::packet::key::SecretKeyMaterial;
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

    let from_file = match &cert_handle {
        FileStdinOrKeyHandle::FileOrStdin(_file) => {
            true
        }
        FileStdinOrKeyHandle::KeyHandle(_kh) => {
            false
        }
    };

    let cert = sq.lookup_one(cert_handle, None, true)?;

    if from_file {
        // First, decrypt all secrets.
        let mut decrypted: Vec<Packet> = vec![
            decrypt_key(
                &sq,
                cert.primary_key().key().clone().parts_into_secret()?,
            )?.into(),
        ];
        for ka in cert.keys().subkeys().secret() {
            decrypted.push(
                decrypt_key(&sq, ka.key().clone().parts_into_secret()?)?
                    .into(),
            );
        }
        let mut cert = cert.insert_packets(decrypted)?;
        assert_eq!(
            cert.keys().secret().count(),
            cert.keys().unencrypted_secret().count()
        );

        if let Some(new) = get_new_password()? {
            let mut encrypted: Vec<Packet> = vec![
                cert
                    .primary_key()
                    .key()
                    .clone()
                    .parts_into_secret()?
                    .encrypt_secret(&new)?
                    .into()
            ];
            for ka in cert.keys().subkeys().unencrypted_secret() {
                encrypted.push(
                    ka.key()
                        .clone()
                        .parts_into_secret()?
                        .encrypt_secret(&new)?
                        .into(),
                );
            }
            cert = cert.insert_packets(encrypted)?;
        }

        let output = output.unwrap_or_else(|| FileOrStdout::new(None));
        let mut output = output.for_secrets().create_safe(sq.force)?;
        if binary {
            cert.as_tsk().serialize(&mut output)?;
        } else {
            cert.as_tsk().armored().serialize(&mut output)?;
        }
    } else {
        let vc = cert.with_policy(sq.policy, sq.time)?;

        let uid = sq.best_userid(&cert, true);

        let ks = sq.key_store_or_else()?;
        let mut ks = ks.lock().unwrap();

        for ka in vc.keys() {
            let keys = ks.find_key(ka.key_handle())
                .with_context(|| {
                    format!("Looking up {}", ka.fingerprint())
                })?;

            // XXX: What should we do if the key is present multiple
            // times?
            let mut key = keys.into_iter().next().expect("have at least one");

            let provide_password
                = if let Protection::Password(hint) = key.locked()?
            {
                let mut unlocked = false;
                for p in sq.cached_passwords() {
                    if key.unlock(p).is_ok() {
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
                            "Please enter the password to decrypt \
                             the key {}/{}, {}",
                            cert.keyid(), ka.keyid(), uid))?;

                        match key.unlock(p.clone()) {
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
                key.password_source()?.is_inline()
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

            key.change_password(password.as_ref())
                .with_context(|| {
                    format!("Changing {}'s password", key.fingerprint())
                })?;
        }
    }

    Ok(())
}

// Decrypts a key, if possible.
//
// The passwords in `passwords` are tried first.  If the key can't be
// decrypted using those, the user is prompted.  If a valid password
// is entered, it is added to `passwords`.
fn decrypt_key<R>(sq: &Sq, key: Key<key::SecretParts, R>)
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

            for p in sq.password_cache.lock().unwrap().iter() {
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
                            sq.password_cache.lock().unwrap().push(p.into());
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
