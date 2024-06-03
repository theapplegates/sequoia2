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
use crate::cli;
use crate::decrypt_key;
use crate::cli::types::FileOrStdout;
use crate::common::password;

pub fn password(
    sq: Sq,
    command: cli::key::PasswordCommand,
) -> Result<()> {
    let mut new_password_ = None;
    // Some(password) => new password
    // None => clear password
    let mut get_new_password = || -> Result<Option<Password>> {
        if new_password_.is_none() {
            new_password_ = if command.clear {
                Some(None)
            } else if let Some(path) = command.new_password_file.as_ref() {
                Some(Some(std::fs::read(path)?.into()))
            } else {
                Some(common::password::prompt_for_new("key")?)
            };
        }

        Ok(new_password_.clone().unwrap())
    };

    if let Some(file) = command.cert_file {
        assert!(command.cert.is_none());

        let key = sq.lookup_one(file, None, true)?;

        // First, decrypt all secrets.
        let passwords = &mut Vec::new();
        for password in command.old_password_file {
            passwords.push(std::fs::read(password)?.into());
        };
        let mut decrypted: Vec<Packet> = vec![
            decrypt_key(
                key.primary_key().key().clone().parts_into_secret()?,
                passwords,
            )?.into(),
        ];
        for ka in key.keys().subkeys().secret() {
            decrypted.push(
                decrypt_key(ka.key().clone().parts_into_secret()?, passwords)?
                    .into(),
            );
        }
        let mut key = key.insert_packets(decrypted)?;
        assert_eq!(
            key.keys().secret().count(),
            key.keys().unencrypted_secret().count()
        );

        if let Some(new) = get_new_password()? {
            let mut encrypted: Vec<Packet> = vec![
                key
                    .primary_key()
                    .key()
                    .clone()
                    .parts_into_secret()?
                    .encrypt_secret(&new)?
                    .into()
            ];
            for ka in key.keys().subkeys().unencrypted_secret() {
                encrypted.push(
                    ka.key()
                        .clone()
                        .parts_into_secret()?
                        .encrypt_secret(&new)?
                        .into(),
                );
            }
            key = key.insert_packets(encrypted)?;
        }

        let output = command.output.unwrap_or_else(|| FileOrStdout::new(None));
        let mut output = output.for_secrets().create_safe(sq.force)?;
        if command.binary {
            key.as_tsk().serialize(&mut output)?;
        } else {
            key.as_tsk().armored().serialize(&mut output)?;
        }
    } else if let Some(kh) = command.cert {
        assert!(command.output.is_none());

        for password in command.old_password_file {
            sq.cache_password(std::fs::read(password)?.into());
        }

        let cert = sq.lookup_one(kh, None, true)?;
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
    } else {
        panic!("clap ensures --cert-file or --cert");
    }

    Ok(())
}
