use anyhow::Context;

use openpgp::parse::Parse;
use openpgp::serialize::Serialize;
use openpgp::Cert;
use openpgp::Packet;
use openpgp::Result;
use sequoia_openpgp as openpgp;

use crate::decrypt_key;
use crate::sq_cli;
use crate::Config;

pub fn password(
    config: Config,
    command: sq_cli::key::PasswordCommand,
) -> Result<()> {
    let input = command.input.open()?;
    let key = Cert::from_reader(input)?;

    if !key.is_tsk() {
        return Err(anyhow::anyhow!("Certificate has no secrets"));
    }

    // First, decrypt all secrets.
    let passwords = &mut Vec::new();
    let mut decrypted: Vec<Packet> = vec![decrypt_key(
        key.primary_key().key().clone().parts_into_secret()?,
        passwords,
    )?
    .into()];
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

    let new_password = if command.clear {
        None
    } else {
        let prompt_0 = rpassword::prompt_password("New password: ")
            .context("Error reading password")?;
        let prompt_1 = rpassword::prompt_password("Repeat new password: ")
            .context("Error reading password")?;

        if prompt_0 != prompt_1 {
            return Err(anyhow::anyhow!("Passwords do not match"));
        }

        if prompt_0.is_empty() {
            // Empty password means no password.
            None
        } else {
            Some(prompt_0.into())
        }
    };

    if let Some(new) = new_password {
        let mut encrypted: Vec<Packet> = vec![key
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()?
            .encrypt_secret(&new)?
            .into()];
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

    let mut output = command.output.create_safe(config.force)?;
    if command.binary {
        key.as_tsk().serialize(&mut output)?;
    } else {
        key.as_tsk().armored().serialize(&mut output)?;
    }
    Ok(())
}
