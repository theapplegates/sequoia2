use openpgp::parse::Parse;
use openpgp::serialize::Serialize;
use openpgp::Cert;
use openpgp::Packet;
use openpgp::Result;
use sequoia_openpgp as openpgp;

use crate::common::prompt_for_password;
use crate::Config;
use crate::cli;
use crate::decrypt_key;

pub fn password(
    config: Config,
    command: cli::key::PasswordCommand,
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
        prompt_for_password("New password: ", Some("Repeat new password: "))?
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
