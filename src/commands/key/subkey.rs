use chrono::DateTime;
use chrono::Utc;

use openpgp::cert::KeyBuilder;
use openpgp::parse::Parse;
use openpgp::serialize::Serialize;
use openpgp::types::KeyFlags;
use openpgp::Cert;
use openpgp::Result;
use sequoia_openpgp as openpgp;

use crate::sq_cli::key::EncryptPurpose;
use crate::sq_cli::key::SubkeyCommand;
use crate::sq_cli::key::SubkeyAddCommand;
use crate::Config;

pub fn subkey(config: Config, command: SubkeyCommand) -> Result<()> {
    match command {
        SubkeyCommand::Add(c) => subkey_add(config, c)?,
    }

    Ok(())
}

/// Add a new Subkey for an existing primary key
///
/// Creates a subkey with features (e.g. `KeyFlags`, `CipherSuite`) based on
/// user input (or application-wide defaults if not specified).
/// If no specific expiry is requested, the subkey never expires.
fn subkey_add(
    config: Config,
    command: SubkeyAddCommand,
) -> Result<()> {
    let input = command.input.open()?;
    let cert = Cert::from_reader(input)?;
    let valid_cert = cert.with_policy(&config.policy, config.time)?;

    let validity = command
        .expiry
        .as_duration(DateTime::<Utc>::from(config.time))?;

    let keyflags = KeyFlags::empty()
        .set_authentication_to(command.can_authenticate)
        .set_signing_to(command.can_sign)
        .set_storage_encryption_to(matches!(
            command.can_encrypt,
            Some(EncryptPurpose::Storage) | Some(EncryptPurpose::Universal)
        ))
        .set_transport_encryption_to(matches!(
            command.can_encrypt,
            Some(EncryptPurpose::Transport) | Some(EncryptPurpose::Universal)
        ));

    let new_cert = KeyBuilder::new(keyflags)
        .set_creation_time(config.time)
        .set_cipher_suite(command.cipher_suite.as_ciphersuite())
        .subkey(valid_cert)?
        .set_key_validity_period(validity)?
        .attach_cert()?;

    let mut sink = command.output.create_safe(config.force)?;
    if command.binary {
        new_cert.as_tsk().serialize(&mut sink)?;
    } else {
        new_cert.as_tsk().armored().serialize(&mut sink)?;
    }
    Ok(())
}
