use std::path::PathBuf;

use chrono::DateTime;
use chrono::Utc;

use openpgp::armor::Kind;
use openpgp::armor::Writer;
use openpgp::cert::CertBuilder;
use openpgp::serialize::Serialize;
use openpgp::types::KeyFlags;
use openpgp::Packet;
use openpgp::Result;
use sequoia_openpgp as openpgp;

use crate::common::password;
use crate::Config;
use crate::cli::types::FileOrStdout;
use crate::cli;

pub fn generate(
    config: Config,
    command: cli::key::GenerateCommand,
) -> Result<()> {
    let mut builder = CertBuilder::new();

    // User ID
    if command.userid.is_empty() {
        wprintln!("No user ID given, using direct key signature");
    } else {
        for uid in command.userid {
            builder = builder.add_userid(uid);
        }
    }

    // Creation time.
    builder = builder.set_creation_time(config.time);

    // Expiration.
    builder = builder.set_validity_period(
        command
        .expiry
        .as_duration(DateTime::<Utc>::from(config.time))?
    );

    // Cipher Suite
    builder = builder.set_cipher_suite(
        command.cipher_suite.as_ciphersuite()
    );

    // Signing Capability
    match (command.can_sign, command.cannot_sign) {
        (false, false) | (true, false) => {
            builder = builder.add_signing_subkey();
        }
        (false, true) => { /* no signing subkey */ }
        (true, true) => {
            return Err(anyhow::anyhow!(
                "Conflicting arguments --can-sign and --cannot-sign"
            ));
        }
    }

    // Authentication Capability
    match (command.can_authenticate, command.cannot_authenticate) {
        (false, false) | (true, false) => {
            builder = builder.add_authentication_subkey()
        }
        (false, true) => { /* no authentication subkey */ }
        (true, true) => {
            return Err(anyhow::anyhow!(
                "Conflicting arguments --can-authenticate and\
                                --cannot-authenticate"
            ));
        }
    }

    // Encryption Capability
    use cli::key::EncryptPurpose::*;
    match (command.can_encrypt, command.cannot_encrypt) {
        (Some(Universal), false) | (None, false) => {
            builder = builder.add_subkey(
                KeyFlags::empty()
                    .set_transport_encryption()
                    .set_storage_encryption(),
                None,
                None,
            );
        }
        (Some(Storage), false) => {
            builder = builder.add_storage_encryption_subkey();
        }
        (Some(Transport), false) => {
            builder = builder.add_transport_encryption_subkey();
        }
        (None, true) => { /* no encryption subkey */ }
        (Some(_), true) => {
            return Err(anyhow::anyhow!(
                "Conflicting arguments --can-encrypt and \
                             --cannot-encrypt"
            ));
        }
    }

    if command.with_password {
        builder = builder.set_password(
            password::prompt_for_new("key")?);
    }

    if command.output.path().is_none() && command.rev_cert.is_none() {
        return Err(anyhow::anyhow!(
            "Missing arguments: --rev-cert is mandatory if --output is '-'."
        ))
    }

    // Generate the key
    let (cert, rev) = builder.generate()?;

    // Export
    let rev_path = if command.rev_cert.is_some() {
        FileOrStdout::new(command.rev_cert)
    } else {
        FileOrStdout::from(PathBuf::from(format!("{}.rev", command.output)))
    };

    let headers = cert.armor_headers();

    // write out key
    {
        let headers: Vec<_> = headers
            .iter()
            .map(|value| ("Comment", value.as_str()))
            .collect();

        let w = command.output.for_secrets().create_safe(config.force)?;
        let mut w = Writer::with_headers(w, Kind::SecretKey, headers)?;
        cert.as_tsk().serialize(&mut w)?;
        w.finalize()?;
    }

    // write out rev cert
    {
        let mut headers: Vec<_> = headers
            .iter()
            .map(|value| ("Comment", value.as_str()))
            .collect();
        headers.insert(0, ("Comment", "Revocation certificate for"));

        let w = rev_path.create_safe(config.force)?;
        let mut w = Writer::with_headers(w, Kind::Signature, headers)?;
        Packet::Signature(rev).serialize(&mut w)?;
        w.finalize()?;
    }

    Ok(())
}
