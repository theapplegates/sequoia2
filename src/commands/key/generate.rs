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

use crate::sq_cli;
use crate::Config;

pub fn generate(
    config: Config,
    command: sq_cli::key::GenerateCommand,
) -> Result<()> {
    let mut builder = CertBuilder::new();

    // User ID
    if command.userid.is_empty() {
        eprintln!("No user ID given, using direct key signature");
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
    use sq_cli::key::EncryptPurpose::*;
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
        let p0 =
            rpassword::prompt_password("Enter password to protect the key: ")?
                .into();
        let p1 = rpassword::prompt_password("Repeat the password once more: ")?
            .into();

        if p0 == p1 {
            builder = builder.set_password(Some(p0));
        } else {
            return Err(anyhow::anyhow!("Passwords do not match."));
        }
    }

    if command.export.is_none() {
        return Err(anyhow::anyhow!(
            "Saving generated key to the store isn't implemented yet."
        ));
    }

    // Generate the key
    let (cert, rev) = builder.generate()?;

    // Export
    if let Some(key_path) = command.export.as_ref() {
        if &format!("{}", key_path.display()) == "-"
            && command.rev_cert.is_none()
        {
            return Err(anyhow::anyhow!(
                "Missing arguments: --rev-cert is mandatory if --export is '-'."
            ))
        }

        let rev_path = if command.rev_cert.is_some() {
            command.rev_cert
        } else {
            Some(PathBuf::from(format!("{}.rev", key_path.display())))
        };

        let headers = cert.armor_headers();

        // write out key
        {
            let headers: Vec<_> = headers
                .iter()
                .map(|value| ("Comment", value.as_str()))
                .collect();

            let w = config.create_or_stdout_safe(Some(key_path))?;
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

            let w = config.create_or_stdout_safe(rev_path.as_deref())?;
            let mut w = Writer::with_headers(w, Kind::Signature, headers)?;
            Packet::Signature(rev).serialize(&mut w)?;
            w.finalize()?;
        }
    }

    Ok(())
}
