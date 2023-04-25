use std::time::Duration;
use std::time::SystemTime;

use openpgp::armor::Kind;
use openpgp::armor::Writer;
use openpgp::cert::prelude::*;
use openpgp::cert::CertBuilder;
use openpgp::serialize::Serialize;
use openpgp::types::KeyFlags;
use openpgp::Packet;
use openpgp::Result;
use sequoia_openpgp as openpgp;

use crate::parse_duration;
use crate::sq_cli;
use crate::Config;
use crate::SECONDS_IN_YEAR;

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
    match (command.expires, command.expires_in) {
        (None, None) =>
        // Default expiration.
        {
            builder = builder.set_validity_period(Some(Duration::new(
                3 * SECONDS_IN_YEAR,
                0,
            )))
        }
        (Some(t), None) if t == "never" => {
            builder = builder.set_validity_period(None)
        }
        (Some(t), None) => {
            let now = builder
                .creation_time()
                .unwrap_or_else(std::time::SystemTime::now);
            let expiration = SystemTime::from(crate::parse_iso8601(
                &t,
                chrono::NaiveTime::from_hms_opt(0, 0, 0).unwrap(),
            )?);
            let validity = expiration.duration_since(now)?;
            builder =
                builder.set_creation_time(now).set_validity_period(validity);
        }
        (None, Some(d)) if d == "never" => {
            builder = builder.set_validity_period(None)
        }
        (None, Some(d)) => {
            let d = parse_duration(&d)?;
            builder = builder.set_validity_period(Some(d));
        }
        (Some(_), Some(_)) => unreachable!("conflicting args"),
    }

    // Cipher Suite
    use sq_cli::key::CipherSuite::*;
    match command.cipher_suite {
        Rsa3k => {
            builder = builder.set_cipher_suite(CipherSuite::RSA3k);
        }
        Rsa4k => {
            builder = builder.set_cipher_suite(CipherSuite::RSA4k);
        }
        Cv25519 => {
            builder = builder.set_cipher_suite(CipherSuite::Cv25519);
        }
    }

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

    // Generate the key
    let (cert, rev) = builder.generate()?;

    // Export
    if command.export.is_some() {
        let (key_path, rev_path) =
            match (command.export.as_deref(), command.rev_cert.as_deref()) {
                (Some("-"), Some("-")) => ("-".to_string(), "-".to_string()),
                (Some("-"), Some(ref rp)) => ("-".to_string(), rp.to_string()),
                (Some("-"), None) => {
                    return Err(anyhow::anyhow!(
                        "Missing arguments: --rev-cert is mandatory \
                                     if --export is '-'."
                    ))
                }
                (Some(ref kp), None) => (kp.to_string(), format!("{}.rev", kp)),
                (Some(ref kp), Some("-")) => (kp.to_string(), "-".to_string()),
                (Some(ref kp), Some(ref rp)) => {
                    (kp.to_string(), rp.to_string())
                }
                _ => {
                    return Err(anyhow::anyhow!(
                        "Conflicting arguments --rev-cert and \
                                     --export"
                    ))
                }
            };

        let headers = cert.armor_headers();

        // write out key
        {
            let headers: Vec<_> = headers
                .iter()
                .map(|value| ("Comment", value.as_str()))
                .collect();

            let w = config.create_or_stdout_safe(Some(&key_path))?;
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

            let w = config.create_or_stdout_safe(Some(&rev_path))?;
            let mut w = Writer::with_headers(w, Kind::Signature, headers)?;
            Packet::Signature(rev).serialize(&mut w)?;
            w.finalize()?;
        }
    } else {
        return Err(anyhow::anyhow!(
            "Saving generated key to the store isn't implemented \
                         yet."
        ));
    }

    Ok(())
}
