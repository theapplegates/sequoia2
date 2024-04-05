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
use crate::ImportStatus;

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
    use cli::types::EncryptPurpose::*;
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

    let rev_path = if let Some(rev_cert) = command.rev_cert {
        FileOrStdout::new(Some(rev_cert))
    } else if let Some(path) = command.output.as_ref().and_then(|o| o.path()) {
        let mut path = path.clone();
        path.as_mut_os_string().push(".rev");
        FileOrStdout::from(path)
    } else {
        return Err(anyhow::anyhow!(
            "Missing arguments: --rev-cert is mandatory if --output is '-' \
             or not provided."
        ));
    };

    // Generate the key
    let (cert, rev) = builder.generate()?;

    let headers = cert.armor_headers();

    let on_keystore = command.output.is_none();

    // write out key
    {
        let headers: Vec<_> = headers
            .iter()
            .map(|value| ("Comment", value.as_str()))
            .collect();

        match command.output {
            Some(output_file) => {
                // Write the key to a file or to stdout.
                let w = output_file.for_secrets().create_safe(config.force)?;
                let mut w = Writer::with_headers(w, Kind::SecretKey, headers)?;
                cert.as_tsk().serialize(&mut w)?;
                w.finalize()?;
            }
            None => {
                // write the key to the key store
                match config.import_key(cert.clone()) {
                    Ok(ImportStatus::New) => { /* success */ }
                    Ok(ImportStatus::Unchanged) => {
                        panic!(
                            "The new key is identical to an existing one; this \
                             should never happen");
                    }
                    Ok(ImportStatus::Updated) => {
                        panic!(
                            "The new key collides with an existing one; this \
                             should never happen")
                    }
                    Err(err) => {
                        return Err(anyhow::anyhow!(
                            "Failed saving to the store: {}", err))
                    }
                }
            }
        }
    }

    // write out rev cert
    {
        let mut headers: Vec<_> = headers
            .iter()
            .map(|value| ("Comment", value.as_str()))
            .collect();
        headers.insert(0, ("Comment", "Revocation certificate for"));

        let w = rev_path.create_safe(config.force)?;
        let mut w = Writer::with_headers(w, Kind::PublicKey, headers)?;
        Packet::from(cert.primary_key().key().clone()).serialize(&mut w)?;
        Packet::Signature(rev).serialize(&mut w)?;
        w.finalize()?;
    }

    if on_keystore {
        // Writing to key store.  Provide some guidance.
        wprintln!("If this is your key, you should mark it as a fully \
                   trusted introducer:");
        println!();
        println!("  $ sq pki link add --ca \\* {} --all",
                 cert.fingerprint());
        println!();

        wprintln!("Otherwise, you should mark it as authenticated:");
        println!();
        println!("  $ sq pki link add {} --all",
                 cert.fingerprint());
        println!();

        wprintln!("You can export your certificate as follows:");
        println!();
        println!("  $ sq cert export --cert {}",
                 cert.fingerprint());
        println!();

        wprintln!("Once you are happy you can upload it to public directories \
                   using:");
        println!();
        println!("  $ sq network keyserver publish {}",
                 cert.fingerprint());
    }

    Ok(())
}
