use std::fs::metadata;
use std::io;
use std::time::SystemTime;

use anyhow::anyhow;
use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::armor;
use openpgp::cert::amalgamation::ValidAmalgamation;
use openpgp::crypto;
use openpgp::policy::Policy;
use openpgp::serialize::stream::Compressor;
use openpgp::serialize::stream::Encryptor;
use openpgp::serialize::stream::LiteralWriter;
use openpgp::serialize::stream::Message;
use openpgp::serialize::stream::Recipient;
use openpgp::serialize::stream::Signer;
use openpgp::serialize::stream::padding::Padder;
use openpgp::types::CompressionAlgorithm;
use openpgp::types::KeyFlags;

use crate::Config;
use crate::Result;
use crate::common::prompt_for_password;
use crate::load_certs;
use crate::sq_cli;
use crate::sq_cli::types::FileOrStdin;
use crate::sq_cli::types::MetadataTime;

use crate::commands::CompressionMode;
use crate::commands::EncryptionMode;
use crate::commands::get_signing_keys;

pub fn dispatch(config: Config, command: sq_cli::encrypt::Command) -> Result<()> {
    tracer!(TRACE, "decrypt::dispatch");

    let mut recipients = load_certs(
        command.recipients_file.iter().map(|s| s.as_ref()))?;
    recipients.extend(
        config.lookup(command.recipients_cert,
                      Some(KeyFlags::empty()
                           .set_storage_encryption()
                           .set_transport_encryption()),
                      true,
                      false)
            .context("--recipient-cert")?);
    recipients.extend(
        config.lookup_by_userid(&command.recipients_email, true)
            .context("--recipient-email")?);
    recipients.extend(
        config.lookup_by_userid(&command.recipients_userid, false)
            .context("--recipient-userid")?);

    let output = command.output.create_pgp_safe(
        config.force,
        command.binary,
        armor::Kind::Message,
    )?;

    let additional_secrets =
        load_certs(command.signer_key_file.iter().map(|s| s.as_ref()))?;

    encrypt(
        &config.policy,
        command.private_key_store.as_deref(),
        command.input,
        output,
        command.symmetric as usize,
        &recipients,
        additional_secrets,
        command.mode,
        command.compression,
        Some(config.time),
        command.use_expired_subkey,
        command.set_metadata_filename,
        command.set_metadata_time
    )?;

    Ok(())
}

pub fn encrypt<'a, 'b: 'a>(
    policy: &'b dyn Policy,
    private_key_store: Option<&str>,
    input: FileOrStdin,
    message: Message<'a>,
    npasswords: usize,
    recipients: &'b [openpgp::Cert],
    signers: Vec<openpgp::Cert>,
    mode: EncryptionMode,
    compression: CompressionMode,
    time: Option<SystemTime>,
    use_expired_subkey: bool,
    set_metadata_filename: bool,
    set_metadata_time: MetadataTime,
)
    -> Result<()>
{
    let mut passwords: Vec<crypto::Password> = Vec::with_capacity(npasswords);
    for n in 0..npasswords {
        let nprompt = format!("Enter password {}: ", n + 1);
        if let Some(password) = prompt_for_password(
            if npasswords > 1 {
                &nprompt
            } else {
                "Enter password: "
            },
            Some("Repeat password: "),
        )? {
            passwords.push(password)
        } else {
            return Err(anyhow::anyhow!("Password can not be empty!"));
        }
    }

    if recipients.len() + passwords.len() == 0 {
        return Err(anyhow::anyhow!(
            "Neither recipient nor password given"));
    }

    let mode = match mode {
        EncryptionMode::Rest => {
            KeyFlags::empty().set_storage_encryption()
        }
        EncryptionMode::Transport => {
            KeyFlags::empty().set_transport_encryption()
        }
        EncryptionMode::All => KeyFlags::empty()
            .set_storage_encryption()
            .set_transport_encryption(),
    };

    let mut signers = get_signing_keys(
        &signers, policy, private_key_store, time, None)?;

    // Build a vector of recipients to hand to Encryptor.
    let mut recipient_subkeys: Vec<Recipient> = Vec::new();
    for cert in recipients.iter() {
        let mut count = 0;
        for key in cert.keys().with_policy(policy, time).alive().revoked(false)
            .key_flags(&mode).supported().map(|ka| ka.key())
        {
            recipient_subkeys.push(key.into());
            count += 1;
        }
        if count == 0 {
            let mut expired_keys = Vec::new();
            for ka in cert.keys().with_policy(policy, time).revoked(false)
                .key_flags(&mode).supported()
            {
                let key = ka.key();
                expired_keys.push(
                    (ka.binding_signature().key_expiration_time(key)
                         .expect("Key must have an expiration time"),
                     key));
            }
            expired_keys.sort_by_key(|(expiration_time, _)| *expiration_time);

            if let Some((expiration_time, key)) = expired_keys.last() {
                if use_expired_subkey {
                    recipient_subkeys.push((*key).into());
                } else {
                    use chrono::{DateTime, offset::Utc};
                    return Err(anyhow::anyhow!(
                        "The last suitable encryption key of cert {} expired \
                         on {}\n\
                         Hint: Use --use-expired-subkey to use it anyway.",
                        cert,
                        DateTime::<Utc>::from(*expiration_time)));
                }
            } else {
                return Err(anyhow::anyhow!(
                    "Cert {} has no suitable encryption key", cert));
            }
        }
    }

    // We want to encrypt a literal data packet.
    let encryptor =
        Encryptor::for_recipients(message, recipient_subkeys)
        .add_passwords(passwords);

    let mut sink = encryptor.build()
        .context("Failed to create encryptor")?;

    match compression {
        CompressionMode::None => (),
        CompressionMode::Pad => sink = Padder::new(sink).build()?,
        CompressionMode::Zip => sink =
            Compressor::new(sink).algo(CompressionAlgorithm::Zip).build()?,
        CompressionMode::Zlib => sink =
            Compressor::new(sink).algo(CompressionAlgorithm::Zlib).build()?,
        CompressionMode::Bzip2 => sink =
            Compressor::new(sink).algo(CompressionAlgorithm::BZip2).build()?,
    }

    // Optionally sign message.
    if ! signers.is_empty() {
        let mut signer = Signer::new(sink, signers.pop().unwrap().0);
        for s in signers {
            signer = signer.add_signer(s.0);
            if let Some(time) = time {
                signer = signer.creation_time(time);
            }
        }
        for r in recipients.iter() {
            signer = signer.add_intended_recipient(r);
        }
        sink = signer.build()?;
    }

    let mut literal_writer = LiteralWriter::new(sink);
    match set_metadata_time {
        MetadataTime::None => {}
        MetadataTime::FileCreation => {
            let metadata = metadata(
                input.inner()
                    .ok_or_else(|| {
                        anyhow!(
                            "Can not get metadata of file, when reading from stdin."
                        )
                    })?)?;
            literal_writer = literal_writer.date(SystemTime::from(metadata.created()?))?;
        }
        MetadataTime::FileModification => {
            let metadata = metadata(
                input.inner()
                    .ok_or_else(|| {
                        anyhow!(
                            "Can not get metadata of file, when reading from stdin."
                        )
                    })?)?;
            literal_writer = literal_writer.date(
                SystemTime::from(metadata.modified()?)
            )?;
        }
        MetadataTime::MessageCreation => {
            literal_writer = literal_writer.date(
                time.ok_or(anyhow!("Unable to get reference time"))?
            )?;
        }
        MetadataTime::Timestamp(time) => {
            literal_writer = literal_writer.date(SystemTime::from(time.time))?;
        }
    }

    if set_metadata_filename {
        literal_writer = literal_writer
            .filename(
                input
                    .inner()
                    .ok_or_else(|| {
                        anyhow!(
                            "Can not embed filename when reading from stdin."
                        )
                    })?
                    .as_path()
                    .file_name()
                    .ok_or_else(|| {
                        anyhow!("Failed to get filename from input.")
                    })?
                    .to_str()
                    .ok_or_else(|| {
                        anyhow!("Failed to convert filename to string.")
                    })?
                    .to_string(),
            )
            .context("Setting filename")?
    }

    let mut writer_stack = literal_writer
        .build()
        .context("Failed to create literal writer")?;

    // Finally, copy stdin to our writer stack to encrypt the data.
    io::copy(&mut input.open()?, &mut writer_stack)
        .context("Failed to encrypt")?;

    writer_stack.finalize().context("Failed to encrypt")?;

    Ok(())
}
