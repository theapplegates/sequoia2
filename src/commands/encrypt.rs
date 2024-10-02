use std::fs::metadata;
use std::io;
use std::path::PathBuf;
use std::time::SystemTime;

use anyhow::anyhow;
use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::armor;
use openpgp::cert::amalgamation::ValidAmalgamation;
use openpgp::crypto;
use openpgp::crypto::Password;
use openpgp::KeyHandle;
use openpgp::KeyID;
use openpgp::policy::Policy;
use openpgp::serialize::stream::Compressor;
use openpgp::serialize::stream::Encryptor2 as Encryptor;
use openpgp::serialize::stream::LiteralWriter;
use openpgp::serialize::stream::Message;
use openpgp::serialize::stream::Recipient;
use openpgp::serialize::stream::Signer;
#[cfg(all(unix, not(unix)))] // Bottom, but: `cfg` predicate key cannot be a literal
use openpgp::serialize::stream::padding::Padder;
use openpgp::types::CompressionAlgorithm;
use openpgp::types::KeyFlags;

use sequoia_keystore::Protection;

use crate::cli;
use crate::cli::types::EncryptPurpose;
use crate::cli::types::FileOrStdin;
use crate::cli::types::MetadataTime;
use crate::Sq;
use crate::Result;
use crate::common::password;
use crate::load_certs;
use crate::print_error_chain;

use crate::commands::CompressionMode;

pub fn dispatch(sq: Sq, command: cli::encrypt::Command) -> Result<()> {
    tracer!(TRACE, "decrypt::dispatch");

    let (recipients, errors) = sq.resolve_certs(
        &command.recipients,
        sequoia_wot::FULLY_TRUSTED)?;
    for error in errors.iter() {
        print_error_chain(error);
    }
    if ! errors.is_empty() {
        return Err(anyhow::anyhow!("Failed to resolve certificates"));
    }

    let output = command.output.create_pgp_safe(
        &sq,
        command.binary,
        armor::Kind::Message,
    )?;

    let additional_secrets =
        load_certs(command.signer_key_file.iter().map(|s| s.as_ref()))?;
    let signer_keys = &command.signer_key[..];

    encrypt(
        &sq,
        sq.policy,
        command.input,
        output,
        command.symmetric as usize,
        command.symmetric_password_file,
        &recipients,
        additional_secrets,
        signer_keys,
        command.mode,
        command.compression,
        Some(sq.time),
        command.use_expired_subkey,
        command.set_metadata_filename,
        command.set_metadata_time
    )?;

    Ok(())
}

pub fn encrypt<'a, 'b: 'a>(
    sq: &Sq,
    policy: &'b dyn Policy,
    input: FileOrStdin,
    message: Message<'a>,
    npasswords: usize,
    password_files: Vec<PathBuf>,
    recipients: &'b [openpgp::Cert],
    signers: Vec<openpgp::Cert>,
    signer_keys: &[KeyHandle],
    mode: EncryptPurpose,
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
        let nprompt;
        let password = password::prompt_for_new(
            sq,
            if npasswords > 1 {
                nprompt = format!("message (password {})", n + 1);
                &nprompt
            } else {
                "message"
            },
        )?;
        passwords.push(password);
    }

    for password_file in password_files {
        let password = std::fs::read(&password_file)
            .with_context(|| {
                format!("Reading {}", password_file.display())
            })?;
        passwords.push(password.into());
    }

    if recipients.len() + passwords.len() == 0 {
        return Err(anyhow::anyhow!(
            "Neither recipient nor password given"));
    }

    let mode = KeyFlags::from(mode);

    let mut signers = sq.get_signing_keys(&signers, None)?;

    let mut signer_keys = if signer_keys.is_empty() {
        Vec::new()
    } else {
        let mut ks = sq.key_store_or_else()?.lock().unwrap();

        signer_keys.into_iter()
            .map(|kh| {
                let keys = ks.find_key(kh.clone())?;

                match keys.len() {
                    0 => return Err(anyhow::anyhow!(
                        "{} is not present on keystore", kh)),
                    1 => (),
                    n => {
                        wprintln!("Warning: {} is present on multiple \
                                   ({}) devices",
                                  kh, n);
                    }
                }
                let mut key = keys.into_iter().next().expect("checked for one");

                match key.locked() {
                    Ok(Protection::Password(msg)) => {
                        let fpr = key.fingerprint();
                        let cert = sq.lookup_one(
                            &KeyHandle::from(&fpr), None, true);
                        let display = match cert {
                            Ok(cert) => {
                                format!(" ({})", sq.best_userid(&cert, true))
                            }
                            Err(_) => {
                                "".to_string()
                            }
                        };
                        let keyid = KeyID::from(&fpr);

                        if let Some(msg) = msg {
                            wprintln!("{}", msg);
                        }
                        loop {
                            let password = Password::from(rpassword::prompt_password(
                                format!("Enter password to unlock {}{}: ",
                                        keyid, display))?);
                            match key.unlock(password) {
                                Ok(()) => break,
                                Err(err) => {
                                    wprintln!("Unlocking {}: {}.", keyid, err);
                                }
                            }
                        }
                    }
                    Ok(Protection::Unlocked) => {
                        // Already unlocked, nothing to do.
                    }
                    Ok(Protection::UnknownProtection(msg))
                        | Ok(Protection::ExternalPassword(msg))
                        | Ok(Protection::ExternalTouch(msg))
                        | Ok(Protection::ExternalOther(msg)) =>
                    {
                        // Locked.
                        wprintln!("Key is locked{}",
                                  if let Some(msg) = msg {
                                      format!(": {}", msg)
                                  } else {
                                      "".into()
                                  });
                    }
                    Err(err) => {
                        // Failed to get the key's locked status.  Just print
                        // a warning now.  We'll (probably) fail more later.
                        wprintln!("Getting {}'s status: {}",
                                  key.keyid(), err);
                    }
                }

                Ok(key)
            })
        .collect::<Result<Vec<_>>>()?
    };

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
        #[cfg(all(unix, not(unix)))] // Bottom, but: `cfg` predicate key cannot be a literal
        CompressionMode::Pad => sink = Padder::new(sink).build()?,
        CompressionMode::Zip => sink =
            Compressor::new(sink).algo(CompressionAlgorithm::Zip).build()?,
        CompressionMode::Zlib => sink =
            Compressor::new(sink).algo(CompressionAlgorithm::Zlib).build()?,
        CompressionMode::Bzip2 => sink =
            Compressor::new(sink).algo(CompressionAlgorithm::BZip2).build()?,
    }

    // Optionally sign message.
    if ! signers.is_empty() || ! signer_keys.is_empty() {
        let mut signer = if ! signers.is_empty() {
            Signer::new(sink, signers.pop().unwrap())
        } else {
            Signer::new(sink, signer_keys.pop().unwrap())
        };
        if let Some(time) = time {
            signer = signer.creation_time(time);
        }
        for s in signers {
            signer = signer.add_signer(s);
        }
        for s in signer_keys {
            signer = signer.add_signer(s);
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
