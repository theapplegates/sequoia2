use std::io;
use std::path::PathBuf;
use std::time::SystemTime;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::armor;
use openpgp::cert::amalgamation::ValidAmalgamation;
use openpgp::crypto;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::packet::signature::subpacket::NotationData;
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
use openpgp::types::SignatureType;

use crate::cli;
use crate::cli::types::EncryptPurpose;
use crate::cli::types::FileOrStdin;
use crate::Sq;
use crate::Result;
use crate::common::password;
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

    let signers =
        sq.resolve_certs_or_fail(&command.signers,
                                 sequoia_wot::FULLY_TRUSTED)?;
    let signers = sq.get_signing_keys(&signers, None)?;

    let notations =
        crate::parse_notations(command.signature_notations)?;

    if signers.is_empty() && ! notations.is_empty() {
        return Err(anyhow::anyhow!("--signature-notation requires signers, \
                                    but none are given"));
    }

    encrypt(
        &sq,
        sq.policy,
        command.input,
        output,
        command.recipients.with_passwords(),
        command.recipients.with_password_files(),
        &recipients,
        signers,
        notations,
        command.mode,
        command.compression,
        Some(sq.time),
        command.use_expired_subkey,
        command.set_metadata_filename,
    )?;

    Ok(())
}

pub fn encrypt<'a, 'b: 'a>(
    sq: &Sq,
    policy: &'b dyn Policy,
    input: FileOrStdin,
    message: Message<'a>,
    npasswords: usize,
    password_files: &[PathBuf],
    recipients: &'b [openpgp::Cert],
    mut signers: Vec<Box<dyn crypto::Signer + Send + Sync>>,
    notations: Vec<(bool, NotationData)>,
    mode: EncryptPurpose,
    compression: CompressionMode,
    time: Option<SystemTime>,
    use_expired_subkey: bool,
    set_metadata_filename: Option<String>,
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
    if let Some(first) = signers.pop() {
        // Create a signature template.
        let mut builder = SignatureBuilder::new(SignatureType::Binary);
        for (critical, n) in notations.iter() {
            builder = builder.add_notation(
                n.name(),
                n.value(),
                Some(n.flags().clone()),
                *critical)?;
        }

        let mut signer = Signer::with_template(sink, first, builder);

        if let Some(time) = time {
            signer = signer.creation_time(time);
        }
        for s in signers {
            signer = signer.add_signer(s);
        }
        for r in recipients.iter() {
            signer = signer.add_intended_recipient(r);
        }
        sink = signer.build()?;
    }

    let literal_writer = LiteralWriter::new(sink)
        .filename(set_metadata_filename.unwrap_or_default())?;

    let mut writer_stack = literal_writer
        .build()
        .context("Failed to create literal writer")?;

    // Finally, copy stdin to our writer stack to encrypt the data.
    io::copy(&mut input.open("data to encrypt")?, &mut writer_stack)
        .context("Failed to encrypt")?;

    writer_stack.finalize().context("Failed to encrypt")?;

    Ok(())
}
