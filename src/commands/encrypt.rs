use std::io;
use std::time::SystemTime;

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
use crate::load_certs;
use crate::sq_cli;

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
    let mut input = command.input.open()?;

    let output = command.output.create_pgp_safe(
        config.force,
        command.binary,
        armor::Kind::Message,
    )?;

    let additional_secrets =
        load_certs(command.signer_key_file.iter().map(|s| s.as_ref()))?;

    let private_key_store = command.private_key_store.as_deref();
    encrypt(EncryptOpts {
        policy: &config.policy,
        private_key_store,
        input: &mut input,
        message: output,
        npasswords: command.symmetric as usize,
        recipients: &recipients,
        signers: additional_secrets,
        mode: command.mode,
        compression: command.compression,
        time: Some(config.time),
        use_expired_subkey: command.use_expired_subkey,
    })?;

    Ok(())
}

pub struct EncryptOpts<'a> {
    pub policy: &'a dyn Policy,
    pub private_key_store: Option<&'a str>,
    pub input: &'a mut dyn io::Read,
    pub message: Message<'a>,
    pub npasswords: usize,
    pub recipients: &'a [openpgp::Cert],
    pub signers: Vec<openpgp::Cert>,
    pub mode: EncryptionMode,
    pub compression: CompressionMode,
    pub time: Option<SystemTime>,
    pub use_expired_subkey: bool,
}

pub fn encrypt(opts: EncryptOpts) -> Result<()> {
    let mut passwords: Vec<crypto::Password> = Vec::with_capacity(opts.npasswords);
    for n in 0..opts.npasswords {
        let nprompt = format!("Enter password {}: ", n + 1);
        passwords.push(rpassword::prompt_password(
            if opts.npasswords > 1 {
                &nprompt
            } else {
                "Enter password: "
            })?.into());
    }

    if opts.recipients.len() + passwords.len() == 0 {
        return Err(anyhow::anyhow!(
            "Neither recipient nor password given"));
    }

    let mode = match opts.mode {
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
        &opts.signers, opts.policy, opts.private_key_store, opts.time, None)?;

    // Build a vector of recipients to hand to Encryptor.
    let mut recipient_subkeys: Vec<Recipient> = Vec::new();
    for cert in opts.recipients.iter() {
        let mut count = 0;
        for key in cert.keys().with_policy(opts.policy, opts.time).alive().revoked(false)
            .key_flags(&mode).supported().map(|ka| ka.key())
        {
            recipient_subkeys.push(key.into());
            count += 1;
        }
        if count == 0 {
            let mut expired_keys = Vec::new();
            for ka in cert.keys().with_policy(opts.policy, opts.time).revoked(false)
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
                if opts.use_expired_subkey {
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
        Encryptor::for_recipients(opts.message, recipient_subkeys)
        .add_passwords(passwords);

    let mut sink = encryptor.build()
        .context("Failed to create encryptor")?;

    match opts.compression {
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
            if let Some(time) = opts.time {
                signer = signer.creation_time(time);
            }
        }
        for r in opts.recipients.iter() {
            signer = signer.add_intended_recipient(r);
        }
        sink = signer.build()?;
    }

    let mut literal_writer = LiteralWriter::new(sink).build()
        .context("Failed to create literal writer")?;

    // Finally, copy stdin to our writer stack to encrypt the data.
    io::copy(opts.input, &mut literal_writer)
        .context("Failed to encrypt")?;

    literal_writer.finalize()
        .context("Failed to encrypt")?;

    Ok(())
}
