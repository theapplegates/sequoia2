use std::collections::BTreeSet;

use anyhow::Context;

use chrono::DateTime;
use chrono::Utc;

use sequoia_openpgp as openpgp;
use openpgp::cert::KeyBuilder;
use openpgp::cert::SubkeyRevocationBuilder;
use openpgp::packet::{Key, Signature, key};
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::parse::Parse;
use openpgp::serialize::Serialize;
use openpgp::types::KeyFlags;
use openpgp::types::ReasonForRevocation;
use openpgp::Cert;
use openpgp::KeyHandle;
use openpgp::Packet;
use openpgp::Result;

use crate::Sq;
use crate::cli::key::subkey::AddCommand;
use crate::cli::key::subkey::Command;
use crate::cli::key::subkey::DeleteCommand;
use crate::cli::key::subkey::ExpireCommand;
use crate::cli::key::subkey::ExportCommand;
use crate::cli::key::subkey::PasswordCommand;
use crate::cli::key::subkey::RevokeCommand;
use crate::cli::types::EncryptPurpose;
use crate::cli::types::FileOrStdout;
use crate::commands::key::adopt;
use crate::common;
use crate::common::key::expire;
use crate::common::key::export;
use crate::common::key::delete;
use crate::common::key::password;
use crate::common::NULL_POLICY;
use crate::common::RevocationOutput;
use crate::common::get_secret_signer;
use crate::parse_notations;

pub fn dispatch(sq: Sq, command: Command) -> Result<()> {
    match command {
        Command::Add(c) => subkey_add(sq, c)?,
        Command::Export(c) => subkey_export(sq, c)?,
        Command::Delete(c) => subkey_delete(sq, c)?,
        Command::Password(c) => subkey_password(sq, c)?,
        Command::Expire(c) => subkey_expire(sq, c)?,
        Command::Revoke(c) => subkey_revoke(sq, c)?,
        Command::Adopt(c) => adopt::adopt(sq, c)?,
    }

    Ok(())
}

fn subkey_export(sq: Sq, command: ExportCommand)
    -> Result<()>
{
    assert!(! command.key.is_empty());

    export(sq, vec![], command.key)
}

fn subkey_delete(sq: Sq, command: DeleteCommand)
    -> Result<()>
{
    let handle = if let Some(file) = command.cert_file {
        assert!(command.cert.is_none());
        file.into()
    } else if let Some(kh) = command.cert {
        kh.into()
    } else {
        panic!("clap enforces --cert or --cert-file is set");
    };

    assert!(! command.key.is_empty());

    delete(sq, handle, command.key, command.output, command.binary)
}

fn subkey_password(sq: Sq, command: PasswordCommand)
    -> Result<()>
{
    let handle = if let Some(file) = command.cert_file {
        assert!(command.cert.is_none());
        file.into()
    } else if let Some(kh) = command.cert {
        kh.into()
    } else {
        panic!("clap enforces --cert or --cert-file is set");
    };

    assert!(! command.key.is_empty());

    password(sq, handle, command.key,
             command.clear_password, command.new_password_file.as_deref(),
             command.output, command.binary)
}

fn subkey_expire(sq: Sq, command: ExpireCommand)
    -> Result<()>
{
    let handle = if let Some(file) = command.cert_file {
        assert!(command.cert.is_none());
        file.into()
    } else if let Some(kh) = command.cert {
        kh.into()
    } else {
        panic!("clap enforces --cert or --cert-file is set");
    };

    assert!(! command.key.is_empty());

    expire(sq, handle, &command.key[..], command.expiration,
           command.output, command.binary)
}

/// Handle the revocation of a subkey
struct SubkeyRevocation {
    cert: Cert,
    revoker: Cert,
    revocations: Vec<(Key<key::PublicParts, key::SubordinateRole>, Signature)>,
}

impl SubkeyRevocation {
    /// Create a new SubkeyRevocation
    pub fn new(
        sq: &Sq,
        keyhandles: &[KeyHandle],
        cert: Cert,
        revoker: Option<Cert>,
        reason: ReasonForRevocation,
        message: &str,
        notations: &[(bool, NotationData)],
    ) -> Result<Self> {
        let valid_cert = cert.with_policy(NULL_POLICY, None)?;
        let (revoker, mut signer)
            = get_secret_signer(sq, &cert, revoker.as_ref())?;

        let mut revocations = Vec::new();
        let mut revoked = BTreeSet::new();
        for keyhandle in keyhandles {
            let keys = valid_cert.keys().subkeys()
                .key_handle(keyhandle.clone())
                .map(|skb| skb.key().clone())
                .collect::<Vec<_>>();

            if keys.len() == 1 {
                let subkey = keys[0].clone();

                // Did we already revoke it?
                if revoked.contains(&subkey.fingerprint()) {
                    continue;
                }
                revoked.insert(subkey.fingerprint());

                let mut rev = SubkeyRevocationBuilder::new()
                    .set_reason_for_revocation(reason, message.as_bytes())?;
                rev = rev.set_signature_creation_time(sq.time)?;
                for (critical, notation) in notations {
                    rev = rev.add_notation(
                        notation.name(),
                        notation.value(),
                        Some(notation.flags().clone()),
                        *critical,
                    )?;
                }
                let rev = rev.build(&mut signer, &cert, &subkey, None)?;
                revocations.push((subkey, rev));
            } else if keys.len() > 1 {
                wprintln!("Key ID {} does not uniquely identify a subkey, \
                           please use a fingerprint instead.\nValid subkeys:",
                          keyhandle);
                for k in keys {
                    wprintln!(
                        "  - {} {}",
                        k.fingerprint(),
                        DateTime::<Utc>::from(k.creation_time()).date_naive()
                    );
                }
                return Err(anyhow::anyhow!(
                    "Subkey is ambiguous."
                ));
            } else {
                wprintln!(
                    "Subkey {} not found.\nValid subkeys:",
                    keyhandle
                );
                let mut have_valid = false;
                for k in valid_cert.keys().subkeys() {
                    have_valid = true;
                    wprintln!(
                        "  - {} {} [{:?}]",
                        k.fingerprint().to_hex(),
                        DateTime::<Utc>::from(k.creation_time()).date_naive(),
                        k.key_flags().unwrap_or_else(KeyFlags::empty)
                    );
                }
                if !have_valid {
                    wprintln!("  - Certificate has no subkeys.");
                }
                return Err(anyhow::anyhow!(
                    "The certificate does not contain the specified subkey."
                ));
            }
        };

        Ok(SubkeyRevocation {
            cert,
            revoker,
            revocations,
        })
    }
}

impl RevocationOutput for SubkeyRevocation {
    fn cert(&self) -> Result<Cert> {
         Cert::from_packets(
            std::iter::once(
                Packet::from(self.cert.primary_key().key().clone()))
                .chain(self.revocations.iter().flat_map(
                    |(k, s)| [k.clone().into(), s.clone().into()].into_iter()))
        )
    }

    fn comment(&self) -> String {
        if self.revocations.len() == 1 {
            format!("This is a revocation certificate for \
                     the subkey {} of cert {}.",
                    self.revocations[0].0.fingerprint(),
                    self.cert.fingerprint())
        } else {
            let fingerprints: Vec<_> = self.revocations.iter()
                .map(|k| k.0.fingerprint().to_string()).collect();
            format!("This is a revocation certificate for \
                     the subkeys {} of cert {}.",
                    fingerprints.join(", "),
                    self.cert.fingerprint())
        }
    }

    fn revoker(&self) -> &Cert {
        &self.revoker
    }
}

/// Add a new Subkey for an existing primary key
///
/// Creates a subkey with features (e.g. `KeyFlags`, `CipherSuite`) based on
/// user input (or application-wide defaults if not specified).
/// If no specific expiry is requested, the subkey never expires.
fn subkey_add(
    sq: Sq,
    mut command: AddCommand,
) -> Result<()> {
    let cert = if let Some(file) = command.cert_file {
        if command.output.is_none() {
            // None means to write to the cert store.  When reading
            // from a file, we want to write to stdout by default.
            command.output = Some(FileOrStdout::new(None));
        }

        let br = file.open()?;
        Cert::from_buffered_reader(br)?
    } else if let Some(kh) = command.cert {
        sq.lookup_one(&kh, None, true)?
    } else {
        panic!("clap enforces --cert or --cert-file");
    };

    let valid_cert = cert.with_policy(sq.policy, sq.time)?;

    let validity = command
        .expiration
        .as_duration(DateTime::<Utc>::from(sq.time))?;

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

    // If a password is needed to use the key, the user will be prompted.
    let (primary_key, password) =
        match sq.get_primary_key(&cert, None) {
            Ok(key) => {
                // Don't use a password, or prompt for one.
                if let Some(password_file) = command.new_password_file {
                    let password = std::fs::read(&password_file)
                        .with_context(|| {
                            format!("Reading {}", password_file.display())
                        })?;
                    (key, Some(password.into()))
                } else if command.without_password {
                    (key, None)
                } else {
                    (key, common::password::prompt_for_new_or_none(
                        &sq, "subkey")?)
                }
            }
            Err(error) => {
                return Err(error)
            }
        };

    let new_cert = KeyBuilder::new(keyflags)
        .set_creation_time(sq.time)
        .set_cipher_suite(command.cipher_suite.as_ciphersuite())
        .set_password(password)
        .subkey(valid_cert)?
        .set_key_validity_period(validity)?
        .set_primary_key_signer(primary_key)
        .attach_cert()?;

    if let Some(output) = command.output {
        let mut sink = output.for_secrets().create_safe(sq.force)?;
        if command.binary {
            new_cert.as_tsk().serialize(&mut sink)?;
        } else {
            new_cert.as_tsk().armored().serialize(&mut sink)?;
        }
    } else {
        sq.import_key(new_cert)?;
    }

    Ok(())
}

/// Revoke a Subkey of an existing primary key
///
/// ## Errors
///
/// Returns an error if parsing of the [`KeyHandle`] fails, if reading of the
/// [`Cert`] fails, if retrieval of [`NotationData`] fails or if the eventual
/// revocation fails.
pub fn subkey_revoke(
    sq: Sq,
    mut command: RevokeCommand,
) -> Result<()> {
    let cert = if let Some(file) = command.cert_file {
        if command.output.is_none() {
            // None means to write to the cert store.  When reading
            // from a file, we want to write to stdout by default.
            command.output = Some(FileOrStdout::new(None));
        }

        let br = file.open()?;
        Cert::from_buffered_reader(br)?
    } else if let Some(kh) = command.cert {
        sq.lookup_one(&kh, None, true)?
    } else {
        panic!("clap enforces --cert or --cert-file");
    };

    let revoker = if let Some(file) = command.revoker_file {
        let br = file.open()?;
        Some(Cert::from_buffered_reader(br)?)
    } else if let Some(kh) = command.revoker {
        Some(sq.lookup_one(&kh, None, true)?)
    } else {
        None
    };

    let notations = parse_notations(command.notation)?;

    let revocation = SubkeyRevocation::new(
        &sq,
        &command.keys,
        cert,
        revoker,
        command.reason.into(),
        &command.message,
        &notations,
    )?;
    revocation.write(&sq, command.output, command.binary)?;

    Ok(())
}
