use anyhow::Context;

use anyhow::anyhow;
use chrono::DateTime;
use chrono::Utc;

use sequoia_openpgp as openpgp;
use openpgp::armor::Kind;
use openpgp::armor::Writer;
use openpgp::cert::KeyBuilder;
use openpgp::cert::SubkeyRevocationBuilder;
use openpgp::packet::{Key, key};
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
use crate::cli::key::SubkeyAddCommand;
use crate::cli::key::SubkeyCommand;
use crate::cli::key::SubkeyRevokeCommand;
use crate::cli::types::EncryptPurpose;
use crate::cli::types::FileOrStdout;
use crate::cli::types::FileOrStdin;
use crate::common;
use crate::common::NULL_POLICY;
use crate::common::RevocationOutput;
use crate::common::get_secret_signer;
use crate::load_certs;
use crate::parse_notations;

/// Handle the revocation of a subkey
struct SubkeyRevocation<'a, 'store, 'rstore> {
    cert: Cert,
    secret: Cert,
    sq: &'a Sq<'store, 'rstore>,
    revocation_packet: Packet,
    first_party_issuer: bool,
    subkey: Key<key::PublicParts, key::SubordinateRole>,
}

impl<'a, 'store, 'rstore> SubkeyRevocation<'a, 'store, 'rstore> {
    /// Create a new SubkeyRevocation
    pub fn new(
        sq: &'a Sq<'store, 'rstore>,
        keyhandle: &KeyHandle,
        cert: Cert,
        secret: Option<Cert>,
        reason: ReasonForRevocation,
        message: &str,
        notations: &[(bool, NotationData)],
    ) -> Result<Self> {
        let (secret, mut signer)
            = get_secret_signer(sq, &cert, secret.as_ref())?;

        let first_party_issuer = secret.fingerprint() == cert.fingerprint();

        let (subkey, revocation_packet) = {
            let valid_cert = cert.with_policy(NULL_POLICY, None)?;

            let keys = valid_cert.keys().subkeys()
                .key_handle(keyhandle.clone())
                .map(|skb| skb.key().clone())
                .collect::<Vec<_>>();

            if keys.len() == 1 {
                let subkey = keys[0].clone();
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
                (subkey.into(), Packet::Signature(rev))
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
                return Err(anyhow!(
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
                return Err(anyhow!(
                    "The certificate does not contain the specified subkey."
                ));
            }
        };

        Ok(SubkeyRevocation {
            cert,
            secret,
            sq,
            revocation_packet,
            first_party_issuer,
            subkey,
        })
    }
}

impl<'a, 'store, 'rstore> RevocationOutput for SubkeyRevocation<'a, 'store, 'rstore> {
    /// Write the revocation certificate to output
    fn write(
        &self,
        output: FileOrStdout,
        binary: bool,
        force: bool,
    ) -> Result<()> {
        let mut output = output.create_safe(force)?;

        // First, build a minimal revocation certificate containing
        // the primary key, the revoked component, and the revocation
        // signature.
        let rev_cert = Cert::from_packets(vec![
            self.cert.primary_key().key().clone().into(),
            self.subkey.clone().into(),
            self.revocation_packet.clone(),
        ].into_iter())?;

        if binary {
            rev_cert.serialize(&mut output)
                .context("serializing revocation certificate")?;
        } else {
            // Add some more helpful ASCII-armor comments.
            let mut more: Vec<String> = vec![];

            // First, the thing that is being revoked.
            more.push(
                "including a revocation to revoke the subkey".to_string(),
            );
            more.push(self.subkey.fingerprint().to_spaced_hex());

            if !self.first_party_issuer {
                // Then if it was issued by a third-party.
                more.push("issued by".to_string());
                more.push(self.secret.fingerprint().to_spaced_hex());
                // This information may be published, so only consider
                // self-signed user IDs to avoid leaking information
                // about the user's web of trust.
                let sanitized_uid = self.sq.best_userid(&self.secret, false);
                // Truncate it, if it is too long.
                more.push(format!("{:.70}", sanitized_uid));
            }

            let headers = &self.cert.armor_headers();
            let headers: Vec<(&str, &str)> = headers
                .iter()
                .map(|s| ("Comment", s.as_str()))
                .chain(more.iter().map(|value| ("Comment", value.as_str())))
                .collect();

            let mut writer =
                Writer::with_headers(&mut output, Kind::PublicKey, headers)?;
            rev_cert.serialize(&mut writer)
                .context("serializing revocation certificate")?;
            writer.finalize()?;
        }
        Ok(())
    }
}

pub fn dispatch(sq: Sq, command: SubkeyCommand) -> Result<()> {
    match command {
        SubkeyCommand::Add(c) => subkey_add(sq, c)?,
        SubkeyCommand::Revoke(c) => subkey_revoke(sq, c)?,
    }

    Ok(())
}

/// Add a new Subkey for an existing primary key
///
/// Creates a subkey with features (e.g. `KeyFlags`, `CipherSuite`) based on
/// user input (or application-wide defaults if not specified).
/// If no specific expiry is requested, the subkey never expires.
fn subkey_add(
    sq: Sq,
    command: SubkeyAddCommand,
) -> Result<()> {
    let input = command.input.open()?;
    let cert = Cert::from_buffered_reader(input)?;
    let valid_cert = cert.with_policy(sq.policy, sq.time)?;

    let validity = command
        .expiry
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
            Ok((key, password)) => {
                // provide a password or reuse that of the primary key
                if command.with_password {
                    (
                        key,
                        common::password::prompt_for_new("subkey")?,
                    )
                } else {
                    (key, password)
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

    let mut sink = command.output.for_secrets().create_safe(sq.force)?;
    if command.binary {
        new_cert.as_tsk().serialize(&mut sink)?;
    } else {
        new_cert.as_tsk().armored().serialize(&mut sink)?;
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
    command: SubkeyRevokeCommand,
) -> Result<()> {
    let br = FileOrStdin::from(command.input.as_deref()).open()?;
    let cert = Cert::from_buffered_reader(br)?;

    let secret = if let Some(file) = command.secret_key_file.as_deref() {
        let certs = load_certs(std::iter::once(file))?;
        if certs.len() > 1 {
            return Err(anyhow::anyhow!(
                format!("{} contains multiple certificates.",
                        file.display())))?;
        }
        certs.into_iter().next()
    } else {
        None
    };

    let notations = parse_notations(command.notation)?;

    let revocation = SubkeyRevocation::new(
        &sq,
        &command.subkey,
        cert,
        secret,
        command.reason.into(),
        &command.message,
        &notations,
    )?;
    revocation.write(command.output, command.binary, sq.force)?;

    Ok(())
}
