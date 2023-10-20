use std::time::SystemTime;

use anyhow::Context;

use anyhow::anyhow;
use chrono::DateTime;
use chrono::Utc;

use sequoia_openpgp as openpgp;
use openpgp::armor::Kind;
use openpgp::armor::Writer;
use openpgp::cert::amalgamation::ValidAmalgamation;
use openpgp::cert::KeyBuilder;
use openpgp::cert::SubkeyRevocationBuilder;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::parse::Parse;
use openpgp::policy::Policy;
use openpgp::serialize::Serialize;
use openpgp::types::KeyFlags;
use openpgp::types::ReasonForRevocation;
use openpgp::Cert;
use openpgp::KeyHandle;
use openpgp::Packet;
use openpgp::Result;

use crate::Config;
use crate::cli::key::EncryptPurpose;
use crate::cli::key::SubkeyAddCommand;
use crate::cli::key::SubkeyCommand;
use crate::cli::key::SubkeyRevokeCommand;
use crate::cli::types::FileOrStdout;
use crate::commands::cert_stub;
use crate::commands::get_primary_keys;
use crate::common::NULL_POLICY;
use crate::common::RevocationOutput;
use crate::common::get_secret_signer;
use crate::common::prompt_for_password;
use crate::common::read_cert;
use crate::common::read_secret;
use crate::parse_notations;

/// Handle the revocation of a subkey
struct SubkeyRevocation<'a> {
    cert: Cert,
    secret: Cert,
    policy: &'a dyn Policy,
    time: Option<SystemTime>,
    revocation_packet: Packet,
    first_party_issuer: bool,
    subkey_packets: Vec<Packet>,
    subkey_as_hex: String,
}

impl<'a> SubkeyRevocation<'a> {
    /// Create a new SubkeyRevocation
    pub fn new(
        keyhandle: &KeyHandle,
        cert: Cert,
        secret: Option<Cert>,
        policy: &'a dyn Policy,
        time: Option<SystemTime>,
        private_key_store: Option<&str>,
        reason: ReasonForRevocation,
        message: &str,
        notations: &[(bool, NotationData)],
    ) -> Result<Self> {
        let (secret, mut signer) = get_secret_signer(
            &cert,
            policy,
            secret.as_ref(),
            private_key_store,
            time,
        )?;

        let first_party_issuer = secret.fingerprint() == cert.fingerprint();

        let mut subkey_packets = vec![];
        let mut subkey_as_hex = String::new();
        let mut subkey = None;

        let revocation_packet = {
            let valid_cert = cert.with_policy(NULL_POLICY, None)?;

            for key in valid_cert.keys().subkeys() {
                if keyhandle.aliases(KeyHandle::from(key.fingerprint())) {
                    subkey_packets.push(Packet::from(key.key().clone()));
                    subkey_packets
                        .push(Packet::from(key.binding_signature().clone()));
                    subkey_as_hex.push_str(&key.fingerprint().to_spaced_hex());
                    subkey = Some(key);
                    break;
                }
            }

            if let Some(ref subkey) = subkey {
                let mut rev = SubkeyRevocationBuilder::new()
                    .set_reason_for_revocation(reason, message.as_bytes())?;
                if let Some(time) = time {
                    rev = rev.set_signature_creation_time(time)?;
                }
                for (critical, notation) in notations {
                    rev = rev.add_notation(
                        notation.name(),
                        notation.value(),
                        Some(notation.flags().clone()),
                        *critical,
                    )?;
                }
                let rev = rev.build(&mut signer, &cert, subkey.key(), None)?;
                Packet::Signature(rev)
            } else {
                eprintln!(
                    "Subkey {} not found.\nValid subkeys:",
                    keyhandle.to_spaced_hex()
                );
                let mut have_valid = false;
                for k in valid_cert.keys().subkeys() {
                    have_valid = true;
                    eprintln!(
                        "  - {} {} [{:?}]",
                        k.fingerprint().to_hex(),
                        DateTime::<Utc>::from(k.creation_time()).date_naive(),
                        k.key_flags().unwrap_or_else(KeyFlags::empty)
                    );
                }
                if !have_valid {
                    eprintln!("  - Certificate has no subkeys.");
                }
                return Err(anyhow!(
                    "The certificate does not contain the specified subkey."
                ));
            }
        };

        Ok(SubkeyRevocation {
            cert,
            secret,
            policy,
            time,
            revocation_packet,
            first_party_issuer,
            subkey_packets,
            subkey_as_hex,
        })
    }
}

impl<'a> RevocationOutput for SubkeyRevocation<'a> {
    /// Write the revocation certificate to output
    fn write(
        &self,
        output: FileOrStdout,
        binary: bool,
        force: bool,
    ) -> Result<()> {
        let mut output = output.create_safe(force)?;

        let (stub, packets): (Cert, Vec<Packet>) = {
            let mut cert_stub = match cert_stub(
                self.cert.clone(),
                self.policy,
                self.time,
                None,
            ) {
                Ok(stub) => stub,
                // We failed to create a stub.  Just use the original
                // certificate as is.
                Err(_) => self.cert.clone(),
            };

            if !self.subkey_packets.is_empty() {
                cert_stub =
                    cert_stub.insert_packets(self.subkey_packets.clone())?;
            }

            (
                cert_stub.clone(),
                cert_stub
                    .insert_packets(self.revocation_packet.clone())?
                    .into_packets()
                    .collect(),
            )
        };

        if binary {
            for packet in packets {
                packet
                    .serialize(&mut output)
                    .context("serializing revocation certificate")?;
            }
        } else {
            // Add some more helpful ASCII-armor comments.
            let mut more: Vec<String> = vec![];

            // First, the thing that is being revoked.
            more.push(
                "including a revocation to revoke the subkey".to_string(),
            );
            more.push(self.subkey_as_hex.clone());

            if !self.first_party_issuer {
                // Then if it was issued by a third-party.
                more.push("issued by".to_string());
                more.push(self.secret.fingerprint().to_spaced_hex());
                if let Ok(valid_cert) =
                    &stub.with_policy(self.policy, self.time)
                {
                    if let Ok(uid) = valid_cert.primary_userid() {
                        let uid = String::from_utf8_lossy(uid.value());
                        // Truncate it, if it is too long.
                        more.push(format!(
                            "{:?}",
                            uid.chars().take(70).collect::<String>()
                        ));
                    }
                }
            }

            let headers = &stub.armor_headers();
            let headers: Vec<(&str, &str)> = headers
                .iter()
                .map(|s| ("Comment", s.as_str()))
                .chain(more.iter().map(|value| ("Comment", value.as_str())))
                .collect();

            let mut writer =
                Writer::with_headers(&mut output, Kind::PublicKey, headers)?;
            for packet in packets {
                packet
                    .serialize(&mut writer)
                    .context("serializing revocation certificate")?;
            }
            writer.finalize()?;
        }
        Ok(())
    }
}

pub fn subkey(config: Config, command: SubkeyCommand) -> Result<()> {
    match command {
        SubkeyCommand::Add(c) => subkey_add(config, c)?,
        SubkeyCommand::Revoke(c) => subkey_revoke(config, c)?,
    }

    Ok(())
}

/// Add a new Subkey for an existing primary key
///
/// Creates a subkey with features (e.g. `KeyFlags`, `CipherSuite`) based on
/// user input (or application-wide defaults if not specified).
/// If no specific expiry is requested, the subkey never expires.
fn subkey_add(
    config: Config,
    command: SubkeyAddCommand,
) -> Result<()> {
    let input = command.input.open()?;
    let cert = Cert::from_reader(input)?;
    let valid_cert = cert.with_policy(&config.policy, config.time)?;

    let validity = command
        .expiry
        .as_duration(DateTime::<Utc>::from(config.time))?;

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
        match get_primary_keys(
            &[cert.clone()],
            &config.policy,
            command.private_key_store.as_deref(),
            Some(config.time),
            None,
        ) {
            Ok(keys) => {
                assert!(
                    keys.len() == 1,
                    "Expect exactly one result from get_primary_keys()"
                );
                // provide a password or reuse that of the primary key
                if command.with_password {
                    (
                        keys.into_iter().next().unwrap().0,
                        prompt_for_password(
                            "Please enter password to encrypt the new subkey: ",
                            Some("Please repeat password to encrypt new subkey: "),
                        )?
                    )
                } else {
                    keys.into_iter().next().unwrap()
                }
            }
            Err(error) => {
                return Err(error)
            }
        };

    let new_cert = KeyBuilder::new(keyflags)
        .set_creation_time(config.time)
        .set_cipher_suite(command.cipher_suite.as_ciphersuite())
        .set_password(password)
        .subkey(valid_cert)?
        .set_key_validity_period(validity)?
        .set_primary_key_signer(primary_key)
        .attach_cert()?;

    let mut sink = command.output.create_safe(config.force)?;
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
    config: Config,
    command: SubkeyRevokeCommand,
) -> Result<()> {
    let cert = read_cert(command.input.as_deref())?;

    let secret = read_secret(command.secret_key_file.as_deref())?;

    let time = Some(config.time);

    let notations = parse_notations(command.notation)?;

    let keyhandle: KeyHandle = command.subkey.parse().context(format!(
        "Parsing {:?} as an OpenPGP fingerprint or Key ID",
        command.subkey
    ))?;

    let revocation = SubkeyRevocation::new(
        &keyhandle,
        cert,
        secret,
        &config.policy,
        time,
        command.private_key_store.as_deref(),
        command.reason.into(),
        &command.message,
        &notations,
    )?;
    revocation.write(command.output, command.binary, config.force)?;

    Ok(())
}
