use std::collections::BTreeSet;

use chrono::DateTime;
use chrono::Utc;

use sequoia_openpgp as openpgp;
use openpgp::cert::SubkeyRevocationBuilder;
use openpgp::packet::{Key, Signature, key};
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::types::KeyFlags;
use openpgp::types::ReasonForRevocation;
use openpgp::Cert;
use openpgp::KeyHandle;
use openpgp::Packet;
use openpgp::Result;

use crate::Sq;
use crate::cli::key::subkey::Command;
use crate::cli::key::subkey::revoke::Command as RevokeCommand;
use crate::commands::key::bind;
use crate::common::NULL_POLICY;
use crate::common::RevocationOutput;
use crate::common::get_secret_signer;
use crate::parse_notations;

mod add;
mod delete;
mod expire;
mod export;
mod password;

pub fn dispatch(sq: Sq, command: Command) -> Result<()> {
    match command {
        Command::Add(c) => add::dispatch(sq, c)?,
        Command::Export(c) => export::dispatch(sq, c)?,
        Command::Delete(c) => delete::dispatch(sq, c)?,
        Command::Password(c) => password::dispatch(sq, c)?,
        Command::Expire(c) => expire::dispatch(sq, c)?,
        Command::Revoke(c) => subkey_revoke(sq, c)?,
        Command::Bind(c) => bind::bind(sq, c)?,
    }

    Ok(())
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

/// Revoke a Subkey of an existing primary key
///
/// ## Errors
///
/// Returns an error if parsing of the [`KeyHandle`] fails, if reading of the
/// [`Cert`] fails, if retrieval of [`NotationData`] fails or if the eventual
/// revocation fails.
pub fn subkey_revoke(
    sq: Sq,
    command: RevokeCommand,
) -> Result<()> {
    let cert =
        sq.resolve_cert_with_policy(&command.cert,
                                    sequoia_wot::FULLY_TRUSTED,
                                    NULL_POLICY,
                                    sq.time)?.0;

    let revoker = if command.revoker.is_empty() {
        None
    } else {
        Some(sq.resolve_cert(&command.revoker, sequoia_wot::FULLY_TRUSTED)?.0)
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
