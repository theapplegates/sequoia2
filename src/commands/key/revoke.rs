use std::time::SystemTime;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::armor::Kind;
use openpgp::armor::Writer;
use openpgp::cert::CertRevocationBuilder;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::policy::Policy;
use openpgp::serialize::Serialize;
use openpgp::types::ReasonForRevocation;
use openpgp::Cert;
use openpgp::Packet;
use openpgp::Result;

use crate::Config;
use crate::cli::key::RevokeCommand;
use crate::cli::types::FileOrStdout;
use crate::common::RevocationOutput;
use crate::common::get_secret_signer;
use crate::common::read_cert;
use crate::common::read_secret;
use crate::parse_notations;

/// Handle the revocation of a certificate
struct CertificateRevocation<'a> {
    cert: Cert,
    secret: Cert,
    policy: &'a dyn Policy,
    time: Option<SystemTime>,
    revocation_packet: Packet,
    first_party_issuer: bool,
}

impl<'a> CertificateRevocation<'a> {
    /// Create a new CertificateRevocation
    pub fn new(
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

        let revocation_packet = {
            // Create a revocation for the certificate.
            let mut rev = CertRevocationBuilder::new()
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
            let rev = rev.build(&mut signer, &cert, None)?;
            Packet::Signature(rev)
        };

        Ok(CertificateRevocation {
            cert,
            secret,
            policy,
            time,
            revocation_packet,
            first_party_issuer,
        })
    }
}

impl<'a> RevocationOutput for CertificateRevocation<'a> {
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
            self.revocation_packet.clone(),
        ].into_iter())?;

        if binary {
            rev_cert.serialize(&mut output)
                .context("serializing revocation certificate")?;
        } else {
            // Add some more helpful ASCII-armor comments.
            let mut more: Vec<String> = vec![];

            // First, the thing that is being revoked.
            more.push("including a revocation for the certificate".to_string());

            if !self.first_party_issuer {
                // Then if it was issued by a third-party.
                more.push("issued by".to_string());
                more.push(self.secret.fingerprint().to_spaced_hex());
                // This information may be published so only consider
                // self-signed user IDs to avoid leaking information
                // about the user's web of trust.
                let sanitized_uid = crate::best_effort_primary_uid(
                    None, &self.secret, self.policy, self.time);
                // Truncate it, if it is too long.
                more.push(sanitized_uid.chars().take(70).collect::<String>());
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

/// Revoke a certificate
pub fn certificate_revoke(
    config: Config,
    command: RevokeCommand,
) -> Result<()> {
    let cert = read_cert(command.input.as_deref())?;

    let secret = read_secret(command.secret_key_file.as_deref())?;

    let time = Some(config.time);

    let notations = parse_notations(command.notation)?;

    let revocation = CertificateRevocation::new(
        cert,
        secret,
        config.policy,
        time,
        command.private_key_store.as_deref(),
        command.reason.into(),
        &command.message,
        &notations,
    )?;
    revocation.write(command.output, command.binary, config.force)?;

    Ok(())
}
