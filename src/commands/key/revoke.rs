use sequoia_openpgp as openpgp;
use openpgp::cert::CertRevocationBuilder;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::parse::Parse;
use openpgp::types::ReasonForRevocation;
use openpgp::Cert;
use openpgp::Packet;
use openpgp::Result;

use crate::Sq;
use crate::cli::key::RevokeCommand;
use crate::cli::types::FileOrStdin;
use crate::common::RevocationOutput;
use crate::common::get_secret_signer;
use crate::load_certs;
use crate::parse_notations;

/// Handle the revocation of a certificate
struct CertificateRevocation {
    cert: Cert,
    secret: Cert,
    revocation_packet: Packet,
}

impl CertificateRevocation {
    /// Create a new CertificateRevocation
    pub fn new(
        sq: &Sq,
        cert: Cert,
        secret: Option<Cert>,
        reason: ReasonForRevocation,
        message: &str,
        notations: &[(bool, NotationData)],
    ) -> Result<Self> {
        let (secret, mut signer) = get_secret_signer(
            sq,
            &cert,
            secret.as_ref(),
        )?;

        let revocation_packet = {
            // Create a revocation for the certificate.
            let mut rev = CertRevocationBuilder::new()
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
            let rev = rev.build(&mut signer, &cert, None)?;
            Packet::Signature(rev)
        };

        Ok(CertificateRevocation {
            cert,
            secret,
            revocation_packet,
        })
    }
}

impl RevocationOutput for CertificateRevocation
{
    fn cert(&self) -> Result<Cert> {
        let cert = Cert::from_packets(vec![
            self.cert.primary_key().key().clone().into(),
            self.revocation_packet.clone(),
        ].into_iter())?;

        Ok(cert)
    }

    fn comment(&self) -> String {
        "Includes a revocation certificate for the certificate"
            .to_string()
    }

    fn revoker(&self) -> &Cert {
        &self.secret
    }
}

/// Revoke a certificate
pub fn certificate_revoke(
    sq: Sq,
    command: RevokeCommand,
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

    let revocation = CertificateRevocation::new(
        &sq,
        cert,
        secret,
        command.reason.into(),
        &command.message,
        &notations,
    )?;
    revocation.write(&sq, command.output, command.binary)?;

    Ok(())
}
