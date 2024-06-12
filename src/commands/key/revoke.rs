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
use crate::cli::types::FileOrStdout;
use crate::common::get_secret_signer;
use crate::common::NULL_POLICY;
use crate::common::RevocationOutput;
use crate::parse_notations;

/// Handle the revocation of a certificate
struct CertificateRevocation {
    cert: Cert,
    revoker: Cert,
    revocation_packet: Packet,
}

impl CertificateRevocation {
    /// Create a new CertificateRevocation
    pub fn new(
        sq: &Sq,
        cert: Cert,
        revoker: Option<Cert>,
        reason: ReasonForRevocation,
        message: &str,
        notations: &[(bool, NotationData)],
    ) -> Result<Self> {
        let (revoker, mut signer) = get_secret_signer(
            sq,
            &cert,
            revoker.as_ref(),
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
            revoker,
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
        &self.revoker
    }
}

/// Revoke a certificate
pub fn certificate_revoke(
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
        sq.lookup_one_with_policy(&kh, None, true,
                                  NULL_POLICY, sq.time)?
    } else {
        panic!("clap enforces --cert or --cert-file");
    };

    let revoker = if let Some(file) = command.revoker_file {
        let br = file.open()?;
        Some(Cert::from_buffered_reader(br)?)
    } else if let Some(kh) = command.revoker {
        Some(sq.lookup_one_with_policy(&kh, None, true,
                                       NULL_POLICY, sq.time)?)
    } else {
        None
    };

    let notations = parse_notations(command.notation)?;

    let revocation = CertificateRevocation::new(
        &sq,
        cert,
        revoker,
        command.reason.into(),
        &command.message,
        &notations,
    )?;
    revocation.write(&sq, command.output, command.binary)?;

    Ok(())
}
