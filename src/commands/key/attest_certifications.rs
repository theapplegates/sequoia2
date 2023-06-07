use openpgp::Cert;
use openpgp::Result;
use openpgp::parse::Parse;
use openpgp::serialize::Serialize;
use sequoia_openpgp as openpgp;

use crate::decrypt_key;
use crate::sq_cli;
use crate::Config;

pub fn attest_certifications(
    config: Config,
    command: sq_cli::key::AttestCertificationsCommand,
) -> Result<()> {
    // Attest to all certifications?
    let all = !command.none; // All is the default.

    let input = command.key.open()?;
    let key = Cert::from_reader(input)?;

    // Get a signer.
    let mut passwords = Vec::new();
    let pk = key.primary_key().key();
    let mut pk_signer =
        decrypt_key(pk.clone().parts_into_secret()?, &mut passwords)?
            .into_keypair()?;

    // Now, create new attestation signatures.
    let mut attestation_signatures = Vec::new();
    for uid in key.userids() {
        if all {
            attestation_signatures.append(&mut uid.attest_certifications(
                &config.policy,
                &mut pk_signer,
                uid.certifications(),
            )?);
        } else {
            attestation_signatures.append(&mut uid.attest_certifications(
                &config.policy,
                &mut pk_signer,
                &[],
            )?);
        }
    }

    for ua in key.user_attributes() {
        if all {
            attestation_signatures.append(&mut ua.attest_certifications(
                &config.policy,
                &mut pk_signer,
                ua.certifications(),
            )?);
        } else {
            attestation_signatures.append(&mut ua.attest_certifications(
                &config.policy,
                &mut pk_signer,
                &[],
            )?);
        }
    }

    // Finally, add the new signatures.
    let key = key.insert_packets(attestation_signatures)?;

    let mut sink = command.output.create_safe(config.force)?;
    if command.binary {
        key.as_tsk().serialize(&mut sink)?;
    } else {
        key.as_tsk().armored().serialize(&mut sink)?;
    }

    Ok(())
}
