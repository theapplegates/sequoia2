use openpgp::Result;
use openpgp::serialize::Serialize;
use sequoia_openpgp as openpgp;

use crate::Sq;
use crate::cli;
use crate::cli::key::approvals;
use crate::cli::types::FileStdinOrKeyHandle;
use crate::cli::types::FileOrStdout;

pub fn dispatch(sq: Sq, command: approvals::Command)
                -> Result<()>
{
    match command {
        approvals::Command::Update(c) => update(sq, c),
    }
}

fn update(
    sq: Sq,
    mut command: cli::key::approvals::UpdateCommand,
) -> Result<()> {
    // Attest to all certifications?
    let all = !command.none; // All is the default.

    let handle: FileStdinOrKeyHandle = if let Some(file) = command.cert_file {
        assert!(command.cert.is_none());

        if command.output.is_none() {
            // None means to write to the cert store.  When reading
            // from a file, we want to write to stdout by default.
            command.output = Some(FileOrStdout::new(None));
        }

        file.into()
    } else if let Some(kh) = command.cert {
        kh.into()
    } else {
        panic!("clap enforces --cert or --cert-file is set");
    };
    let key = sq.lookup_one(handle, None, true)?;

    // Get a signer.
    let mut pk_signer = sq.get_primary_key(&key, None)?.0;

    // Now, create new attestation signatures.
    let mut attestation_signatures = Vec::new();
    for uid in key.userids() {
        if all {
            attestation_signatures.append(&mut uid.attest_certifications2(
                sq.policy,
                sq.time,
                &mut pk_signer,
                uid.certifications(),
            )?);
        } else {
            attestation_signatures.append(&mut uid.attest_certifications2(
                sq.policy,
                sq.time,
                &mut pk_signer,
                &[],
            )?);
        }
    }

    for ua in key.user_attributes() {
        if all {
            attestation_signatures.append(&mut ua.attest_certifications2(
                sq.policy,
                sq.time,
                &mut pk_signer,
                ua.certifications(),
            )?);
        } else {
            attestation_signatures.append(&mut ua.attest_certifications2(
                sq.policy,
                sq.time,
                &mut pk_signer,
                &[],
            )?);
        }
    }

    // Finally, add the new signatures.
    let key = key.insert_packets(attestation_signatures)?;

    if let Some(sink) = command.output {
        let path = sink.path().map(Clone::clone);
        let mut output = sink.for_secrets().create_safe(sq.force)?;
        if command.binary {
            key.as_tsk().serialize(&mut output)?;
        } else {
            key.as_tsk().armored().serialize(&mut output)?;
        }

        if let Some(path) = path {
            sq.hint(format_args!(
                "Updated key written to {}.  \
                 To make the update effective, it has to be published \
                 so that others can find it, for example using:",
                path.display()))
                .command(format_args!(
                    "sq network keyserver publish {}",
                    path.display()));
        } else {
            sq.hint(format_args!(
                "To make the update effective, it has to be published \
                 so that others can find it."));
        }
    } else {
        let keyid = key.keyid();
        if let Err(err) = sq.import_cert(key) {
            wprintln!("Error importing updated cert: {}", err);
            return Err(err);
        } else {
            sq.hint(format_args!(
                "Imported updated cert into the cert store.  \
                 To make the update effective, it has to be published \
                 so that others can find it, for example using:"))
                .command(format_args!(
                    "sq network keyserver publish --cert {}",
                    keyid));
        }
    }

    Ok(())
}
