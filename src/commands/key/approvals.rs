use std::{
    collections::BTreeSet,
};

use sequoia_openpgp::{
    Result,
    cert::amalgamation::ValidUserIDAmalgamation,
    serialize::Serialize,
};

use sequoia_cert_store::Store;

use crate::Sq;
use crate::cli;
use crate::cli::key::approvals;
use crate::cli::types::FileStdinOrKeyHandle;
use crate::cli::types::FileOrStdout;

pub fn dispatch(sq: Sq, command: approvals::Command)
                -> Result<()>
{
    match command {
        approvals::Command::List(c) => list(sq, c),
        approvals::Command::Update(c) => update(sq, c),
    }
}

fn list(sq: Sq, cmd: approvals::ListCommand) -> Result<()> {
    let cert = sq.lookup_one(&cmd.cert, None, true)?;
    let vcert = cert.with_policy(sq.policy, sq.time)?;
    let store = sq.cert_store_or_else()?;

    let uid_filter = |uid: &ValidUserIDAmalgamation| {
        if cmd.emails.is_empty() && cmd.names.is_empty() && cmd.userids.is_empty() {
            // No filter, list all user IDs.
            true
        } else {
            uid.email_normalized().ok().flatten()
                .map(|e| cmd.emails.contains(&e)).unwrap_or(false)
                || uid.name2().ok().flatten()
                .map(|n| cmd.names.iter().any(|i| i == n)).unwrap_or(false)
                || std::str::from_utf8(uid.value())
                .map(|u| cmd.userids.iter().any(|i| i == u)).unwrap_or(false)
        }
    };

    for uid in vcert.userids().filter(uid_filter) {
        eprintln!("- {}", String::from_utf8_lossy(uid.value()));

        let approved =
            uid.attested_certifications().collect::<BTreeSet<_>>();

        let mut any = false;
        for (approved, c) in uid.certifications()
            .map(|c| (approved.contains(c), c))
            .filter(|(a, _)| ! *a == cmd.pending)
        {
            // Verify certifications by looking up the issuing cert.
            let mut issuer = None;
            let mut err = None;
            for i in c.get_issuers().into_iter()
                .filter_map(|i| store.lookup_by_cert(&i).ok()
                            .map(IntoIterator::into_iter))
                .flatten()
            {
                match c.verify_signature(&i.primary_key()) {
                    Ok(_) => issuer = Some(i),
                    Err(e) => err = Some(e),
                }
            }

            eprintln!("  - {}: {}",
                      issuer.as_ref()
                      .and_then(|i| Some(sq.best_userid(i.to_cert().ok()?, true)
                                         .to_string()))
                      .or(c.get_issuers().into_iter().next()
                          .map(|h| h.to_string()))
                      .unwrap_or_else(|| "no issuer information".into()),
                      if issuer.is_none() {
                          if let Some(e) = err {
                              e.to_string()
                          } else {
                              "issuer cert not found".into()
                          }
                      } else if approved {
                          "approved".into()
                      } else {
                          "unapproved".into()
                      });
            any = true;
        }

        if ! any {
            eprintln!("  - no {} certifications",
                      if cmd.pending {
                          "unapproved"
                      } else {
                          "approved"
                      });
        }
    }

    Ok(())
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
    let mut pk_signer = sq.get_primary_key(&key, None)?;

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
