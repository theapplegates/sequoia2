use std::{
    collections::BTreeSet,
};

use sequoia_openpgp::{
    Result,
    serialize::Serialize,
};

use sequoia_cert_store::Store;
use sequoia_wot as wot;

use crate::Sq;
use crate::cli;
use crate::cli::key::approvals;
use crate::cli::types::FileStdinOrKeyHandle;
use crate::cli::types::FileOrStdout;
use crate::common::userid::make_userid_filter;

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

    let uid_filter = make_userid_filter(
        &cmd.names, &cmd.emails, &cmd.userids)?;
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
    let store = sq.cert_store_or_else()?;

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
    let vcert = key.with_policy(sq.policy, sq.time)?;

    // Lookup any explicitly goodlisted certifiers.  We need these to
    // verify the certifications.
    let mut add_by = Vec::new();
    for i in &command.add_by {
        add_by.append(&mut store.lookup_by_cert(i)?);
    }

    // If we want to authenticate, prepare the authentication network.
    let network_threshold = command.add_authenticated.map(
        |threshold|
        (wot::NetworkBuilder::rooted(store, &*sq.trust_roots()).build(),
         usize::from(threshold)));

    // Get a signer.
    let mut pk_signer = sq.get_primary_key(&key, None)?;

    // Now, create new attestation signatures.
    let mut attestation_signatures = Vec::new();

    // For the selected user IDs.
    let uid_filter = make_userid_filter(
        &command.names, &command.emails, &command.userids)?;
    for uid in vcert.userids().filter(uid_filter) {
        eprintln!("- {}", String::from_utf8_lossy(uid.value()));

        let previously_approved =
            uid.attested_certifications().collect::<BTreeSet<_>>();

        // Start from scratch or from the current set?
        let mut next_approved = if command.remove_all {
            Default::default()
        } else {
            previously_approved.clone()
        };

        // Selectively remove approvals.
        next_approved.retain(|s| ! s.get_issuers().iter().any(
            // Quadratic, but how bad can it be...?
            |i| command.remove_by.iter().any(|j| i.aliases(j))));

        // Selectively add approvals.
        let next_approved_cloned = next_approved.clone();
        for sig in uid.certifications()
        // Don't consider those that we already approved.
            .filter(|s| ! next_approved_cloned.contains(s))
        // Don't consider those explicitly removed.
            .filter(|s| ! s.get_issuers().iter().any(
                // Quadratic, but how bad can it be...?
                |i| command.remove_by.iter().any(|j| i.aliases(j))))
        {
            if command.add_all {
                next_approved.insert(sig);
                continue;
            }

            // Add by issuer handle.
            if let Some(cert) = sig.get_issuers().iter().find_map(
                // Quadratic, but how bad can it be...?
                |i| add_by.iter().find_map(
                    |cert| i.aliases(cert.key_handle()).then_some(cert)))
            {
                if sig.verify_signature(&cert.primary_key()).is_ok() {
                    next_approved.insert(sig);
                }
                continue;
            }

            // Add authenticated certifiers.
            if let Some((ref network, threshold)) = network_threshold {
                if let Some(cert) = sig.get_issuers().iter().find_map(
                    |i| store.lookup_by_cert(i).unwrap_or_default().into_iter()
                        .find_map(
                            |cert| sig.verify_signature(&cert.primary_key())
                                .is_ok().then_some(cert)))
                {
                    // We found the certifier.
                    if cert.userids().any(
                        |u| network.authenticate(u, cert.fingerprint(),
                                                 threshold)
                            .amount() >= threshold)
                    {
                        next_approved.insert(sig);
                        continue;
                    }
                }
            }
        }

        let mut any = false;
        for (prev, next, c) in uid.certifications()
            .map(|c| (previously_approved.contains(c),
                      next_approved.contains(c), c))
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

            eprintln!("  {} {}: {}",
                      match (prev, next) {
                          (false, false) => '.',
                          (true, false) => '-',
                          (false, true) => '+',
                          (true, true) => '=',
                      },
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
                      } else if next {
                          "approved".into()
                      } else if prev {
                          "previously approved".into()
                      } else {
                          "unapproved".into()
                      });
            any = true;
        }

        if ! any {
            eprintln!("    no certifications");
        }

        attestation_signatures.append(&mut uid.attest_certifications2(
            sq.policy,
            sq.time,
            &mut pk_signer,
            next_approved.into_iter(),
        )?);
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
