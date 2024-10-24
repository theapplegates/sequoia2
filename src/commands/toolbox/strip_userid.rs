use std::sync::Arc;

use sequoia_openpgp as openpgp;
use openpgp::packet::UserID;
use openpgp::serialize::Serialize;
use openpgp::types::HashAlgorithm;
use openpgp::Cert;
use openpgp::Result;

use sequoia_cert_store as cert_store;
use cert_store::{LazyCert, StoreUpdate, store::MergeCerts};

use crate::Sq;
use crate::cli;
use crate::common::userid::{
    lint_emails,
    lint_names,
};

/// Computes a checksum of the cert.
fn cert_checksum(cert: &Cert) -> Result<Vec<u8>> {
    use openpgp::crypto::hash::Digest;
    let mut sum = HashAlgorithm::default().context()?;
    cert.as_tsk().serialize(&mut sum)?;
    sum.into_digest()
}

pub fn userid_strip(
    sq: Sq,
    mut command: cli::toolbox::strip_userid::Command,
) -> Result<()> {
    let cert =
        sq.resolve_cert(&command.cert, sequoia_wot::FULLY_TRUSTED)?.0;

    lint_names(&command.names)?;
    for n in &command.names {
        command.userid.push(UserID::from(n.as_str()));
    }

    lint_emails(&command.emails)?;
    for n in &command.emails {
        command.userid.push(UserID::from_address(None, None, n)?);
    }

    userid_strip_internal(sq, command, cert, 3)
}

fn userid_strip_internal(
    sq: Sq,
    command: cli::toolbox::strip_userid::Command,
    key: Cert,
    tries: usize,
) -> Result<()> {
    let orig_cert_checksum = cert_checksum(&key)?;
    let orig_cert_valid = key.with_policy(sq.policy, None).is_ok();

    let strip: &Vec<_> = &command.userid;

    // Make sure that each User ID that the user requested to remove exists in
    // `key`, and *can* be removed.
    let key_userids: Vec<_> =
        key.userids().map(|u| u.userid().value()).collect();

    let missing: Vec<_> = strip
        .iter()
        .filter(|s| !key_userids.contains(&s.value()))
        .collect();
    if !missing.is_empty() {
        return Err(anyhow::anyhow!(
            "The certificate doesn't contain the User ID(s) {}.",
            missing.iter().map(|s| format!("{:?}", s)).collect::<Vec<_>>()
                .join(", "),
        ));
    }

    let cert = key.retain_userids(|uid| {
        // Don't keep User IDs that were selected for removal
        !strip.iter().any(|rm| rm == uid.component())
    });

    if orig_cert_valid {
        if let Err(err) = cert.with_policy(sq.policy, None) {
            wprintln!(
                "Removing the User ID(s) has resulted in a invalid key:
{}

You could create a direct key signature or update the self
signatures on other User IDs to make the key valid again.",
                err
            );
        }
    }

    if let Some(output) = command.output {
        let mut sink = output.for_secrets().create_safe(&sq)?;
        if command.binary {
            cert.as_tsk().serialize(&mut sink)?;
        } else {
            cert.as_tsk().armored().serialize(&mut sink)?;
        }
    } else {
        // Update the cert in the cert store.  Be careful not to stomp
        // on concurrent edits.
        struct CarefulUpdate {
            orig_checksum: Vec<u8>,
        }

        #[derive(thiserror::Error, Debug)]
        #[error("the cert changed in the store")]
        struct RetryWith {
            cert: Cert,
        }

        let updater = CarefulUpdate {
            orig_checksum: orig_cert_checksum,
        };

        impl<'a> MergeCerts<'a> for CarefulUpdate {
            fn merge_public<'b>(
                &self,
                new: Arc<LazyCert<'a>>,
                disk: Option<Arc<LazyCert<'b>>>,
            ) -> Result<Arc<LazyCert<'a>>> {
                // While we're holding the lock, make sure that the
                // cert didn't change.
                let disk = disk.ok_or_else(|| anyhow::anyhow!(
                    "cert was deleted in the cert store"))?;
                let checksum = cert_checksum(disk.to_cert()?)?;
                if self.orig_checksum == checksum {
                    // It didn't change, replace it.
                    Ok(new)
                } else {
                    // It changed, keep the disk version and retry.
                    Err(RetryWith {
                        cert: disk.to_cert()?.clone(),
                    }.into())
                }
            }
        }

        let cert_store = sq.cert_store_or_else()?;
        if let Err(e) = cert_store.update_by(Arc::new(cert.into()), &updater) {
            return match e.downcast::<RetryWith>() {
                Ok(retry_with) => {
                    if tries > 0 {
                        // The cert changed in the store, and there
                        // are tries left..  Retry the operation with
                        // the changed cert.
                        userid_strip_internal(
                            sq, command, retry_with.cert,
                            tries.checked_sub(1).expect("tries left"))
                    } else {
                        Err(retry_with.into())
                    }
                },
                Err(e) => Err(e),
            }
        }
    }

    Ok(())
}
