use std::sync::Arc;

use sequoia_openpgp as openpgp;
use openpgp::serialize::Serialize;
use openpgp::types::HashAlgorithm;
use openpgp::Cert;
use openpgp::Result;

use sequoia_cert_store as cert_store;
use cert_store::{LazyCert, StoreUpdate, store::MergeCerts};

use crate::Sq;
use crate::cli::types::userid_designator::ResolvedUserID;
use crate::cli;
use crate::commands::FileOrStdout;
use crate::sq::NULL_POLICY;

/// Computes a checksum of the cert.
fn cert_checksum(cert: &Cert) -> Result<Vec<u8>> {
    use openpgp::crypto::hash::Digest;
    let mut sum = HashAlgorithm::default().context()?;
    cert.as_tsk().serialize(&mut sum)?;
    sum.into_digest()
}

pub fn userid_strip(
    sq: Sq,
    command: cli::toolbox::strip_userid::Command,
) -> Result<()> {
    let cert =
        sq.resolve_cert(&command.cert, sequoia_wot::FULLY_TRUSTED)?.0;

    // We use the NULL policy, because we don't really care if the
    // user IDs are valid: the user is not trying to use them; they
    // are trying to remove them.
    let vc = cert.with_policy(&NULL_POLICY, sq.time)?;
    let userids = command.userids.resolve(&vc)?;

    userid_strip_internal(sq, cert, userids, 3, command.output, command.binary)
}

fn userid_strip_internal(
    sq: Sq,
    key: Cert,
    strip: Vec<ResolvedUserID>,
    tries: usize,
    output: Option<FileOrStdout>,
    binary: bool,
) -> Result<()> {
    let orig_cert_checksum = cert_checksum(&key)?;
    let orig_cert_valid = key.with_policy(sq.policy, None).is_ok();

    // Make sure that each User ID that the user requested to remove exists in
    // `key`, and *can* be removed.
    let key_userids: Vec<_> =
        key.userids().map(|u| u.userid().value()).collect();

    let missing: Vec<_> = strip
        .iter()
        .filter(|s| !key_userids.contains(&s.userid().value()))
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
        !strip.iter().any(|rm| rm.userid() == uid.component())
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

    if let Some(output) = output {
        let mut sink = output.for_secrets().create_safe(&sq)?;
        if binary {
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
                            sq, retry_with.cert, strip,
                            tries.checked_sub(1).expect("tries left"),
                            output, binary)
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
