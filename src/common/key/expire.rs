//! Changes key expiration.

use std::sync::Arc;

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;
use openpgp::Packet;
use openpgp::Result;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::serialize::Serialize;
use openpgp::types::SignatureType;

use sequoia_cert_store::StoreUpdate;

use crate::cli::types::Expiration;
use crate::cli::types::FileOrStdout;
use crate::cli::types::FileStdinOrKeyHandle;
use crate::Sq;
use crate::sq::GetKeysOptions;

pub fn expire(sq: Sq,
              cert: FileStdinOrKeyHandle,
              subkeys: &[KeyHandle],
              expiration: Expiration,
              mut output: Option<FileOrStdout>,
              binary: bool)
    -> Result<()>
{
    let policy = sq.policy.clone();

    if cert.is_file() {
        if output.is_none() {
            // None means to write to the cert store.  When reading
            // from a file, we want to write to stdout by default.
            output = Some(FileOrStdout::new(None));
        }
    }
    let key = sq.lookup_one(cert, None, true)?;

    let primary_handle = key.key_handle();

    let mut primary_signer
        = sq.get_primary_key(&key, Some(&[GetKeysOptions::AllowNotAlive]))?.0;

    // Fix the new expiration time.
    let expiration_time = expiration.to_systemtime(sq.time);

    // We want to check that all given key handles exist, make a list.
    let handles = key.keys().map(|k| k.key_handle()).collect::<Vec<_>>();

    // We update the primary key if no subkey is given, or it is
    // explicitly listed as subkey to change.
    let mut update_primary_key = subkeys.is_empty();

    // We update the subkey bindings if they are explicitly given.
    let update_subkeys = ! subkeys.is_empty();

    let mut keys = key.keys().subkeys();
    for h in subkeys {
        if ! handles.iter().any(|k| k.aliases(h)) {
            wprintln!("Selected subkey {} does not exist in the key.", h);
            wprintln!();
            wprintln!("The key has the following subkeys:");
            wprintln!();
            for k in &handles {
                wprintln!(" - {}", k);
            }
            return Err(anyhow::anyhow!("selected subkey not found"));
        }

        if h.aliases(&primary_handle) {
            update_primary_key = true;
        } else {
            keys = keys.key_handle(h.clone());
        }
    }

    // Collect new signatures here, then canonicalize once.
    let mut acc = Vec::<Packet>::new();

    if update_subkeys {
        // To update subkey expiration times, create new binding
        // signatures.
        for skb in keys {
            // Preferably use the binding signature under our policy,
            // fall back to the most recent binding signature.
            let template = skb.binding_signature(&policy, sq.time)
                .or(skb.self_signatures().next()
                    .ok_or(anyhow::anyhow!("no binding signature")))?
                .clone();

            acc.push(skb.bind(
                &mut primary_signer,
                &key,
                SignatureBuilder::from(template)
                    .set_signature_creation_time(sq.time)?
                    .set_key_expiration_time(skb.key(), expiration_time)?)?
                     .into());
        }
    }

    // To change the key's expiration time, create a new direct key
    // signature and new binding signatures for the user IDs.
    if update_primary_key {
        // Preferably use the direct key signature under our policy,
        // fall back to the most recent direct key signature.
        let template = key.primary_key().binding_signature(&policy, sq.time)
            .or(key.primary_key().self_signatures().next()
                .ok_or(anyhow::anyhow!("no primary key signature")))?
            .clone();

        acc.push(SignatureBuilder::from(template)
                 .set_type(SignatureType::DirectKey)
                 .set_signature_creation_time(sq.time)?
                 .set_key_expiration_time(key.primary_key().key(),
                                          expiration_time)?
                 .sign_direct_key(&mut primary_signer, None)?
                 .into());

        for uidb in key.userids() {
            // Preferably use the direct binding signature under our
            // policy, fall back to the most recent binding signature.
            let template = uidb.binding_signature(&policy, sq.time)
                .or(uidb.self_signatures().next()
                    .ok_or(anyhow::anyhow!("no user ID binding signature")))?
                .clone();

            acc.push(uidb.bind(
                &mut primary_signer,
                &key,
                SignatureBuilder::from(template)
                    .set_signature_creation_time(sq.time)?
                    .set_key_expiration_time(key.primary_key().key(),
                                             expiration_time)?)?
                     .into());
        }
    }

    // Merge and canonicalize.
    let key = key.insert_packets(acc)?;

    if let Some(sink) = output {
        let path = sink.path().map(Clone::clone);
        let mut output = sink.for_secrets().create_safe(sq.force)?;
        if binary {
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
        let cert_store = sq.cert_store_or_else()?;

        let keyid = key.keyid();
        if let Err(err) = cert_store.update(Arc::new(key.into())) {
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
