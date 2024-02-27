//! Changes key expiration.

use std::sync::Arc;

use anyhow::Context;

use sequoia_openpgp::{
    Cert,
    Packet,
    Result,
    packet::signature::SignatureBuilder,
    parse::Parse,
    serialize::Serialize,
    types::SignatureType,
};
use sequoia_cert_store::StoreUpdate;

use crate::{
    Config,
    cli,
};

pub fn dispatch(config: Config, command: cli::key::expire::Command)
                -> Result<()>
{
    let policy = config.policy.clone();
    let cert_store = if command.output.is_none() {
        Some(config.cert_store_or_else()?)
    } else {
        None
    };

    let input = command.input.open()?;
    let key = Cert::from_reader(input)?;
    if ! key.is_tsk() {
        return Err(anyhow::anyhow!("Certificate has no secrets"));
    }

    let primary_handle = key.key_handle();
    let mut primary_signer = key.primary_key().key().clone()
        .parts_into_secret().and_then(|k| k.into_keypair())
        .with_context(|| "Primary key has no secrets")?;

    // Fix the new expiration time.
    let expiration_time = command.expiry.to_systemtime();

    // We want to check that all given key handles exist, make a list.
    let handles = key.keys().map(|k| k.key_handle()).collect::<Vec<_>>();

    // We update the primary key if no subkey is given, or it is
    // explicitly listed as subkey to change.
    let mut update_primary_key = command.subkey.is_empty();

    // We update the subkey bindings if they are explicitly given.
    let update_subkeys = ! command.subkey.is_empty();

    let mut keys = key.keys().subkeys();
    for h in command.subkey {
        if ! handles.iter().any(|k| k.aliases(&h)) {
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
            keys = keys.key_handle(h);
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
            let template = skb.binding_signature(&policy, None)
                .or(skb.self_signatures().next()
                    .ok_or(anyhow::anyhow!("no binding signature")))?
                .clone();

            acc.push(skb.bind(
                &mut primary_signer,
                &key,
                SignatureBuilder::from(template)
                    .set_key_expiration_time(skb.key(), expiration_time)?)?
                     .into());
        }
    }

    // To change the key's expiration time, create a new direct key
    // signature and new binding signatures for the user IDs.
    if update_primary_key {
        // Preferably use the direct key signature under our policy,
        // fall back to the most recent direct key signature.
        let template = key.primary_key().binding_signature(&policy, None)
            .or(key.primary_key().self_signatures().next()
                .ok_or(anyhow::anyhow!("no primary key signature")))?
            .clone();

        acc.push(SignatureBuilder::from(template)
                 .set_type(SignatureType::DirectKey)
                 .set_key_expiration_time(key.primary_key().key(),
                                          expiration_time)?
                 .sign_direct_key(&mut primary_signer, None)?
                 .into());

        for uidb in key.userids() {
            // Preferably use the direct binding signature under our
            // policy, fall back to the most recent binding signature.
            let template = uidb.binding_signature(&policy, None)
                .or(uidb.self_signatures().next()
                    .ok_or(anyhow::anyhow!("no user ID binding signature")))?
                .clone();

            acc.push(uidb.bind(
                &mut primary_signer,
                &key,
                SignatureBuilder::from(template)
                    .set_key_expiration_time(key.primary_key().key(),
                                             expiration_time)?)?
                     .into());
        }
    }

    // Merge and canonicalize.
    let key = key.insert_packets(acc)?;

    if let Some(sink) = command.output {
        let path = sink.path().map(Clone::clone);
        let mut output = sink.for_secrets().create_safe(config.force)?;
        if command.binary {
            key.as_tsk().serialize(&mut output)?;
        } else {
            key.as_tsk().armored().serialize(&mut output)?;
        }

        if let Some(path) = path {
            config.hint(format_args!(
                "Updated key written to {}.  \
                 To make the update effective, it has to be published \
                 so that others can find it, for example using:",
                path.display()))
                .command(format_args!(
                    "sq network keyserver publish {}",
                    path.display()));
        } else {
            config.hint(format_args!(
                "To make the update effective, it has to be published \
                 so that others can find it."));
        }
    } else {
        let keyid = key.keyid();
        if let Err(err) = cert_store.expect("set if output is None")
            .update_by(Arc::new(key.into()), &mut ())
        {
            wprintln!("Error importing updated cert: {}", err);
            return Err(err);
        } else {
            config.hint(format_args!(
                "Imported updated cert into the cert store.  \
                 To make the update effective, it has to be published \
                 so that others can find it, for example using:"))
                .command(format_args!(
                    "sq cert export --cert {} | sq network keyserver publish",
                    keyid));
        }
    }

    Ok(())
}
