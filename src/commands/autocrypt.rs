use std::sync::Arc;

use anyhow::{Context, Result};

use buffered_reader::{BufferedReader, Dup};
use sequoia_openpgp as openpgp;
use openpgp::{
    packet::UserID,
    parse::{Cookie, Parse, stream::DecryptorBuilder},
};
use sequoia_autocrypt as autocrypt;
use sequoia_cert_store::{LazyCert, StoreUpdate};

use crate::{
    Sq,
    commands::network::{
        certify_downloads,
    },
    output::import::ImportStats,
};

/// Imports certs encoded as Autocrypt headers.
///
/// We also try to decrypt the message, and collect the gossip headers.
pub fn import_certs(sq: &mut Sq, source: &mut Box<dyn BufferedReader<Cookie>>,
                    stats: &mut ImportStats)
                    -> Result<()>
{
    let mut acc = Vec::new();

    // First, get the Autocrypt headers from the outside.
    let mut dup = Dup::with_cookie(&mut *source, Cookie::default());
    let ac = autocrypt::AutocryptHeaders::from_reader(&mut dup)?;
    let from = UserID::from(
        ac.from.as_ref().ok_or(anyhow::anyhow!("no From: header"))?
            .as_str());
    let from_addr = from.email2()?.ok_or(
        anyhow::anyhow!("no email address in From: header"))?;

    use autocrypt::AutocryptHeaderType::*;
    let mut sender_cert = None;
    for h in ac.headers.into_iter().filter(|h| h.header_type == Sender) {
        if let Some(addr) = h.attributes.iter()
            .find_map(|a| (&a.key == "addr"
                           && &a.value == &from_addr)
                      .then(|| a.value.clone()))
        {
            if let Some(cert) = h.key {
                sender_cert = Some(cert.clone());

                if let Ok((ca, _)) = sq.certd_or_else()
                    .and_then(|certd| certd.shadow_ca_autocrypt())
                {
                    acc.append(&mut certify_downloads(
                        sq, ca,
                        vec![cert], Some(&addr[..])));
                } else {
                    acc.push(cert);
                }
            }
        }
    }

    let cert_store = sq.cert_store_or_else()?;
    for cert in acc.drain(..) {
        cert_store.update_by(Arc::new(LazyCert::from(cert)), stats)?;
    }

    // If there is no Autocrypt header, don't bother looking for
    // gossip.
    let sender_cert = match sender_cert {
        Some(c) => c,
        None => return Ok(()),
    };

    // Then, try to decrypt the message, and look for gossip headers.
    use crate::commands::decrypt::Helper;
    let mut helper = Helper::new(
        &sq,
        1, // Require one trusted signature...
        vec![sender_cert.clone()], // ... from this cert.
        vec![], vec![], false);
    helper.quiet(true);

    let policy = sq.policy.clone();
    let dup = Dup::with_cookie(source, Cookie::default());
    let mut decryptor = match DecryptorBuilder::from_buffered_reader(dup)?
        .with_policy(&policy, None, helper)
        .context("Decryption failed")
    {
        Ok(d) => d,
        Err(e) => {
            // The decryption failed, but we should still import the
            // Autocrypt header.
            wprintln!("Note: Decryption of message failed: {}", e);
            return Ok(());
        },
    };

    let ac = autocrypt::AutocryptHeaders::from_reader(&mut decryptor)?;
    let helper = decryptor.into_helper();

    // We know there has been one good signature from the sender.  Now
    // check that the message was encrypted.  Note: it doesn't have to
    // be encrypted for the purpose of the certification, but
    // Autocrypt requires messages to be signed and encrypted.
    if helper.sym_algo.is_none() {
        return Err(anyhow::anyhow!("Message is not encrypted."));
    }

    for h in ac.headers.into_iter().filter(|h| h.header_type == Gossip) {
        if let Some(_addr) = h.attributes.iter()
            .find_map(|a| (&a.key == "addr").then(|| a.value.clone()))
        {
            if let Some(cert) = h.key {
                acc.push(cert);
            }
        }
    }

    for cert in acc {
        cert_store.update_by(Arc::new(LazyCert::from(cert)), stats)?;
    }

    Ok(())
}
