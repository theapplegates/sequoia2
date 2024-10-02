use anyhow::Context;

use buffered_reader::Dup;
use sequoia_openpgp as openpgp;
use openpgp::{
    Cert,
    Result,
    armor,
    packet::UserID,
    parse::{Cookie, Parse, stream::DecryptorBuilder},
    serialize::Serialize,
};
use sequoia_autocrypt as autocrypt;

use crate::{
    Sq,
    cli,
    commands::network::{
        certify_downloads,
        import_certs,
    },
};

pub fn dispatch(sq: Sq, c: &cli::autocrypt::Command) -> Result<()> {
    use cli::autocrypt::Subcommands::*;

    match &c.subcommand {
        Import(c) => import(sq, c),
        Decode(c) => decode(sq, c),
        EncodeSender(c) => encode_sender(sq, c),
    }
}

fn import<'store, 'rstore>(mut sq: Sq<'store, 'rstore>,
                   command: &cli::autocrypt::ImportCommand)
          -> Result<()>
    where 'store: 'rstore
{
    let mut input = command.input.open()?;

    // Accumulate certs and do one import so that we generate one
    // report.
    let mut acc = Vec::new();

    // First, get the Autocrypt headers from the outside.
    let mut dup = Dup::with_cookie(&mut input, Cookie::default());
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
                        &mut sq, ca,
                        vec![cert], Some(&addr[..])));
                } else {
                    acc.push(cert);
                }
            }
        }
    }

    // If there is no Autocrypt header, don't bother looking for
    // gossip.
    let sender_cert = match sender_cert {
        Some(c) => c,
        None => {
            // Import what we got.
            import_certs(&mut sq, acc)?;
            return Ok(());
        },
    };

    // Then, try to decrypt the message, and look for gossip headers.
    use crate::{load_keys, commands::decrypt::Helper};
    let secrets =
        load_keys(command.secret_key_file.iter().map(|s| s.as_ref()))?;

    let mut helper = Helper::new(
        &sq,
        1, // Require one trusted signature...
        vec![sender_cert.clone()], // ... from this cert.
        secrets, command.session_key.clone(), false);
    helper.quiet(true);

    let policy = sq.policy.clone();
    let mut decryptor = match DecryptorBuilder::from_buffered_reader(input)?
        .with_policy(&policy, None, helper)
        .context("Decryption failed")
    {
        Ok(d) => d,
        Err(e) => {
            // The decryption failed, but we should still import the
            // Autocrypt header.
            wprintln!("Note: Decryption of message failed: {}", e);
            import_certs(&mut sq, acc)?;
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
        if let Some(addr) = h.attributes.iter()
            .find_map(|a| (&a.key == "addr").then(|| a.value.clone()))
        {
            if let Some(cert) = h.key {
                if let Ok((ca, _)) = sq.certd_or_else()
                    .and_then(|certd| certd.shadow_ca_autocrypt_gossip_for(
                        &sender_cert, from_addr))
                {
                    acc.append(&mut certify_downloads(
                        &mut sq, ca,
                        vec![cert], Some(&addr[..])));
                } else {
                    acc.push(cert);
                }
            }
        }
    }

    // Finally, do one import.
    import_certs(&mut sq, acc)?;

    Ok(())
}

fn decode(sq: Sq, command: &cli::autocrypt::DecodeCommand)
          -> Result<()>
{
    let input = command.input.open()?;
    let mut output = command.output.create_pgp_safe(
        &sq,
        command.binary,
        armor::Kind::PublicKey,
    )?;
    let ac = autocrypt::AutocryptHeaders::from_reader(input)?;
    for h in &ac.headers {
        if let Some(ref cert) = h.key {
            cert.serialize(&mut output)?;
        }
    }
    output.finalize()?;

    Ok(())
}

fn encode_sender(sq: Sq, command: &cli::autocrypt::EncodeSenderCommand)
                 -> Result<()>
{
    let input = command.input.open()?;
    let mut output = command.output.create_safe(&sq)?;
    let cert = Cert::from_buffered_reader(input)?;
    let addr = command.address.clone()
        .or_else(|| {
            cert.with_policy(sq.policy, None)
                .and_then(|vcert| vcert.primary_userid()).ok()
                .map(|ca| ca.userid().to_string())
        });
    let ac = autocrypt::AutocryptHeader::new_sender(
        sq.policy,
        &cert,
        &addr.ok_or_else(|| anyhow::anyhow!(
            "No well-formed primary userid found, use \
             --address to specify one"))?,
        Some(command.prefer_encrypt.to_string().as_str()))?;
    write!(&mut output, "Autocrypt: ")?;
    ac.serialize(&mut output)?;

    Ok(())
}
