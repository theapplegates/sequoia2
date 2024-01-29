use sequoia_openpgp as openpgp;
use openpgp::{
    Cert,
    Result,
    armor,
    packet::UserID,
    parse::Parse,
    serialize::Serialize,
};
use sequoia_autocrypt as autocrypt;

use crate::{
    Config,
    cli,
    commands::net::{
        certify_downloads,
        import_certs,
    },
};

pub fn dispatch(config: Config, c: &cli::autocrypt::Command) -> Result<()> {
    use cli::autocrypt::Subcommands::*;

    match &c.subcommand {
        Import(c) => import(config, c),
        Decode(c) => decode(config, c),
        EncodeSender(c) => encode_sender(config, c),
    }
}

fn import(mut config: Config, command: &cli::autocrypt::ImportCommand)
          -> Result<()>
{
    let input = command.input.open()?;
    let ac = autocrypt::AutocryptHeaders::from_reader(input)?;
    let from = UserID::from(
        ac.from.as_ref().ok_or(anyhow::anyhow!("no From: header"))?
            .as_str());
    let from_addr = from.email2()?.ok_or(
        anyhow::anyhow!("no email address in From: header"))?;

    for h in ac.headers {
        if let Some(addr) = h.attributes.iter()
            .find_map(|a| (&a.key == "addr"
                           && &a.value == &from_addr)
                      .then(|| a.value.clone()))
        {
            if let Some(cert) = h.key {
                let certs = if let Ok((ca, _)) = config.certd_or_else()
                    .and_then(|certd| certd.shadow_ca_autocrypt())
                {
                    certify_downloads(
                        &mut config, ca,
                        vec![cert], Some(&addr[..]))
                } else {
                    vec![cert]
                };

                import_certs(&mut config, certs)?;
            }
        }
    }

    Ok(())
}

fn decode(config: Config, command: &cli::autocrypt::DecodeCommand)
          -> Result<()>
{
    let input = command.input.open()?;
    let mut output = command.output.create_pgp_safe(
        config.force,
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

fn encode_sender(config: Config, command: &cli::autocrypt::EncodeSenderCommand)
                 -> Result<()>
{
    let input = command.input.open()?;
    let mut output = command.output.create_safe(config.force)?;
    let cert = Cert::from_reader(input)?;
    let addr = command.address.clone()
        .or_else(|| {
            cert.with_policy(&config.policy, None)
                .and_then(|vcert| vcert.primary_userid()).ok()
                .map(|ca| ca.userid().to_string())
        });
    let ac = autocrypt::AutocryptHeader::new_sender(
        &config.policy,
        &cert,
        &addr.ok_or_else(|| anyhow::anyhow!(
            "No well-formed primary userid found, use \
             --address to specify one"))?,
        Some(command.prefer_encrypt.to_string().as_str()))?;
    write!(&mut output, "Autocrypt: ")?;
    ac.serialize(&mut output)?;

    Ok(())
}
