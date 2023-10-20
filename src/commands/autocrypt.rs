use sequoia_openpgp as openpgp;
use openpgp::{
    Cert,
    Result,
    armor,
    parse::Parse,
    serialize::Serialize,
};
use sequoia_autocrypt as autocrypt;

use crate::{
    Config,
    cli,
};

pub fn dispatch(config: Config, c: &cli::autocrypt::Command) -> Result<()> {
    use cli::autocrypt::Subcommands::*;

    match &c.subcommand {
        Decode(command) => {
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
        }
        EncodeSender(command) => {
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
        },
    }

    Ok(())
}

