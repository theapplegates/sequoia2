use openpgp::parse::Parse;
use openpgp::serialize::Serialize;
use openpgp::Cert;
use openpgp::Result;
use sequoia_openpgp as openpgp;

use crate::sq_cli;
use crate::Config;

pub fn extract_cert(
    config: Config,
    command: sq_cli::key::ExtractCertCommand,
) -> Result<()> {
    let input = command.input.open()?;
    let mut output = command.output.create_safe(config.force)?;

    let cert = Cert::from_reader(input)?;
    if command.binary {
        cert.serialize(&mut output)?;
    } else {
        cert.armored().serialize(&mut output)?;
    }
    Ok(())
}
