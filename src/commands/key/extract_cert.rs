use openpgp::parse::Parse;
use openpgp::serialize::Serialize;
use openpgp::Cert;
use openpgp::Result;
use sequoia_openpgp as openpgp;

use crate::open_or_stdin;
use crate::sq_cli;
use crate::Config;

pub fn extract_cert(
    config: Config,
    command: sq_cli::key::ExtractCertCommand,
) -> Result<()> {
    let input = open_or_stdin(command.io.input.as_deref())?;
    let mut output =
        config.create_or_stdout_safe(command.io.output.as_deref())?;

    let cert = Cert::from_reader(input)?;
    if command.binary {
        cert.serialize(&mut output)?;
    } else {
        cert.armored().serialize(&mut output)?;
    }
    Ok(())
}
