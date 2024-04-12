//! Converts a key to a cert.

use openpgp::parse::Parse;
use openpgp::serialize::Serialize;
use openpgp::Cert;
use openpgp::Result;
use sequoia_openpgp as openpgp;

use crate::Config;
use crate::cli;

pub fn dispatch(
    config: Config,
    command: cli::toolbox::extract_cert::Command,
) -> Result<()> {
    let input = command.input.open()?;
    let mut output = command.output.create_safe(config.force)?;

    let cert = Cert::from_buffered_reader(input)?;
    if command.binary {
        cert.serialize(&mut output)?;
    } else {
        cert.armored().serialize(&mut output)?;
    }
    Ok(())
}
