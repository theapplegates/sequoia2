//! Converts a key to a cert.

use openpgp::parse::Parse;
use openpgp::serialize::Serialize;
use openpgp::Cert;
use openpgp::Result;
use sequoia_openpgp as openpgp;

use crate::Sq;
use crate::cli;

pub fn dispatch(
    sq: Sq,
    command: cli::toolbox::extract_cert::Command,
) -> Result<()> {
    let input = command.input.open()?;
    let mut output = command.output.create_safe(&sq)?;

    let cert = Cert::from_buffered_reader(input)?;
    if false {
        cert.serialize(&mut output)?;
    } else {
        cert.armored().serialize(&mut output)?;
    }
    Ok(())
}
