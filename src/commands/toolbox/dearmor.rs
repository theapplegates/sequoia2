use std::io;

use sequoia_openpgp as openpgp;
use openpgp::armor;

use crate::Config;
use crate::Result;
use crate::cli;

pub fn dispatch(config: Config, command: cli::toolbox::dearmor::Command)
    -> Result<()>
{
    tracer!(TRACE, "dearmor::dispatch");

    let mut input = command.input.open()?;
    let mut output = command.output.create_safe(config.force)?;
    let mut filter = armor::Reader::from_buffered_reader(&mut input, None)?;
    io::copy(&mut filter, &mut output)?;

    Ok(())
}
