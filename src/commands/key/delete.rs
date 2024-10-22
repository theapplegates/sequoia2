//! Changes key expiration.

use crate::Sq;
use crate::cli;
use crate::common::key::delete;
use crate::Result;

pub fn dispatch(sq: Sq, command: cli::key::delete::Command)
                -> Result<()>
{
    let handle =
        sq.resolve_cert(&command.cert, sequoia_wot::FULLY_TRUSTED)?.1;

    delete::delete(sq, handle, Vec::new(), command.output, command.binary)
}
