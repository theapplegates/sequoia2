//! Changes key expiration.

use crate::Sq;
use crate::cli;
use crate::common::key::expire;
use crate::Result;

pub fn dispatch(sq: Sq, command: cli::key::expire::Command)
                -> Result<()>
{
    let handle =
        sq.resolve_cert(&command.cert, sequoia_wot::FULLY_TRUSTED)?.1;

    expire(sq, handle, &[], command.expiration.value(),
           command.output, command.binary)
}
