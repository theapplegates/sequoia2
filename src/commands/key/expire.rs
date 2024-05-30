//! Changes key expiration.

use crate::Sq;
use crate::cli;
use crate::common::expire;
use crate::Result;

pub fn dispatch(sq: Sq, command: cli::key::expire::Command)
                -> Result<()>
{
    expire(sq, command.cert_file, &command.subkey, command.expiry,
           command.output, command.binary)
}
