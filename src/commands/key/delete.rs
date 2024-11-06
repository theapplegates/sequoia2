//! Changes key expiration.

use crate::Result;
use crate::Sq;
use crate::cli::types::KeyDesignators;
use crate::cli;
use crate::common::key::delete;

pub fn dispatch(sq: Sq, command: cli::key::delete::Command)
                -> Result<()>
{
    delete::delete(sq, command.cert, KeyDesignators::none(),
                   command.output, command.binary)
}
