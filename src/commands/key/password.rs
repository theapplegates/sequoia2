//! Changes a key's password.

use crate::Result;
use crate::Sq;
use crate::cli::types::KeyDesignators;
use crate::cli;
use crate::common::key::password;

pub fn dispatch(sq: Sq, command: cli::key::password::Command)
                -> Result<()>
{
    password::password(sq, command.cert, KeyDesignators::none(),
                       command.clear_password,
                       command.new_password_file.as_deref(),
                       command.output, command.binary)
}
