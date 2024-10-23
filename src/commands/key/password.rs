//! Changes a key's password.

use crate::Sq;
use crate::cli;
use crate::common::key::password;
use crate::Result;

pub fn dispatch(sq: Sq, command: cli::key::password::Command)
                -> Result<()>
{
    let handle =
        sq.resolve_cert(&command.cert, sequoia_wot::FULLY_TRUSTED)?.1;

    password::password(sq, handle, vec![],
                       command.clear_password,
                       command.new_password_file.as_deref(),
                       command.output, command.binary)
}
