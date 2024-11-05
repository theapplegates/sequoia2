use crate::Result;
use crate::Sq;
use crate::common::key::password;

pub fn dispatch(sq: Sq, command: crate::cli::key::subkey::password::Command)
    -> Result<()>
{
    let handle =
        sq.resolve_cert(&command.cert, sequoia_wot::FULLY_TRUSTED)?.1;

    assert!(! command.key.is_empty());

    password(sq, handle, command.key,
             command.clear_password, command.new_password_file.as_deref(),
             command.output, command.binary)
}

