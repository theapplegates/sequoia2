use crate::Result;
use crate::Sq;
use crate::common::key::password;

pub fn dispatch(sq: Sq, command: crate::cli::key::subkey::password::Command)
    -> Result<()>
{
    assert!(! command.keys.is_empty());

    password(sq, command.cert, Some(command.keys),
             command.clear_password, command.new_password_file.as_deref(),
             command.output, command.binary)
}

