use crate::Result;
use crate::Sq;
use crate::common::key::delete;

pub fn dispatch(sq: Sq, command: crate::cli::key::subkey::delete::Command)
    -> Result<()>
{
    assert!(! command.keys.is_empty());

    delete(sq, command.cert, Some(command.keys),
           command.output, command.binary)
}
