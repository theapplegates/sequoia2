use crate::Result;
use crate::Sq;
use crate::common::key::export;

pub fn dispatch(sq: Sq, command: crate::cli::key::subkey::export::Command)
    -> Result<()>
{
    assert!(! command.key.is_empty());

    export(sq, vec![], command.key, command.output, command.binary)
}

