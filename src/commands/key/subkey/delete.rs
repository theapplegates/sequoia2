use crate::Result;
use crate::Sq;
use crate::common::key::delete;

pub fn dispatch(sq: Sq, command: crate::cli::key::subkey::delete::Command)
    -> Result<()>
{
    let handle =
        sq.resolve_cert(&command.cert, sequoia_wot::FULLY_TRUSTED)?.1;

    assert!(! command.key.is_empty());

    delete(sq, handle, command.key, command.output, command.binary)
}
