use crate::Sq;
use crate::cli;
use crate::common::key::export;
use crate::Result;

pub fn dispatch(sq: Sq, command: cli::key::export::Command)
                -> Result<()>
{
    export::export(sq, command.cert, Vec::new())
}
