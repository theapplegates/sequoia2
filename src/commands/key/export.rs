use crate::Sq;
use crate::cli;
use crate::common::key::export;
use crate::Result;

pub fn dispatch(sq: Sq, command: cli::key::export::Command)
                -> Result<()>
{
    let certs =
        sq.resolve_certs_or_fail(&command.certs, sequoia_wot::FULLY_TRUSTED)?
        .into_iter()
        .map(|c| c.key_handle())
        .collect();

    export::export(sq, certs, Vec::new())
}
