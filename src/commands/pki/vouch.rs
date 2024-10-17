use sequoia_openpgp as openpgp;
use openpgp::Result;

use crate::cli::pki::vouch;
use crate::Sq;

pub mod authorize;
pub mod certify;

pub fn vouch(sq: Sq, c: vouch::Command) -> Result<()> {
    use vouch::Subcommands::*;
    match c.subcommand {
        Certify(c) => certify::certify(sq, c)?,
        Authorize(c) => authorize::authorize(sq, c)?,
    }
    Ok(())
}
