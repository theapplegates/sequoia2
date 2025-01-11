use sequoia_openpgp as openpgp;
use openpgp::Result;

use crate::Sq;
use crate::cli::pki::vouch::list;

pub fn list(sq: Sq, c: list::Command)
    -> Result<()>
{
    let certifier =
        sq.resolve_cert(&c.certifier, sequoia_wot::FULLY_TRUSTED)?.0;

    crate::common::pki::list::list(
        sq, &certifier, c.certs, c.pattern, false, false)?;

    Ok(())
}
