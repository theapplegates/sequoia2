use sequoia_cert_store as cert_store;
use cert_store::Store;

use crate::Result;
use crate::Sq;
use crate::cli::pki::link;

pub fn list(sq: Sq, c: link::ListCommand)
    -> Result<()>
{
    let cert_store = sq.cert_store_or_else()?;
    cert_store.prefetch_all();

    let trust_root = sq.local_trust_root()?;
    let trust_root = trust_root.to_cert()?;

    crate::common::pki::list::list(
        sq, &trust_root, c.certs, c.pattern, c.ca, true)?;

    Ok(())
}
