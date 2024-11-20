use sequoia_openpgp as openpgp;
use openpgp::Result;

use crate::Sq;
use crate::cli::pki::vouch::add;
use crate::commands::FileOrStdout;
use crate::parse_notations;

pub fn add(sq: Sq, mut c: add::Command)
    -> Result<()>
{
    let certifier =
        sq.resolve_cert(&c.certifier, sequoia_wot::FULLY_TRUSTED)?.0;

    let (cert, source) = sq.resolve_cert(&c.cert, sequoia_wot::FULLY_TRUSTED)?;
    if source.is_file() {
        // If the cert is read from a file, we default to stdout.
        // (None means write to the cert store.)
        if c.output.is_none() {
            c.output = Some(FileOrStdout::new(None));
        }
    }

    let vc = cert.with_policy(sq.policy, Some(sq.time))?;
    let userids = c.userids.resolve(&vc)?;

    let notations = parse_notations(&c.notation)?;

    crate::common::pki::certify::certify(
        &sq,
        true, // Always recreate.
        &certifier,
        &cert,
        &userids[..],
        true, // User supplied user IDs.
        &[(c.amount, c.expiration.value())],
        0,
        &[][..], &[][..], // Domain, regex.
        c.local,
        c.non_revocable,
        &notations[..],
        c.output,
        false)
}
