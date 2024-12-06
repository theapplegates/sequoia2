use sequoia_openpgp as openpgp;
use openpgp::Result;

use crate::Sq;
use crate::cli::pki::vouch::authorize;
use crate::commands::FileOrStdout;

pub fn authorize(sq: Sq, mut c: authorize::Command)
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

    let notations = c.signature_notations.parse()?;
    let expiration =
        sq.config.pki_vouch_expiration(&c.expiration, c.expiration_source);


    crate::common::pki::certify::certify(
        &mut std::io::stderr(),
        &sq,
        true, // Always recreate.
        &certifier,
        &cert,
        &userids[..],
        true, // User supplied user IDs.
        &[(c.amount, expiration)],
        c.depth,
        &c.domain[..],
        &c.regex[..],
        c.local,
        c.non_revocable,
        &notations[..],
        c.output,
        false)
}
