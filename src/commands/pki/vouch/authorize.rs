use sequoia_openpgp as openpgp;
use openpgp::Result;

use crate::Sq;
use crate::cli::pki::vouch::authorize;
use crate::cli::types::userid_designator::ResolvedUserID;
use crate::commands::FileOrStdout;
use crate::parse_notations;

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
    let mut userids = c.userids.resolve(&vc)?;
    let user_supplied_userids = if userids.is_empty() {
        // Use all self-signed User IDs.
        userids = ResolvedUserID::implicit_for_valid_cert(&vc);

        if userids.is_empty() {
            return Err(anyhow::anyhow!(
                "{} has no self-signed user IDs, and you didn't provide \
                 an alternate user ID",
                vc.fingerprint()));
        }

        false
    } else {
        true
    };

    let notations = parse_notations(&c.notation)?;

    crate::common::pki::certify::certify(
        &sq,
        true, // Always recreate.
        &certifier,
        &cert,
        &userids[..],
        user_supplied_userids,
        &[(c.amount, c.expiration.value())],
        c.depth,
        &c.domain[..],
        &c.regex[..],
        c.local,
        c.non_revocable,
        &notations[..],
        c.output,
        c.binary)
}
