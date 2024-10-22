use sequoia_openpgp as openpgp;
use openpgp::Result;
use openpgp::types::KeyFlags;

use crate::Sq;
use crate::cli::pki::vouch::certify;
use crate::cli::types::FileStdinOrKeyHandle;
use crate::commands::FileOrStdout;
use crate::parse_notations;

pub fn certify(sq: Sq, mut c: certify::Command)
    -> Result<()>
{
    let certifier: FileStdinOrKeyHandle = if let Some(file) = c.certifier_file {
        assert!(c.certifier.is_none());
        file.into()
    } else if let Some(kh) = c.certifier {
        kh.into()
    } else {
        panic!("clap enforces --certifier or --certifier-file is set");
    };

    let certifier = sq.lookup_one(
        certifier, Some(KeyFlags::empty().set_certification()), true)?;

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
        c.userids.add_userid().unwrap_or(false),
        true, // User supplied user IDs.
        &[(c.amount, c.expiration)],
        0,
        &[][..], &[][..], // Domain, regex.
        c.local,
        c.non_revocable,
        &notations[..],
        c.output,
        c.binary)
}
