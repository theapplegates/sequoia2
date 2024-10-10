use std::fmt;

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;
use openpgp::packet::UserID;
use openpgp::Result;
use openpgp::types::KeyFlags;

use crate::Sq;
use crate::cli::pki::certify;
use crate::cli::types::FileOrStdin;
use crate::cli::types::FileStdinOrKeyHandle;
use crate::commands::FileOrStdout;
use crate::parse_notations;

/// How to match on user IDs.
#[derive(Debug)]
enum UserIDQuery {
    /// Exact match.
    Exact(String),

    /// Match on the email address.
    Email(String),
}

impl fmt::Display for UserIDQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserIDQuery::Exact(q) => f.write_str(q),
            UserIDQuery::Email(q) => write!(f, "<{}>", q),
        }
    }
}

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

    // XXX: Change this interface: it's dangerous to guess whether an
    // identifier is a file or a key handle.
    let cert = if let Ok(kh) = c.certificate.parse::<KeyHandle>() {
        FileStdinOrKeyHandle::KeyHandle(kh)
    } else {
        FileStdinOrKeyHandle::FileOrStdin(
            FileOrStdin::new(Some(c.certificate.into())))
    };
    if cert.is_file() {
        // If the cert is read from a file, we default to stdout.
        // (None means write to the cert store.)
        if c.output.is_none() {
            c.output = Some(FileOrStdout::new(None));
        }
    }

    let cert = sq.lookup_one(cert, None, true)?;
    let vc = cert.with_policy(sq.policy, Some(sq.time))?;

    // Find the matching User ID.
    let query = if c.email {
        UserIDQuery::Email(c.userid)
    } else {
        UserIDQuery::Exact(c.userid)
    };

    let mut userids = Vec::new();
    for ua in vc.userids() {
        match &query {
            UserIDQuery::Exact(q) => {
                if ua.userid().value() == q.as_bytes() {
                    userids.push(ua.userid().clone());
                    break;
                }
            },
            UserIDQuery::Email(q) => {
                if ua.userid().email2().map(|u| u == Some(q.as_str()))
                    .unwrap_or(false)
                {
                    userids.push(ua.userid().clone());
                }
            },
        }
    }

    if userids.is_empty() && c.add_userid {
        userids.push(match &query {
            UserIDQuery::Exact(q) => UserID::from(q.as_str()),
            UserIDQuery::Email(q) => {
                // XXX: Ideally, we could just use the following
                // expression, but currently this returns the bare
                // email address without brackets, so currently we
                // only use it to validate the address...
                UserID::from_address(None, None, q.as_str())?;

                // ... and construct the value by foot:
                UserID::from(format!("<{}>", q))

                // See https://gitlab.com/sequoia-pgp/sequoia/-/issues/1076
            },
        });
    }

    if userids.is_empty() {
        wprintln!("User ID: '{}' not found.\nValid User IDs:", query);
        let mut have_valid = false;
        for ua in vc.userids() {
            if let Ok(u) = std::str::from_utf8(ua.userid().value()) {
                have_valid = true;
                wprintln!("  - {}", u);
            }
        }
        if ! have_valid {
            wprintln!("  - Certificate has no valid User IDs.");
        }
        return Err(anyhow::format_err!("No matching User ID found"));
    };

    let notations = parse_notations(&c.notation)?;

    crate::common::pki::certify::certify(
        &sq,
        true, // Always recreate.
        &certifier,
        &cert,
        &userids[..],
        c.add_userid,
        true, // User supplied user IDs.
        &[(c.amount, c.expiration)],
        c.depth,
        &c.regex[..],
        c.local,
        c.non_revocable,
        &notations[..],
        c.output,
        c.binary)
}
