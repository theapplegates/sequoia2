use sequoia_openpgp as openpgp;
use openpgp::packet::UserID;
use openpgp::Result;
use openpgp::types::KeyFlags;

use crate::Sq;
use crate::cli::pki::authorize;
use crate::cli::types::FileStdinOrKeyHandle;
use crate::cli::types::cert_designator::CertDesignator;
use crate::commands::FileOrStdout;
use crate::parse_notations;

pub fn authorize(sq: Sq, mut c: authorize::Command)
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

    let (cert, from_file) = sq.resolve_cert(&c.cert, sequoia_wot::FULLY_TRUSTED)?;
    if from_file {
        // If the cert is read from a file, we default to stdout.
        // (None means write to the cert store.)
        if c.output.is_none() {
            c.output = Some(FileOrStdout::new(None));
        }
    }

    let vc = cert.with_policy(sq.policy, Some(sq.time))?;

    // Find the matching User ID.
    let mut userids = Vec::new();

    // Don't stop at the first error.
    let mut missing = false;
    let mut bad = None;

    for designator in c.userids.iter() {
        match designator {
            CertDesignator::UserID(userid) => {
                let userid = UserID::from(&userid[..]);

                // If --add-userid is specified, we use the user ID as
                // is.  Otherwise, we make sure there is a matching
                // self-signed user ID.
                if c.add_userid {
                    userids.push(userid.clone());
                } else if let Some(_) = vc.userids()
                    .find(|ua| {
                        ua.userid() == &userid
                    })
                {
                    userids.push(userid.clone());
                } else {
                    wprintln!("{:?} is not a self-signed user ID.",
                              String::from_utf8_lossy(userid.value()));
                    missing = true;
                }
            }
            CertDesignator::Email(email) => {
                // Validate the email address.
                let userid = match UserID::from_address(None, None, email) {
                    Ok(userid) => userid,
                    Err(err) => {
                        wprintln!("{:?} is not a valid email address: {}",
                                  email, err);
                        bad = Some(err);
                        continue;
                    }
                };

                // Extract a normalized version for comparison
                // purposes.
                let email_normalized = match userid.email_normalized() {
                    Ok(Some(email)) => email,
                    Ok(None) => {
                        wprintln!("{:?} is not a valid email address", email);
                        bad = Some(anyhow::anyhow!(format!(
                            "{:?} is not a valid email address", email)));
                        continue;
                    }
                    Err(err) => {
                        wprintln!("{:?} is not a valid email address: {}",
                                  email, err);
                        bad = Some(err);
                        continue;
                    }
                };

                // Find any the matching self-signed user IDs.
                let mut found = false;
                for ua in vc.userids() {
                    if Some(&email_normalized)
                        == ua.email_normalized().unwrap_or(None).as_ref()
                    {
                        userids.push(ua.userid().clone());
                        found = true;
                    }
                }

                if ! found {
                    if c.add_userid {
                        // Add the bare email address.
                        userids.push(userid);
                    } else {
                        eprintln!("The email address {:?} does not match any \
                                   user IDs.",
                                  email);
                        missing = true;
                    }
                }
            }
            _ => unreachable!("enforced by clap"),
        }
    }

    if missing || userids.is_empty() {
        // Use all self-signed User IDs.
        userids = vc.userids()
            .map(|ua| ua.userid().clone())
            .collect::<Vec<_>>();

        if userids.is_empty() {
            return Err(anyhow::anyhow!(
                "{} has no self-signed user IDs, and you didn't provide \
                 an alternate user ID",
                vc.fingerprint()));
        }
    };

    if let Some(err) = bad {
        return Err(err);
    }

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
