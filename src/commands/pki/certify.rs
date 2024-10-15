use sequoia_openpgp as openpgp;
use openpgp::packet::UserID;
use openpgp::Result;
use openpgp::types::KeyFlags;

use crate::Sq;
use crate::cli::pki::certify;
use crate::cli::types::FileStdinOrKeyHandle;
use crate::cli::types::userid_designator::UserIDDesignator;
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
            UserIDDesignator::UserID(userid) => {
                let userid = UserID::from(&userid[..]);

                // If --add-userid is specified, we use the user ID as
                // is.  Otherwise, we make sure there is a matching
                // self-signed user ID.
                if c.userids.add_userid().unwrap_or(false) {
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
            UserIDDesignator::Email(email) => {
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
                    if c.userids.add_userid().unwrap_or(false) {
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
        }
    }

    if missing {
        wprintln!("{}'s self-signed user IDs:", vc.fingerprint());
        let mut have_valid = false;
        for ua in vc.userids() {
            if let Ok(u) = std::str::from_utf8(ua.userid().value()) {
                have_valid = true;
                wprintln!("  - {:?}", u);
            }
        }
        if ! have_valid {
            wprintln!("  - Certificate has no valid user IDs.");
        }
        wprintln!("Pass `--add-userid` to certify a user ID even if it \
                   isn't self signed.");
        return Err(anyhow::anyhow!("Not a self-signed user ID"));
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
