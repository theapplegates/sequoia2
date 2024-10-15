use sequoia_openpgp as openpgp;
use openpgp::cert::ValidCert;
use openpgp::packet::UserID;

use crate::Result;
use crate::cli::types::UserIDDesignators;
use crate::cli::types::userid_designator::UserIDDesignator;

impl<Arguments, Options> UserIDDesignators<Arguments, Options> {
    /// Resolve the user ID designators.
    pub fn resolve(&self, vc: &ValidCert) -> Result<Vec<UserID>> {
        // Find the matching User ID.
        let mut userids = Vec::new();

        // Don't stop at the first error.
        let mut missing = false;
        let mut bad = None;

        for designator in self.iter() {
            match designator {
                UserIDDesignator::UserID(userid) => {
                    let userid = UserID::from(&userid[..]);

                    // If --add-userid is specified, we use the user ID as
                    // is.  Otherwise, we make sure there is a matching
                    // self-signed user ID.
                    if self.add_userid().unwrap_or(false) {
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
                        if self.add_userid().unwrap_or(false) {
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

        Ok(userids)
    }
}
