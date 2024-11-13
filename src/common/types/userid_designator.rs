use std::collections::HashSet;

use typenum::Unsigned;

use sequoia_openpgp as openpgp;
use openpgp::cert::amalgamation::ValidAmalgamation;
use openpgp::cert::ValidCert;
use openpgp::packet::UserID;
use openpgp::types::RevocationStatus;

use crate::Result;
use crate::cli::types::UserIDDesignators;
use crate::cli::types::userid_designator::AddEmailArg;
use crate::cli::types::userid_designator::AddUserIDArg;
use crate::cli::types::userid_designator::ResolvedUserID;
use crate::cli::types::userid_designator::UserIDDesignator;

impl<Arguments, Options> UserIDDesignators<Arguments, Options>
where
    Arguments: typenum::Unsigned,
{
    /// Resolve the user ID designators.
    ///
    /// If `--add-userid` is enabled, then this will return an error
    /// if a user ID that is not self-signed is designated.
    pub fn resolve(&self, vc: &ValidCert) -> Result<Vec<ResolvedUserID>> {
        let arguments = Arguments::to_usize();
        let add_userid_arg = (arguments & AddUserIDArg::to_usize()) > 0;
        let add_email_arg = (arguments & AddEmailArg::to_usize()) > 0;

        // Find the matching User IDs.
        let mut userids = Vec::new();

        // Don't stop at the first error.
        let mut missing = false;
        let mut ambiguous = false;
        let mut bad = None;

        if let Some(true) = self.all() {
            let all_userids = vc.userids()
                .filter_map(|ua| {
                    if let RevocationStatus::Revoked(_) = ua.revocation_status() {
                        None
                    } else {
                        Some(ua.userid().clone())
                    }
                })
                .map(|userid| ResolvedUserID::implicit(userid))
                .collect::<Vec<_>>();

            if all_userids.is_empty() {
                return Err(anyhow::anyhow!(
                    "{} has no valid self-signed user IDs",
                    vc.fingerprint()));
            }

            userids.extend(all_userids);
        }

        for designator in self.iter() {
            match designator {
                UserIDDesignator::UserID(userid) => {
                    let userid = UserID::from(&userid[..]);

                    if let Some(_) = vc.userids()
                        .find(|ua| {
                            ua.userid() == &userid
                        })
                    {
                        userids.push(designator.resolve_to(userid.clone()));
                    } else {
                        wprintln!("{:?} is not a self-signed user ID.",
                                  String::from_utf8_lossy(userid.value()));
                        missing = true;
                    }
                }
                UserIDDesignator::AnyUserID(userid)
                    | UserIDDesignator::AddUserID(userid) =>
                {
                    let userid = UserID::from(&userid[..]);
                    userids.push(designator.resolve_to(userid));
                }
                UserIDDesignator::Email(email)
                    | UserIDDesignator::AnyEmail(email)
                    | UserIDDesignator::AddEmail(email) =>
                {
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
                            if found {
                                wprintln!("{} is ambiguous: it matches \
                                           multiple self-signed user IDs.",
                                          email);
                                ambiguous = true;
                            }

                            userids.push(designator.clone()
                                         .resolve_to(ua.userid().clone()));
                            found = true;
                        }
                    }

                    if ! found {
                        if matches!(designator, UserIDDesignator::Email(_)) {
                            eprintln!("None of the self-signed user IDs \
                                       are for the email address {:?}.",
                                      email);
                            missing = true;
                        } else {
                            userids.push(
                                designator.clone().resolve_to(userid));
                        }
                    }
                }
            }
        }

        if missing || ambiguous {
            wprintln!("{}'s self-signed user IDs:", vc.fingerprint());
            let mut have_valid = false;
            for ua in vc.userids() {
                if let Ok(u) = std::str::from_utf8(ua.userid().value()) {
                    have_valid = true;
                    wprintln!("  - {:?}", u);
                }
            }
            if ! have_valid {
                wprintln!("  - Certificate has no valid self-signed user IDs.");
            }
        }

        if missing {
            if add_userid_arg && add_email_arg {
                wprintln!("Use `--add-userid` or `--add-email` to use \
                           a user ID even if it isn't self signed.");
            }
            return Err(anyhow::anyhow!("Not a self-signed user ID"));
        }
        if ambiguous {
            wprintln!("Use `--userid` with the full user ID, or \
                       `--add-userid` to add a new user ID.");
        }

        if let Some(err) = bad {
            return Err(err);
        }

        // Dedup while preserving order.
        let mut seen = HashSet::new();
        userids.retain(|userid| seen.insert(userid.userid().clone()));

        Ok(userids)
    }
}
