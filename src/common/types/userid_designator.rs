use std::collections::BTreeSet;
use std::collections::HashSet;

use typenum::Unsigned;

use sequoia_openpgp as openpgp;
use openpgp::cert::amalgamation::ValidAmalgamation;
use openpgp::cert::ValidCert;
use openpgp::packet::UserID;
use openpgp::types::RevocationStatus;
use openpgp::cert::amalgamation::ValidateAmalgamation;

use crate::Result;
use crate::cli::types::UserIDDesignators;
use crate::cli::types::userid_designator::AddEmailArg;
use crate::cli::types::userid_designator::AddUserIDArg;
use crate::cli::types::userid_designator::ResolvedUserID;
use crate::cli::types::userid_designator::UserIDDesignator;
use crate::common::userid::lint_email;
use crate::common::userid::lint_name;
use crate::common::userid::lint_userid;
use crate::sq::NULL_POLICY;

impl<Arguments, Options> UserIDDesignators<Arguments, Options>
where
    Arguments: typenum::Unsigned,
{
    /// Resolve the user ID designators.
    ///
    /// We first match on self-signed user IDs.  We return an error if
    /// a match is ambiguous (e.g., when matching on an email address,
    /// and there are multiple user IDs with the specified email
    /// address).
    ///
    /// If there are no matches, and we don't require a match (e.g.,
    /// UserIDArg, EmailArg, NameArg), then we create a new user ID.
    ///
    /// This will match on revoked user IDs.
    ///
    /// When `--all` is provided, returns all non-revoked, self-signed
    /// user IDs.  If there are none, an error is returned.
    ///
    /// The returned `ResolvedUserID` are deduped by user ID.  That
    /// is, if multiple designators resolve to the same user ID, only
    /// one is kept.
    pub fn resolve(&self, vc: &ValidCert) -> Result<Vec<ResolvedUserID>> {
        let arguments = Arguments::to_usize();
        let add_userid_arg = (arguments & AddUserIDArg::to_usize()) > 0;
        let add_email_arg = (arguments & AddEmailArg::to_usize()) > 0;

        // Find the matching User IDs.
        let mut userids = Vec::new();

        // Don't stop at the first error.
        let mut missing = false;
        let mut ambiguous_email = false;
        let mut ambiguous_name = false;
        let mut bad = None;

        if let Some(true) = self.all() {
            let mut revoked_userids = BTreeSet::new();
            let valid_userids = vc.userids()
                .filter_map(|ua| {
                    if let RevocationStatus::Revoked(_) = ua.revocation_status() {
                        revoked_userids.insert(ua.userid());
                        None
                    } else {
                        Some(ua.userid().clone())
                    }
                })
                .collect::<BTreeSet<_>>();

            let non_self_signed_userids = vc.cert().userids()
                .filter(|_| self.all_matches_non_self_signed())
                .filter(|u| ! revoked_userids.contains(u.userid()))
                .filter(|u| ! valid_userids.contains(u.userid()))
                .map(|u| u.userid().clone())
                .collect::<Vec<_>>();

            let all_userids = valid_userids.into_iter()
                .chain(non_self_signed_userids.into_iter())
                .map(|userid| ResolvedUserID::implicit(userid))
                .collect::<Vec<_>>();

            if all_userids.is_empty() {
                return Err(anyhow::anyhow!(
                    "{} has no {}user IDs",
                    vc.fingerprint(),
                    if self.all_matches_non_self_signed() {
                        ""
                    } else {
                        "valid self-signed "
                    }));
            }

            userids.extend(all_userids);
        }

        for designator in self.iter() {
            match designator {
                UserIDDesignator::UserID(userid)
                    | UserIDDesignator::AnyUserID(userid)
                    | UserIDDesignator::AddUserID(userid) =>
                {
                    let userid = UserID::from(&userid[..]);

                    if let Some(_) = vc.userids()
                        .find(|ua| {
                            ua.userid() == &userid
                        })
                    {
                        userids.push(designator.resolve_to(userid.clone()));
                    } else if matches!(designator,
                                       UserIDDesignator::AnyUserID(_)
                                       | UserIDDesignator::AddUserID(_))
                    {
                        if ! self.allow_non_canonical_userids {
                            // We're going to add a user ID.  Lint it
                            // first.
                            lint_userid(&userid)?;
                        }
                        userids.push(designator.resolve_to(userid));
                    } else {
                        weprintln!("{:?} is not a self-signed user ID.",
                                   String::from_utf8_lossy(userid.value()));
                        missing = true;
                    }
                }
                UserIDDesignator::Email(email)
                    | UserIDDesignator::AnyEmail(email)
                    | UserIDDesignator::AddEmail(email) =>
                {
                    // Validate the email address.
                    let userid = match UserID::from_address(None, None, email) {
                        Ok(userid) => userid,
                        Err(err) => {
                            weprintln!("{:?} is not a valid email address: {}",
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
                            weprintln!("{:?} is not a valid email address", email);
                            bad = Some(anyhow::anyhow!(format!(
                                "{:?} is not a valid email address", email)));
                            continue;
                        }
                        Err(err) => {
                            weprintln!("{:?} is not a valid email address: {}",
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
                                weprintln!("{} is ambiguous: it matches \
                                            multiple self-signed user IDs.",
                                           email);
                                ambiguous_email = true;
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
                            if ! self.allow_non_canonical_userids {
                                // We're going to add a user ID.  Lint it
                                // first.
                                lint_email(email)?;
                            }
                            userids.push(
                                designator.clone().resolve_to(userid));
                        }
                    }
                }
                UserIDDesignator::Name(name)
                    | UserIDDesignator::AnyName(name)
                    | UserIDDesignator::AddName(name) =>
                {
                    let userid = UserID::from(&name[..]);
                    if userid.name2().ok() != Some(Some(&name[..])) {
                        let err = format!("{:?} is not a valid display name",
                                          name);
                        weprintln!("{}", err);
                        bad = Some(anyhow::anyhow!(err));
                        continue;
                    };

                    let mut found = false;
                    for ua in vc.userids() {
                        if let Ok(Some(n)) = ua.userid().name2() {
                            if n == name {
                                if found {
                                    weprintln!("{:?} is ambiguous: it matches \
                                                multiple self-signed user IDs.",
                                               name);
                                    ambiguous_name = true;
                                }

                                userids.push(designator.clone()
                                             .resolve_to(ua.userid().clone()));
                                found = true;
                            }
                        }
                    }

                    if ! found {
                        if matches!(designator, UserIDDesignator::Name(_)) {
                            eprintln!("None of the self-signed user IDs \
                                       are for the display name {:?}.",
                                      name);
                            missing = true;
                        } else {
                            if ! self.allow_non_canonical_userids {
                                // We're going to add a user ID.  Lint it
                                // first.
                                lint_name(&name[..])?;
                            }
                            userids.push(designator.resolve_to(
                                UserID::from(&name[..])));
                        }
                    }
                }
            }
        }

        if missing || ambiguous_email || ambiguous_name {
            weprintln!("{}'s self-signed user IDs:", vc.fingerprint());
            let mut have_valid = false;
            for ua in vc.userids() {
                if let Ok(u) = std::str::from_utf8(ua.userid().value()) {
                    have_valid = true;
                    weprintln!(initial_indent="  - ",
                               subsequent_indent="    ",
                               "{:?}", u);
                }
            }
            if ! have_valid {
                weprintln!("  - Certificate has no valid self-signed user IDs.");
            }

            if let Ok(null) = vc.clone().with_policy(&NULL_POLICY, vc.time()) {
                if vc.userids().count() < null.userids().count() {
                    weprintln!("Invalid self-signed user IDs:");
                    let valid: BTreeSet<_>
                        = vc.userids().map(|ua| ua.userid().clone()).collect();
                    for ua in null.userids() {
                        if valid.contains(ua.userid()) {
                            continue;
                        }

                        if let Ok(u) = std::str::from_utf8(ua.userid().value()) {
                            if let Err(err) = ua.with_policy(vc.policy(), vc.time()) {
                                weprintln!(initial_indent="  - ",
                                           subsequent_indent="    ",
                                           "{:?}: {}", u, err);
                            }
                        }
                    }
                }
            }
        }

        if missing {
            if add_userid_arg && add_email_arg {
                weprintln!("Use `--userid-or-add` or `--email-or-add` to use \
                            a user ID even if it isn't self signed, or has \
                            an invalid self signature.");
            }
            return Err(anyhow::anyhow!("No matching self-signed user ID"));
        }
        if ambiguous_email {
            weprintln!("Use `--userid` with the full user ID, or \
                        `--userid-or-add` to add a new user ID.");
            return Err(anyhow::anyhow!("\
                An email address does not unambiguously designate a \
                self-signed user ID"));
        }
        if ambiguous_name {
            weprintln!("Use `--userid` with the full user ID, or \
                        `--userid-or-add` to add a new user ID.");
            return Err(anyhow::anyhow!("\
                A name does not unambiguously designate a \
                self-signed user ID"));
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
