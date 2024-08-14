use sequoia_openpgp as openpgp;
use openpgp::packet::UserID;

/// A canonical user ID.
#[derive(thiserror::Error, Debug)]
pub enum UserIDLint {
    /// Not UTF-8 Encoded.
    #[error("{:?} is not UTF-8 encoded",
            String::from_utf8_lossy(.0.value()))]
    NotUTF8Encoded(UserID, #[source] std::str::Utf8Error),

    /// Not in canonical form.
    ///
    /// Canonical form is: `Display Name (Comment)
    /// <email@example.org>` where either the display name, comment or
    /// email address is required.
    #[error("{:?} is not in canonical form{}",
            String::from_utf8_lossy(.0.value()),
            .1.as_ref()
                .map(|u| {
                    format!(", try {:?}",
                            String::from_utf8_lossy(u.value()))
                })
            .unwrap_or_else(|| "".to_string()))]
    NotCanonical(UserID, Option<UserID>),

    /// Bare emails are technically in canonical form, but are not
    /// advisable.
    ///
    /// Bare emails are problematic, because regular expressions that
    /// match on email addresses usually assume the email address is
    /// in angle brackets.
    #[error("\"{}\" is a bare email address, try \"<{}>\"",
            String::from_utf8_lossy(.0.value()),
            String::from_utf8_lossy(.0.value()))]
    BareEmail(UserID),
}

/// Returns an error if the user ID is not in canonical form.
pub(crate) fn lint_userid(uid: &UserID)
    -> std::result::Result<(), UserIDLint>
{
    let mut components = Vec::new();

    let map_err = |err: anyhow::Error| {
        if let Ok(err) = err.downcast::<std::str::Utf8Error>() {
            return UserIDLint::NotUTF8Encoded(uid.clone(), err);
        }

        UserIDLint::NotCanonical(uid.clone(), None)
    };

    // Returning the name (or comment or email address) means
    // checking that the user ID is in canonical form.  Thus,
    // if this fails, the user ID is not in canonical form.
    if let Some(name) = uid.name2().map_err(map_err)? {
        components.push(name.to_string());
    }

    if let Some(comment) = uid.comment2().map_err(map_err)? {
        components.push(format!("({})", comment));
    }

    let email = if let Some(email) = uid.email2().map_err(map_err)? {
        components.push(format!("<{}>", email));
        Some(email)
    } else {
        None
    };

    let userid_canonical = UserID::from(components.join(" "));
    if &userid_canonical != uid {
        if email.map(|e| e.as_bytes()) == Some(&uid.value()) {
            // Bare email address.
            return Err(UserIDLint::BareEmail(uid.clone()));
        } else {
            return Err(UserIDLint::NotCanonical(
                uid.clone(), Some(userid_canonical)));
        }
    }

    Ok(())
}

/// Lints user IDs and displays the lints.
///
/// Returns an error if any of the user IDs have lints.
pub(crate) fn lint_userids(uids: &[UserID]) -> Result<(), anyhow::Error> {
    let mut non_canonical = Vec::new();
    for uid in uids.into_iter() {
        if let Err(err) = lint_userid(&uid) {
            non_canonical.push(err)
        }
    }

    if non_canonical.is_empty() {
        Ok(())
    } else {
        if non_canonical.len() == 1 {
            wprintln!("{}.", non_canonical[0]);
            eprintln!();
        } else {
            wprintln!("The following user IDs are not in canonical form:");
            eprintln!();
            for err in non_canonical.iter() {
                eprintln!("  - {}", err);
            }
            eprintln!();
        }

        let bare_email = non_canonical.iter()
            .filter_map(|err| {
                if let UserIDLint::BareEmail(uid) = err {
                    Some(uid.clone())
                } else {
                    None
                }
            })
            .next();

        wprintln!("Canonical user IDs are of the form \
                   `Name <localpart@example.org>`.  {}\
                   Consider fixing the user IDs or passing \
                   `--allow-non-canonical-userids`.",
                  if let Some(uid) = bare_email {
                      format!("Bare email addresses should be wrapped in angle \
                               brackets like so `<{}>`.  ",
                              String::from_utf8_lossy(uid.value()))
                  } else {
                      "".to_string()
                  });
        eprintln!();

        Err(anyhow::anyhow!("\
            Some user IDs are not in canonical form"))
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn userid_lint() {
        // Invalid UTF-8.
        match lint_userid(&UserID::from(vec![0, 159, 146, 150])) {
            Err(UserIDLint::NotUTF8Encoded(_, _)) => (),
            Err(err) => {
                panic!("User ID with invalid UTF-8 resulted in wrong error: {}",
                       err);
            }
            Ok(()) => {
                panic!("User ID with invalid UTF-8 was not rejected");
            }
        }

        // Bare email.
        match lint_userid(&UserID::from("alice@example.org")) {
            Err(UserIDLint::BareEmail(_)) => (),
            Err(err) => {
                panic!("User ID with bare email address \
                        resulted in wrong error: {}",
                       err);
            }
            Ok(()) => {
                panic!("User ID with bare email address was not rejected");
            }
        }

        for uid in [
            "<foo@bar@example.com>",
            "<foo@example.org",
        ].into_iter() {
            match lint_userid(&UserID::from(uid)) {
                Err(UserIDLint::NotCanonical(_, _)) => (),
                Err(err) => {
                    panic!("Non-canonical User ID ({}) \
                            resulted in wrong error: {}",
                           uid, err);
                }
                Ok(()) => {
                    panic!("Non-canonical User ID ({}) was not rejected",
                           uid);
                }
            }
        }
    }
}
