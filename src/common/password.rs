//! Common password-related functionality such as prompting.

use openpgp::crypto::Password;
use openpgp::Result;
use rpassword::prompt_password;
use sequoia_openpgp as openpgp;

/// Prompt to repeat a password.
const REPEAT_PROMPT: &str = "Please repeat the password";

/// Prompts twice for a new password and returns an optional [`Password`].
///
/// This function is intended for creating artifacts.  For example, if
/// a new key or subkey is generated, or a message should be encrypted
/// using a password.  The cost of mistyping is high, so we prompt
/// twice.
///
/// If the two entered passwords match, the result is returned.  If
/// the password was the empty string, `None` is returned.
///
/// If the passwords differ, an error message is printed and the
/// process is repeated.
pub fn prompt_for_new(
    reason: &str,
) -> Result<Option<Password>> {
    let prompt = format!("Please enter the password to protect {} \
                          (press enter to not use a password)", reason);
    let width = prompt.len().max(REPEAT_PROMPT.len());
    let p0 = format!("{:>1$}: ", prompt, width);
    let p1 = format!("{:>1$}: ", REPEAT_PROMPT, width);

    loop {
        let password = prompt_password(&p0)?;
        let password_repeat = prompt_password(&p1)?;

        if password != password_repeat {
            wprintln!("The passwords do not match.  Please try again.");
            wprintln!();
            continue;
        }

        return if password.is_empty() {
            Ok(None)
        } else {
            Ok(Some(password.into()))
        };
    }
}

/// Prompts once for a password to unlock an existing object.
///
/// This function is intended for consuming artifacts.  For example,
/// if a key or subkey is locked and must be unlocked, or a message
/// should be decrypted using a password.
pub fn prompt_to_unlock(reason: &str) -> Result<Password> {
    let prompt =
        format!("Please enter the password to decrypt {}: ", reason);
    let password = prompt_password(&prompt)?;
    Ok(password.into())
}

/// Prompts once for a password to unlock an existing object.
///
/// This function is intended for consuming artifacts.  For example,
/// if a key or subkey is locked and must be unlocked, or a message
/// should be decrypted using a password.
pub fn prompt_to_unlock_or_cancel(reason: &str) -> Result<Option<Password>> {
    let password = prompt_to_unlock(&format!("{} (blank to skip)", reason))?;
    Ok(if password.map(|p| p.is_empty()) { None } else { Some(password) })
}
