use openpgp::crypto::Password;
use openpgp::Result;
use rpassword::prompt_password;
use sequoia_openpgp as openpgp;

/// Prompt to repeat a password.
const REPEAT_PROMPT: &str = "Repeat password";

/// Prompts twice for a new password and returns an optional [`Password`].
///
/// Prompts twice for comparison and only returns a [`Password`] in a [`Result`]
/// if both inputs match and are not empty.
/// Returns [`None`](Option::None), if the password is empty.
pub fn prompt_for_password(
    prompt: &str,
) -> Result<Option<Password>> {
    let width = prompt.len().max(REPEAT_PROMPT.len());
    let p0 = format!("{:>1$}: ", prompt, width);
    let p1 = format!("{:>1$}: ", REPEAT_PROMPT, width);
    let password = prompt_password(&p0)?;
    let password_repeat = prompt_password(&p1)?;

    if password != password_repeat {
        return Err(anyhow::anyhow!("The passwords do not match!"));
    }

    if password.is_empty() {
        Ok(None)
    } else {
        Ok(Some(password.into()))
    }
}
