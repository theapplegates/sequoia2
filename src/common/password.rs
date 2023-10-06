use openpgp::crypto::Password;
use openpgp::Result;
use rpassword::prompt_password;
use sequoia_openpgp as openpgp;

/// Prompts twice for a new password and returns an optional [`Password`].
///
/// Prompts twice for comparison and only returns a [`Password`] in a [`Result`]
/// if both inputs match and are not empty.
/// Returns [`None`](Option::None), if the password is empty.
pub fn prompt_for_password(
    prompt: &str,
    prompt_repeat: Option<&str>,
) -> Result<Option<Password>> {
    let password = prompt_password(prompt)?;
    let password_repeat = match prompt_repeat {
        Some(prompt_repeat) => prompt_password(prompt_repeat)?,
        None => prompt_password(format!("Repeat: {}", prompt))?,
    };

    if password != password_repeat {
        return Err(anyhow::anyhow!("The passwords do not match!"));
    }

    if password.is_empty() {
        Ok(None)
    } else {
        Ok(Some(password.into()))
    }
}
