use anyhow::anyhow;
use anyhow::Result;

use chrono::offset::Utc;
use chrono::DateTime;

use openpgp::crypto::Signer;
use openpgp::Cert;
use sequoia_openpgp as openpgp;

use crate::cli::types::FileOrStdout;
use crate::Sq;

/// A trait for unifying the approach of writing a revocation to an output
pub trait RevocationOutput {
    fn write(
        &self,
        output: FileOrStdout,
        binary: bool,
        force: bool,
    ) -> Result<()>;
}

/// Get secret Cert and Signer from an optional secret Cert or a Cert
///
/// Returns a secret Cert and the corresponding Signer, derived from `secret`,
/// if `secret` is `Some`, else attempts to derive it from `cert`.
///
/// ## Errors
///
/// - Returns an `Error` if `secret` is `Some`, but no suitable certification key
/// can be derived from it.
/// - Returns an `Error` if `secret` is `None` and no suitable certification key
/// can be derived from `cert`.
pub fn get_secret_signer<'a>(
    sq: &'a Sq,
    cert: &'a Cert,
    secret: Option<&'a Cert>,
) -> Result<(Cert, Box<dyn Signer + Send + Sync>)> {
    if let Some(secret) = secret {
        if let Ok((key, _password)) = sq.get_primary_key(secret, None) {
            Ok((secret.clone(), key))
        } else {
            if ! sq.time_is_now {
                return Err(anyhow!(
                    "\
No certification key found: the key specified with --revocation-file \
does not contain a certification key with secret key material.  \
Perhaps this is because no certification keys are valid at the time \
you specified ({})",
                    DateTime::<Utc>::from(sq.time)
                ));
            } else {
                return Err(anyhow!(
                    "\
No certification key found: the key specified with --revocation-file \
does not contain a certification key with secret key material"
                ));
            }
        }
    } else {
        if let Ok((key, _password)) = sq.get_primary_key(cert, None) {
            Ok((cert.clone(), key))
        } else {
            if ! sq.time_is_now {
                return Err(anyhow!(
                    "\
No certification key found: --revocation-file not provided and the
certificate to revoke does not contain a certification key with secret
key material.  Perhaps this is because no certification keys are valid at
the time you specified ({})",
                    DateTime::<Utc>::from(sq.time)
                ));
            } else {
                return Err(anyhow!(
                    "\
No certification key found: --revocation-file not provided and the
certificate to revoke does not contain a certification key with secret
key material"
                ));
            }
        }
    }
}
