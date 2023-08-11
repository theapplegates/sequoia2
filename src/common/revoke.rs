use std::time::SystemTime;

use anyhow::anyhow;
use anyhow::Result;

use chrono::offset::Utc;
use chrono::DateTime;

use openpgp::crypto::Signer;
use openpgp::policy::Policy;
use openpgp::Cert;
use sequoia_openpgp as openpgp;

use crate::commands::get_certification_keys;
use crate::sq_cli::types::FileOrStdout;

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
    cert: &'a Cert,
    policy: &dyn Policy,
    secret: Option<&'a Cert>,
    private_key_store: Option<&str>,
    time: Option<SystemTime>,
) -> Result<(Cert, Box<dyn Signer + Send + Sync>)> {
    if let Some(secret) = secret {
        if let Ok(keys) = get_certification_keys(
            &[secret.clone()],
            policy,
            private_key_store,
            time,
            None,
        ) {
            assert!(
                keys.len() == 1,
                "Expect exactly one result from get_certification_keys()"
            );
            Ok((secret.clone(), keys.into_iter().next().expect("have one").0))
        } else {
            if let Some(time) = time {
                return Err(anyhow!(
                    "\
No certification key found: the key specified with --revocation-file \
does not contain a certification key with secret key material.  \
Perhaps this is because no certification keys are valid at the time \
you specified ({})",
                    DateTime::<Utc>::from(time)
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
        if let Ok(keys) = get_certification_keys(
            &[cert],
            policy,
            private_key_store,
            time,
            None,
        ) {
            assert!(
                keys.len() == 1,
                "Expect exactly one result from get_certification_keys()"
            );
            Ok((cert.clone(), keys.into_iter().next().expect("have one").0))
        } else {
            if let Some(time) = time {
                return Err(anyhow!(
                    "\
No certification key found: --revocation-file not provided and the
certificate to revoke does not contain a certification key with secret
key material.  Perhaps this is because no certification keys are valid at
the time you specified ({})",
                    DateTime::<Utc>::from(time)
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
