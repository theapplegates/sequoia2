use std::sync::Arc;

use anyhow::Context;
use anyhow::Result;

use chrono::offset::Utc;
use chrono::DateTime;

use sequoia_openpgp as openpgp;
use openpgp::armor::Kind;
use openpgp::armor::Writer;
use openpgp::Cert;
use openpgp::crypto::Signer;
use openpgp::serialize::Serialize;

use sequoia_cert_store as cert_store;
use cert_store::StoreUpdate;
use cert_store::LazyCert;

use crate::cli::types::FileOrStdout;
use crate::Sq;
use crate::sq::GetKeysOptions;

/// A trait for unifying the approach of writing a revocation to an output
pub trait RevocationOutput {
    /// Returns a minimal version of the certificate including the
    /// revocation certificate.
    fn cert(&self) -> Result<Cert>;

    /// Returns a comment, which will be used as a header in the
    /// ASCII-armor output.
    ///
    /// This should be of the form:
    ///
    /// ```
    /// Includes a revocation certificate for User ID $userid
    /// ```
    fn comment(&self) -> String;

    /// Returns the revoker's certificate.
    fn revoker(&self) -> &Cert;

    /// Write out the revocation certificate.
    fn write(&self, sq: &Sq, output: Option<FileOrStdout>, binary: bool)
        -> Result<()>
    {
        if let Some(output) = output {
            let mut output = output.create_safe(sq.force)?;

            // First, build a minimal revocation certificate containing
            // the primary key, the revoked component, and the revocation
            // signature.
            let cert = self.cert()?;

            if binary {
                cert.serialize(&mut output)
                    .context("serializing revocation certificate")?;
            } else {
                // Add some more helpful ASCII-armor comments.
                let mut more: Vec<String> = vec![];

                // First, the thing that is being revoked.
                more.push(self.comment());

                let revoker = self.revoker();

                let first_party_issuer = revoker.fingerprint() == cert.fingerprint();
                if ! first_party_issuer {
                    // Then if it was issued by a third-party.
                    more.push("issued by".to_string());
                    more.push(revoker.fingerprint().to_spaced_hex());
                    // This information may be published so only consider
                    // self-signed user IDs to avoid leaking information
                    // about the user's web of trust.
                    let sanitized_uid = sq.best_userid(revoker, false);
                    // Truncate it, if it is too long.
                    more.push(format!("{:.70}", sanitized_uid));
                }

                let headers = &cert.armor_headers();
                let headers: Vec<(&str, &str)> = headers
                    .iter()
                    .map(|s| ("Comment", s.as_str()))
                    .chain(more.iter().map(|value| ("Comment", value.as_str())))
                    .collect();

                let mut writer =
                    Writer::with_headers(&mut output, Kind::PublicKey, headers)?;
                cert.serialize(&mut writer)
                    .context("serializing revocation certificate")?;
                writer.finalize()?;
            }
        } else {
            let cert_store = sq.cert_store_or_else()?;
            let cert = self.cert()?;
            cert_store.update(Arc::new(LazyCert::from(cert)))
                .with_context(|| {
                    "Error importing the revocation certificate into cert store"
                })?;
        }

        Ok(())
    }
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
    let flags = Some(&[
        GetKeysOptions::AllowRevoked,
        GetKeysOptions::AllowNotAlive,
        GetKeysOptions::NullPolicy,
    ][..]);

    if let Some(secret) = secret {
        match sq.get_primary_key(secret, flags) {
            Ok(key) => Ok((secret.clone(), key)),
            Err(err) => {
                if ! sq.time_is_now {
                    return Err(err.context(format!("\
No certification key found: the key specified with --revocation-file \
does not contain a certification key with secret key material.  \
Perhaps this is because no certification keys are valid at the time \
you specified ({})",
                        DateTime::<Utc>::from(sq.time))));
                } else {
                    return Err(err.context(format!("\
No certification key found: the key specified with --revocation-file \
does not contain a certification key with secret key material")));
                }
            }
        }
    } else {
        match sq.get_primary_key(cert, flags) {
            Ok(key) => Ok((cert.clone(), key)),
            Err(err) => {
                if ! sq.time_is_now {
                    return Err(err.context(format!("\
No certification key found: --revocation-file not provided and the
certificate to revoke does not contain a certification key with secret
key material.  Perhaps this is because no certification keys are valid at
the time you specified ({})",
                        DateTime::<Utc>::from(sq.time))));
                } else {
                    return Err(err.context(format!("\
No certification key found: --revocation-file not provided and the
certificate to revoke does not contain a certification key with secret
key material")));
                }
            }
        }
    }
}
