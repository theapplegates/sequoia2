use std::path::Path;

use anyhow::anyhow;
use anyhow::Result;

use openpgp::cert::CertParser;
use openpgp::parse::Parse;
use openpgp::policy::NullPolicy;
use openpgp::Cert;
use sequoia_openpgp as openpgp;

use crate::cli::types::FileOrStdin;
use crate::load_certs;

mod revoke;
pub use revoke::get_secret_signer;
pub use revoke::RevocationOutput;

mod password;
pub use password::prompt_for_password;

pub const NULL_POLICY: &NullPolicy = &NullPolicy::new();

/// Parse the cert from input and ensure it is only one cert.
pub fn read_cert(input: Option<&Path>) -> Result<Cert> {
    let input = FileOrStdin::from(input).open()?;

    let cert = CertParser::from_reader(input)?.collect::<Vec<_>>();
    let cert = match cert.len() {
        0 => Err(anyhow!("No certificates provided."))?,
        1 => cert.into_iter().next().expect("have one")?,
        _ => Err(anyhow!("Multiple certificates provided."))?,
    };
    Ok(cert)
}

/// Parse the secret key and ensure it is at most one.
pub fn read_secret(skf: Option<&Path>) -> Result<Option<Cert>> {
    let secret = load_certs(skf.into_iter())?;
    if secret.len() > 1 {
        Err(anyhow!("Multiple secret keys provided."))?;
    }
    let secret = secret.into_iter().next();
    Ok(secret)
}
