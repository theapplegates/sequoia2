//! Changes a key's password.

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Cert;

use crate::Result;
use crate::Sq;
use crate::cli;
use crate::common::key::get_keys;
use crate::common::key::password;

pub fn dispatch(sq: Sq, command: cli::key::password::Command)
                -> Result<()>
{
    let (cert, cert_source)
        = sq.resolve_cert(&command.cert, sequoia_wot::FULLY_TRUSTED)?;

    let vc = Cert::with_policy(&cert, sq.policy, sq.time)
        .with_context(|| {
            format!("The certificate {} is not valid under the \
                     current policy.",
                    cert.fingerprint())
        })?;

    let kas = vc.keys().collect::<Vec<_>>();
    let kas = kas.iter().collect::<Vec<_>>();

    let to_change = get_keys(&sq, &cert_source, &kas)?;

    password::password(sq, &cert, cert_source, to_change,
                       command.clear_password,
                       command.new_password_file.as_deref(),
                       command.output, false)
}
