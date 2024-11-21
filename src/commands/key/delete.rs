//! Deletes all of a certificate's secret key material.

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Cert;

use crate::Result;
use crate::Sq;
use crate::cli;
use crate::common::key::delete;

pub fn dispatch(sq: Sq, command: cli::key::delete::Command)
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

    delete::delete(sq, &cert, cert_source, &kas,
                   command.output, false)
}
