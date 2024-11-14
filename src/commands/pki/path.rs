use sequoia_openpgp as openpgp;
use openpgp::Result;

use anyhow::Context;

use sequoia_wot as wot;

use crate::Sq;
use crate::cli::pki::PathCommand;
use crate::commands::pki::print_path;
use crate::commands::pki::print_path_error;
use crate::commands::pki::print_path_header;
use crate::commands::pki::required_trust_amount;

pub fn path(sq: Sq, c: PathCommand)
    -> Result<()>
{
    let PathCommand {
        certification_network, trust_amount, path,
    } = c;

    // Build the network.
    let cert_store = match sq.cert_store() {
        Ok(Some(cert_store)) => cert_store,
        Ok(None) => {
            return Err(anyhow::anyhow!("Certificate store has been disabled"));
        }
        Err(err) => {
            return Err(err).context("Opening certificate store");
        }
    };

    let mut n = wot::NetworkBuilder::rooted(cert_store, &*sq.trust_roots());
    if *certification_network {
        n = n.certification_network();
    }
    let q = n.build();

    let required_amount =
        required_trust_amount(*trust_amount, *certification_network)?;

    let (khs, userid) = (path.certs()?, path.userid()?);
    assert!(khs.len() > 0, "guaranteed by clap");

    let r = q.lint_path(&khs, &userid, required_amount, sq.policy);

    let target_kh = khs.last().expect("have one");

    let trust_amount = match r {
        Ok(path) => {
            print_path_header(
                target_kh,
                &userid,
                path.amount(),
                required_amount,
            );
            print_path(&path, &userid, "  ")?;

            let trust_amount = path.amount();
            if trust_amount >= required_amount {
                return Ok(());
            }

            trust_amount
        }
        Err(err) => {
            print_path_header(
                target_kh,
                &userid,
                0,
                required_amount,
            );

            print_path_error(err);

            0
        }
    };

    Err(anyhow::anyhow!(
        "The path is not sufficient to authenticate the binding.  \
         Its trust amount is {}, but a trust amount of {} is required.",
        trust_amount, required_amount))
}
