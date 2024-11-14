use sequoia_openpgp as openpgp;
use openpgp::Result;

use anyhow::Context;

use sequoia_wot as wot;

use crate::Sq;
use crate::cli::pki::path::Command;
use crate::commands::pki::print_path;
use crate::commands::pki::print_path_error;
use crate::commands::pki::print_path_header;
use crate::commands::pki::required_trust_amount;

pub fn path(sq: Sq, c: Command)
    -> Result<()>
{
    let Command {
        certification_network, trust_amount, path, userids,
    } = c;

    assert_eq!(userids.len(), 1, "guaranteed by clap");

    let target = path.last().expect("guaranteed by clap");
    let mut userid = None;
    if let Ok(cert) = sq.lookup_one(target, None, false) {
        if let Ok(vc) = cert.with_policy(sq.policy, sq.time) {
            if let Ok(userids) = userids.resolve(&vc) {
                assert_eq!(userids.len(), 1);
                userid = Some(userids.into_iter().next().unwrap());
            }
        }
    }
    let userid = userid.unwrap_or_else(|| {
        userids.iter().next().unwrap().resolve_to_self()
    });

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

    assert!(path.len() > 0, "guaranteed by clap");

    let r = q.lint_path(&path, userid.userid(), required_amount, sq.policy);

    let target_kh = path.last().expect("have one");

    let trust_amount = match r {
        Ok(path) => {
            print_path_header(
                target_kh,
                userid.userid(),
                path.amount(),
                required_amount,
            );
            print_path(&path, userid.userid(), "  ")?;

            let trust_amount = path.amount();
            if trust_amount >= required_amount {
                return Ok(());
            }

            trust_amount
        }
        Err(err) => {
            print_path_header(
                target_kh,
                userid.userid(),
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
