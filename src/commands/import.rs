use std::borrow::Cow;
use std::path::PathBuf;

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::raw::RawCertParser,
    Result,
    parse::Parse,
};

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;
use cert_store::StoreUpdate;

use crate::{
    Config,
    best_effort_primary_uid,
    output::sanitize::Safe,
};
use crate::cli::import;
use crate::cli::types::FileOrStdin;


pub fn dispatch<'store>(mut config: Config<'store>, cmd: import::Command)
    -> Result<()>
{
    let inputs = if cmd.input.is_empty() {
        vec![ PathBuf::from("-") ]
    } else {
        cmd.input
    };

    let mut stats = cert_store::store::MergePublicCollectStats::new();

    let inner = || -> Result<()> {
        for input in inputs.into_iter() {
            let input = FileOrStdin::from(input).open()?;
            let raw_certs = RawCertParser::from_reader(input)?;

            let policy = config.policy.clone();
            let time = config.time;
            let cert_store = config.cert_store_mut_or_else()?;

            for raw_cert in raw_certs {
                let cert = match raw_cert {
                    Ok(raw_cert) => LazyCert::from(raw_cert),
                    Err(err) => {
                        wprintln!("Error parsing input: {}", err);
                        stats.errors += 1;
                        continue;
                    }
                };

                let fingerprint = cert.fingerprint();
                let userid = best_effort_primary_uid(
                    cert.to_cert()?, &policy, time).clone();
                if let Err(err) = cert_store.update_by(Cow::Owned(cert), &mut stats) {
                    wprintln!("Error importing {}, {:?}: {}",
                              fingerprint, userid, err);
                    stats.errors += 1;
                    continue;
                } else {
                    wprintln!("Imported {}, {}", fingerprint, Safe(&userid));
                }
            }
        }

        Ok(())
    };

    let result = inner();

    wprintln!("Imported {} new certificates, updated {} certificates, \
               {} certificates unchanged, {} errors.",
              stats.new, stats.updated, stats.unchanged, stats.errors);

    Ok(result?)
}
