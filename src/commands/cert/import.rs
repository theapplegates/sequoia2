use std::sync::Arc;
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
};
use crate::cli::cert::import;
use crate::cli::types::FileOrStdin;


pub fn dispatch<'store, 'rstore>(config: Config<'store, 'rstore>,
                                 cmd: import::Command)
    -> Result<()>
where 'store: 'rstore
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
            let raw_certs = RawCertParser::from_buffered_reader(input)?;

            let policy = config.policy.clone();
            let time = config.time;
            let cert_store = config.cert_store_or_else()?;

            for raw_cert in raw_certs {
                let cert = match raw_cert {
                    Ok(raw_cert) => LazyCert::from(raw_cert),
                    Err(err) => {
                        wprintln!("Error parsing input: {}", err);
                        stats.inc_errors();
                        continue;
                    }
                };

                let fingerprint = cert.fingerprint();
                let sanitized_userid = best_effort_primary_uid(
                    Some(&config), cert.to_cert()?, &policy, time);
                if let Err(err) = cert_store.update_by(Arc::new(cert), &mut stats) {
                    wprintln!("Error importing {}, {}: {}",
                              fingerprint, sanitized_userid, err);
                    stats.inc_errors();
                    continue;
                } else {
                    wprintln!("Imported {}, {}", fingerprint, sanitized_userid);
                }
            }
        }

        Ok(())
    };

    let result = inner();

    wprintln!("Imported {} new certificates, updated {} certificates, \
               {} certificates unchanged, {} errors.",
              stats.new_certs(), stats.updated_certs(),
              stats.unchanged_certs(), stats.errors());

    Ok(result?)
}
