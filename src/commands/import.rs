use std::borrow::Cow;

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
    open_or_stdin,
};

use crate::sq_cli::import;

pub fn dispatch<'store>(mut config: Config<'store>, cmd: import::Command)
    -> Result<()>
{
    let inputs = if cmd.input.is_empty() {
        vec![ "-".to_string() ]
    } else {
        cmd.input
    };

    let mut stats = cert_store::store::MergePublicCollectStats::new();

    let inner = || -> Result<()> {
        for input in inputs.into_iter() {
            let input = open_or_stdin(
                if input == "-" { None } else { Some(&input) })?;
            let raw_certs = RawCertParser::from_reader(input)?;

            let cert_store = config.cert_store_mut_or_else()?;

            for raw_cert in raw_certs {
                let cert = match raw_cert {
                    Ok(raw_cert) => LazyCert::from(raw_cert),
                    Err(err) => {
                        eprintln!("Error parsing input: {}", err);
                        stats.errors += 1;
                        continue;
                    }
                };

                let fingerprint = cert.fingerprint();
                if let Err(err) = cert_store.update_by(Cow::Owned(cert), &mut stats) {
                    eprintln!("Error importing {}: {}", fingerprint, err);
                    stats.errors += 1;
                    continue;
                }
            }
        }

        Ok(())
    };

    let result = inner();

    eprintln!("Imported {} new certificates, updated {} certificates, \
               {} certificates unchanged, {} errors.",
              stats.new, stats.updated, stats.unchanged, stats.errors);

    Ok(result?)
}
