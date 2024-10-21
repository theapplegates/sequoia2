use std::sync::Arc;
use std::path::PathBuf;

use buffered_reader::Dup;

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::raw::RawCertParser,
    Result,
    parse::Parse,
};

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;
use cert_store::StoreUpdate;

use crate::Sq;
use crate::cli::cert::import;
use crate::cli::types::FileOrStdin;


pub fn dispatch<'store, 'rstore>(sq: Sq<'store, 'rstore>,
                                 cmd: import::Command)
    -> Result<()>
where 'store: 'rstore
{
    let inputs = if cmd.input.is_empty() {
        vec![ PathBuf::from("-") ]
    } else {
        cmd.input
    };

    let mut stats = crate::output::import::ImportStats::default();

    let inner = || -> Result<()> {
        for input in inputs.into_iter() {
            let input = FileOrStdin::from(input);
            let mut input_reader = input.open()?;
            let dup =
                Dup::with_cookie(&mut input_reader, Default::default());
            let raw_certs =
                RawCertParser::from_buffered_reader(dup)?;

            let cert_store = sq.cert_store_or_else()?;

            for raw_cert in raw_certs {
                let cert = match raw_cert
                    .and_then(|raw| LazyCert::from(raw).to_cert().cloned())
                {
                    Ok(cert) => cert,
                    Err(err) => {
                        wprintln!("Error parsing input: {}", err);
                        stats.certs.inc_errors();
                        continue;
                    }
                };

                if cert.is_tsk() {
                    let mut cmd = sq.hint(format_args!(
                        "Certificate {} contains secret key material.  \
                         To import keys, do:", cert.fingerprint()))
                        .sq().arg("key").arg("import");

                    if let Some(file) = input.path() {
                        cmd = cmd.arg(file.display());
                    }

                    cmd.done();
                }


                let fingerprint = cert.fingerprint();
                let sanitized_userid = sq.best_userid(&cert, true);
                if let Err(err) = cert_store.update_by(Arc::new(cert.into()),
                                                       &mut stats)
                {
                    wprintln!("Error importing {}, {}: {}",
                              fingerprint, sanitized_userid, err);
                    stats.certs.inc_errors();
                    continue;
                } else {
                    wprintln!("Imported {}, {}", fingerprint, sanitized_userid);
                }
            }
        }

        Ok(())
    };

    let result = inner();

    stats.print_summary()?;

    Ok(result?)
}
