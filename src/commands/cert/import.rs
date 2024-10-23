use std::sync::Arc;
use std::path::PathBuf;

use buffered_reader::{BufferedReader, Dup};

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::raw::RawCertParser,
    Result,
    parse::{Cookie, Parse},
};

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;
use cert_store::StoreUpdate;

use crate::Sq;
use crate::cli::cert::import;
use crate::cli::types::FileOrStdin;
use crate::commands::autocrypt;
use crate::output::import::ImportStats;

pub fn dispatch<'store, 'rstore>(mut sq: Sq<'store, 'rstore>,
                                 cmd: import::Command)
    -> Result<()>
where 'store: 'rstore
{
    let inputs = if cmd.input.is_empty() {
        vec![ PathBuf::from("-") ]
    } else {
        cmd.input
    };

    let mut stats = ImportStats::default();

    let inner = || -> Result<()> {
        for input in inputs.into_iter() {
            let input = FileOrStdin::from(input);
            let mut input_reader = input.open()?;

            // First, try to import certs encoded as OpenPGP keyring.
            let mut st0 = ImportStats::default();
            let r0 = import_certs(
                &mut sq, &mut input_reader, input.path(), &mut st0);
            if r0.is_ok() {
                stats += st0;
                continue;
            }

            // Next, try to import certs encoded as Autocrypt headers.
            let r1 = autocrypt::import_certs(
                &mut sq, &mut input_reader, &mut stats);
            if r1.is_ok() {
                continue;
            }

            // Importing nothing used to be okay.  Preserve this.
            if input_reader.data_eof()?.is_empty() {
                return Ok(());
            }

            return r0;
        }

        Ok(())
    };

    let result = inner();

    wprintln!();
    stats.print_summary(&sq)?;

    Ok(result?)
}

/// Imports certs encoded as OpenPGP keyring.
fn import_certs(sq: &mut Sq,
                source: &mut Box<dyn BufferedReader<Cookie>>,
                source_path: Option<&PathBuf>,
                stats: &mut ImportStats)
                -> Result<()>
{
    let dup = Dup::with_cookie(source, Cookie::default());
    let raw_certs = RawCertParser::from_buffered_reader(dup)?;
    let cert_store = sq.cert_store_or_else()?;

    let mut one_ok = false;
    let mut errors = Vec::new();
    for raw_cert in raw_certs {
        let cert = match raw_cert
            .and_then(|raw| LazyCert::from(raw).to_cert().cloned())
        {
            Ok(cert) => {
                one_ok = true;
                cert
            },
            Err(err) => {
                errors.push(err);
                stats.certs.inc_errors();
                continue;
            }
        };

        if cert.is_tsk() {
            let mut cmd = sq.hint(format_args!(
                "Certificate {} contains secret key material.  \
                 To import keys, do:", cert.fingerprint()))
                .sq().arg("key").arg("import");

            if let Some(file) = source_path {
                cmd = cmd.arg(file.display());
            }

            cmd.done();
        }


        let fingerprint = cert.fingerprint();
        let sanitized_userid = sq.best_userid(&cert, true);
        if let Err(err) = cert_store.update_by(Arc::new(cert.into()),
                                               stats)
        {
            wprintln!("Error importing {}, {}: {}",
                      fingerprint, sanitized_userid, err);
            stats.certs.inc_errors();
            continue;
        } else {
            wprintln!("Imported {}, {}", fingerprint, sanitized_userid);
        }
    }

    if ! one_ok {
        // This likely wasn't a keyring.
        errors.reverse();
        Err(errors.pop().ok_or_else(|| anyhow::anyhow!("no cert found"))?)
    } else {
        for err in errors {
            wprintln!("Error parsing input: {}", err);
        }
        Ok(())
    }
}
