use sequoia_openpgp as openpgp;
use openpgp::cert::CertParser;
use openpgp::parse::Parse;

use crate::output::import::ImportStats;

use crate::cli;
use crate::Sq;
use crate::Result;

pub fn import(sq: Sq, command: cli::key::ImportCommand) -> Result<()> {
    let mut stats = Default::default();
    let r = import_internal(sq, command, &mut stats);
    stats.print_summary()?;
    r
}

fn import_internal(sq: Sq, command: cli::key::ImportCommand,
                   stats: &mut ImportStats)
                   -> Result<()>
{
    // Return the first error.
    let mut ret = Ok(());

    for file in command.file {
        for r in CertParser::from_file(&file)? {
            let cert = match r {
                Ok(cert) => cert,
                Err(err) => {
                    wprintln!("Error reading {}: {}", file.display(), err);
                    if ret.is_ok() {
                        ret = Err(err);
                    }
                    continue;
                }
            };

            let id = format!("{} {}",
                             cert.fingerprint(),
                             sq.best_userid(&cert, true));

            let cert_is_tsk = cert.is_tsk();
            match sq.import_key(cert, stats) {
                Ok((key, cert)) => {
                    wprintln!("Imported {} from {}: {}",
                              id, file.display(),
                              if key == cert {
                                  key.to_string()
                              } else {
                                  format!("key {}, cert {}", key, cert)
                              });

                }

                Err(err) => {
                    wprintln!("Error importing {} from {}: {}",
                              id, file.display(), err);

                    if ! cert_is_tsk {
                        sq.hint(format_args!(
                            "To import certificates, do:"))
                            .sq().arg("cert").arg("import")
                            .arg(file.display())
                            .done();
                    }

                    if ret.is_ok() {
                        ret = Err(err);
                    }
                }
            }
        }
    }

    ret
}
