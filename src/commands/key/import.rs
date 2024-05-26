use sequoia_openpgp as openpgp;
use openpgp::cert::CertParser;
use openpgp::parse::Parse;

use crate::best_effort_primary_uid;
use crate::cli;
use crate::Sq;
use crate::ImportStatus;
use crate::Result;

pub fn import(sq: Sq, command: cli::key::ImportCommand) -> Result<()> {
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
                             best_effort_primary_uid(
                                 Some(&sq), &cert, sq.policy,
                                 sq.time));

            match sq.import_key(cert) {
                Ok(ImportStatus::New) => {
                    wprintln!("Imported {} from {}: new",
                              id, file.display());
                }
                Ok(ImportStatus::Unchanged) => {
                    wprintln!("Imported {} from {}: unchanged",
                              id, file.display());
                }
                Ok(ImportStatus::Updated) => {
                    wprintln!("Imported {} from {}: updated",
                              id, file.display());
                }
                Err(err) => {
                    wprintln!("Error importing {} from {}: {}",
                              id, file.display(), err);
                    if ret.is_ok() {
                        ret = Err(err);
                    }
                }
            }
        }
    }

    ret
}
