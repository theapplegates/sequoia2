use std::fs::File;
use std::sync::Arc;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::cert::CertParser;
use openpgp::parse::Parse;
use openpgp::serialize::Serialize;

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;
use cert_store::StoreUpdate;

use crate::best_effort_primary_uid;
use crate::cli;
use crate::Config;
use crate::Result;

pub fn import(mut config: Config, command: cli::key::ImportCommand) -> Result<()> {
    let softkeys = config.key_store_path_or_else()?
        .join("keystore").join("softkeys");

    std::fs::create_dir_all(&softkeys)?;

    for file in command.file {
        for cert in CertParser::from_file(&file)? {
            let mut cert = cert.with_context(|| {
                format!("While reading {}", file.display())
            })?;

            let id = format!("{} {}",
                             cert.fingerprint(),
                             best_effort_primary_uid(
                                 &cert, &config.policy, config.time));

            config.info(format_args!(
                "Importing {} from {}", id, file.display()));

            if ! cert.is_tsk() {
                wprintln!("Skipping {}: no secret key material", id);
                continue;
            }

            let filename = softkeys.join(format!("{}.pgp", cert.fingerprint()));

            let mut update = false;
            match Cert::from_file(&filename) {
                Ok(old) => {
                    if old.fingerprint() != cert.fingerprint() {
                        return Err(anyhow::anyhow!(
                            "{} contains {}, but expected {}",
                            filename.display(),
                            old.fingerprint(),
                            cert.fingerprint()));
                    }

                    update = true;

                    // Prefer secret key material from `cert`.
                    cert = old.clone().merge_public_and_secret(cert.clone())?;

                    if cert == old {
                        wprintln!("Skipping {}: unchanged.", id);
                        continue;
                    }
                }
                Err(err) => {
                    // If the file doesn't exist yet, it's not an
                    // error: it just means that we don't have to
                    // merge.
                    if let Some(ioerr) = err.downcast_ref::<std::io::Error>() {
                        if ioerr.kind() == std::io::ErrorKind::NotFound {
                            // Not found.  No problem.
                        } else {
                            return Err(err);
                        }
                    } else {
                        return Err(err);
                    }
                }
            }

            // We write to a temporary file and then move it into
            // place.  This doesn't eliminate races, but it does
            // prevent a partial update from destroying the existing
            // data.
            let mut tmp_filename = filename.clone();
            tmp_filename.set_extension("pgp~");

            let mut f = File::create(&tmp_filename)?;
            cert.as_tsk().serialize(&mut f)?;

            std::fs::rename(&tmp_filename, &filename)?;

            if update {
                wprintln!("Updated {}", id);
            } else {
                wprintln!("Imported {}", id);
            }

            // Also insert the certificate into the certificate store.
            // If we can't, we don't fail.  This allows, in
            // particular, `sq --no-cert-store key import` to work.
            match config.cert_store_mut_or_else() {
                Ok(cert_store) => {
                    if let Err(err) = cert_store.update(
                        Arc::new(LazyCert::from(cert)))
                    {
                        config.info(format_args!(
                            "While importing {} into cert store: {}",
                            id, err));
                    }
                }
                Err(err) => {
                    config.info(format_args!(
                        "Not importing {} into cert store: {}",
                        id, err));
                }
            }
        }
    }

    Ok(())
}
