//! Deletes secret key material.
use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::parse::Parse;
use openpgp::Result;
use openpgp::serialize::Serialize;

use crate::cli::types::FileOrStdout;
use crate::cli::types::FileStdinOrKeyHandle;
use crate::Sq;

pub fn delete(sq: Sq,
              cert: FileStdinOrKeyHandle,
              output: Option<FileOrStdout>,
              binary: bool)
    -> Result<()>
{
    match cert {
        FileStdinOrKeyHandle::FileOrStdin(file) => {
            let input = file.open()?;
            let cert = Cert::from_buffered_reader(input)?;

            let output = output.unwrap_or_else(|| FileOrStdout::new(None));
            let mut output = output.create_safe(sq.force)?;
            if binary {
                cert.serialize(&mut output)?;
            } else {
                cert.armored().serialize(&mut output)?;
            }
        }
        FileStdinOrKeyHandle::KeyHandle(kh) => {
            let cert = sq.lookup_one(kh, None, true)?;
            let vc = cert.with_policy(sq.policy, None)?;

            let ks = sq.key_store_or_else()?;
            let mut ks = ks.lock().unwrap();

            // Delete the primary last.
            let keys: Vec<_> = vc.keys().collect();
            for ka in keys.into_iter().rev() {
                let remote_keys = ks.find_key(ka.key_handle())?;
                if remote_keys.is_empty() {
                    eprintln!("Skipping {}: the key store does not manage \
                               its secret key material",
                              ka.fingerprint());
                }
                for mut kh in remote_keys.into_iter() {
                    kh.delete_secret_key_material().with_context(|| {
                        format!("Deleting {}", ka.fingerprint())
                    })?;
                }
            }
        }
    }


    Ok(())
}
