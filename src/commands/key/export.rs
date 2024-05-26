use std::collections::BTreeMap;

use sequoia_openpgp as openpgp;
use openpgp::cert::amalgamation::key::PrimaryKey;
use openpgp::cert::Cert;
use openpgp::Fingerprint;
use openpgp::packet::Packet;
use openpgp::serialize::Serialize;

use anyhow::Context;

use crate::cli;
use crate::Sq;
use crate::Result;

const NULL: openpgp::policy::NullPolicy =
    openpgp::policy::NullPolicy::new();

pub fn export(sq: Sq, command: cli::key::ExportCommand)
    -> Result<()>
{
    let ks = sq.key_store_or_else()?;
    let mut ks = ks.lock().unwrap();

    // If the user asks for multiple keys from the same certificate,
    // then we only want to export the certificate once.
    let mut certs: BTreeMap<Fingerprint, Cert> = BTreeMap::new();

    for (export_cert, export) in command.cert.into_iter().map(|kh| (true, kh))
        .chain(command.key.into_iter().map(|kh| (false, kh)))
    {
        let mut cert = sq.lookup_one(&export, None, true)?;
        if let Some(c) = certs.remove(&cert.fingerprint()) {
            cert = c;
        }

        let vc = Cert::with_policy(&cert, sq.policy, sq.time)
            .or_else(|err| {
                if export_cert {
                    Err(err)
                } else {
                    // When exporting by --key, fallback to the null
                    // policy.  It should be possible to export old
                    // keys, even if the certificate is not considered
                    // safe any more.
                    Cert::with_policy(&cert, &NULL, sq.time)
                }
            })
            .with_context(|| {
                format!("The certificate {} is not valid under the \
                         current policy.  Use --key to export \
                         specific keys.",
                        cert.fingerprint())
            })?;

        let mut secret_keys: Vec<Packet> = Vec::new();
        for loud in [false, true] {
            for key in vc.keys() {
                if key.has_secret() {
                    continue;
                }

                let key_handle = key.key_handle();

                if ! export_cert && ! key_handle.aliases(&export) {
                    continue;
                }

                for mut remote in ks.find_key(key_handle)? {
                    match remote.export() {
                        Ok(secret_key) => {
                            if key.primary() {
                                secret_keys.push(
                                    secret_key.role_into_primary().into());
                            } else {
                                secret_keys.push(
                                    secret_key.role_into_subordinate().into());
                            }
                            break;
                        }
                        Err(err) => {
                            if loud {
                                eprintln!("Exporting {}: {}",
                                          key.fingerprint(), err);
                            }
                        }
                    }
                }
            }

            if loud {
                return Err(anyhow::anyhow!(
                    "Failed to export {}: no secret key material is available",
                    cert.fingerprint()));
            } else if ! secret_keys.is_empty() {
                break;
            }
        }
        let cert = cert.insert_packets(secret_keys)?;
        certs.insert(cert.fingerprint(), cert);
    }

    let mut output = openpgp::armor::Writer::new(
        std::io::stdout(),
        openpgp::armor::Kind::SecretKey)?;

    for (_fpr, cert) in certs.into_iter() {
        cert.as_tsk().serialize(&mut output)
            .with_context(|| {
                format!("Serializing {}", cert.fingerprint())
            })?;
    }

    output.finalize()?;

    Ok(())
}
