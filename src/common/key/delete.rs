//! Deletes secret key material.
use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Packet;
use openpgp::Result;
use openpgp::cert::amalgamation::key::ValidErasedKeyAmalgamation;
use openpgp::packet::key::KeyParts;
use openpgp::serialize::Serialize;

use crate::Sq;
use crate::cli::types::FileOrStdout;
use crate::cli::types::FileStdinOrKeyHandle;

use super::get_keys;

pub fn delete<'a, P>(
    sq: Sq,
    cert: &Cert,
    cert_source: FileStdinOrKeyHandle,
    kas: &[ValidErasedKeyAmalgamation<'a, P>],
    output: Option<FileOrStdout>,
    binary: bool)
    -> Result<()>
where
    P: 'a + KeyParts,
{
    let to_delete = get_keys(&sq, &cert_source, kas)?;

    let ks = matches!(cert_source, FileStdinOrKeyHandle::KeyHandle(_));
    if ks {
        // Delete the secret key material from the key store.
        for (key, _primary, remote_keys) in to_delete.into_iter() {
            let remote_keys = remote_keys.expect("have remote keys");
            assert!(! remote_keys.is_empty());
            for mut kh in remote_keys.into_iter() {
                kh.delete_secret_key_material().with_context(|| {
                    format!("Deleting {}", key.fingerprint())
                })?;
            }
        }
    } else {
        // Strip the secret key material from the certificate.
        let mut stripped: Vec<Packet> = Vec::new();

        for (key, primary, _) in to_delete.into_iter() {
            let pk = key.take_secret().0;
            if primary {
                stripped.push(
                    Packet::PublicKey(pk.role_into_primary()));
            } else {
                stripped.push(
                    Packet::PublicSubkey(pk.role_into_subordinate()));
            }
        }

        let cert = cert.clone().insert_packets(
            stripped.into_iter().map(|stripped| Packet::from(stripped)))?;

        let output = output.unwrap_or_else(|| FileOrStdout::new(None));
        let mut output = output.for_secrets().create_safe(&sq)?;
        if binary {
            cert.as_tsk().serialize(&mut output)?;
        } else {
            cert.as_tsk().armored().serialize(&mut output)?;
        }
    }

    Ok(())
}
