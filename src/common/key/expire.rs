//! Changes key expiration.

use std::sync::Arc;

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;
use openpgp::Packet;
use openpgp::Result;
use openpgp::cert::amalgamation::ValidAmalgamation;
use openpgp::cert::amalgamation::ValidateAmalgamation;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::serialize::Serialize;
use openpgp::types::RevocationStatus;
use openpgp::types::RevocationType;
use openpgp::types::SignatureType;

use sequoia_cert_store::StoreUpdate;

use crate::cli::types::Expiration;
use crate::cli::types::FileOrStdout;
use crate::cli::types::FileStdinOrKeyHandle;
use crate::Sq;
use crate::sq::GetKeysOptions;

pub fn expire(sq: Sq,
              cert_handle: FileStdinOrKeyHandle,
              keys: &[KeyHandle],
              expiration: Expiration,
              mut output: Option<FileOrStdout>,
              binary: bool)
    -> Result<()>
{
    if cert_handle.is_file() {
        if output.is_none() {
            // None means to write to the cert store.  When reading
            // from a file, we want to write to stdout by default.
            output = Some(FileOrStdout::new(None));
        }
    }
    let cert = sq.lookup_one(cert_handle.clone(), None, true)?;

    let mut primary_signer
        = sq.get_primary_key(&cert, Some(&[GetKeysOptions::AllowNotAlive]))?;

    let vc = cert.with_policy(sq.policy, sq.time)?;

    let primary_handle = cert.key_handle();
    let all_handles = vc.keys().map(|k| k.key_handle()).collect::<Vec<_>>();

    // Fix the new expiration time.
    let expiration_time = expiration.to_system_time(sq.time)?;

    // We update the primary key if no subkey is given, or it is
    // explicitly listed as a key to change.
    let mut update_primary_key = keys.is_empty();

    // We only update subkey bindings if they are explicitly given.
    let update_subkeys = ! keys.is_empty();

    let mut subkeys = vc.keys().subkeys();
    for h in keys {
        if ! all_handles.iter().any(|k| k.aliases(h)) {
            let mut weak = None;
            if let Some(ka) = cert.keys().key_handle(h.clone()).next() {
                weak = ka.with_policy(sq.policy, sq.time).err();
            }
            if let Some(ref err) = weak {
                wprintln!("Selected key {} is unusable: {}.", h, err);
                sq.hint(format_args!(
                    "After checking the integrity of the certificate, you \
                     may be able to repair it using:"))
                    .sq().arg("cert").arg("lint").arg("--fix")
                    .arg_value(
                        match &cert_handle {
                            FileStdinOrKeyHandle::KeyHandle(_kh) => {
                                "--cert"
                            }
                            FileStdinOrKeyHandle::FileOrStdin(_file) => {
                                "--file"
                            }
                        },
                        match &cert_handle {
                            FileStdinOrKeyHandle::KeyHandle(kh) => {
                                kh.to_string()
                            }
                            FileStdinOrKeyHandle::FileOrStdin(file) => {
                                file.path()
                                    .map(|p| p.display().to_string())
                                    .unwrap_or_else(|| "".into())
                            }
                        })
                    .done();
            } else {
                wprintln!("Selected key {} is not part of the certificate.", h);
            }
            wprintln!();
            wprintln!("{} has the following keys:", cert.fingerprint());
            wprintln!();
            for k in &all_handles {
                wprintln!(" - {}", k);
            }
            if weak.is_some() {
                return Err(anyhow::anyhow!("Selected key not usable"));
            } else {
                return Err(anyhow::anyhow!("Selected key not found"));
            }
        }

        if h.aliases(&primary_handle) {
            update_primary_key = true;
        } else {
            subkeys = subkeys.key_handle(h.clone());
        }
    }

    // Collect new signatures here, then canonicalize once.
    let mut acc = Vec::<Packet>::new();

    if update_subkeys {
        // To update subkey expiration times, create new binding
        // signatures.
        for ka in subkeys {
            if let RevocationStatus::Revoked(sigs) = ka.revocation_status() {
                for sig in sigs {
                    let reason = sig.reason_for_revocation();
                    let bad = if let Some((reason, _)) = reason {
                        reason.revocation_type() == RevocationType::Hard
                    } else {
                        true
                    };

                    if bad {
                        return Err(anyhow::anyhow!(
                            "Can't extend the expiration of {}, \
                             it is hard revoked",
                            ka.fingerprint()));
                    }
                }
            }

            // Use the binding signature under our policy as the template.
            let template = ka.binding_signature();

            // Push a copy of the key to make reordering easier.
            acc.push(Packet::from(ka.key().clone()));
            acc.push(ka.bind(
                &mut primary_signer,
                &cert,
                SignatureBuilder::from(template.clone())
                    .set_signature_creation_time(sq.time)?
                    .set_key_expiration_time(ka.key(), expiration_time)?)?
                     .into());
        }
    }

    // To change the cert's expiration time, create a new direct key
    // signature and new binding signatures for the user IDs.
    if update_primary_key {
        let template = vc.primary_key().binding_signature().clone();

        // Clean the template.
        let template = SignatureBuilder::from(template)
            .modify_unhashed_area(|mut a| {
                a.clear();
                Ok(a)
            })?
            .modify_hashed_area(|mut a| {
                // XXX: Rework once
                // https://gitlab.com/sequoia-pgp/sequoia/-/issues/1127
                // is available.
                let mut strip_tags: std::collections::BTreeSet<_> =
                    a.iter().map(|s| s.tag()).collect();

                // Symbolic names for the policy below.
                let strip = true;
                let keep = false;

                use openpgp::packet::signature::subpacket::SubpacketTag::*;
                #[allow(deprecated)]
                strip_tags.retain(|t| match t {
                    // These we keep.
                    PreferredSymmetricAlgorithms => keep,
                    RevocationKey => keep,
                    NotationData => keep,
                    PreferredHashAlgorithms => keep,
                    PreferredCompressionAlgorithms => keep,
                    KeyServerPreferences => keep,
                    PreferredKeyServer => keep,
                    PolicyURI => keep,
                    KeyFlags => keep,
                    Features => keep,
                    // XXXv6: PreferredAEADCiphersuites => keep,

                    // Oddballs, keep them.
                    Reserved(_) => keep,
                    Private(_) => keep,
                    Unknown(_) => keep,

                    // These we want to strip.
                    SignatureCreationTime => strip,
                    SignatureExpirationTime => strip,
                    ExportableCertification => strip,
                    TrustSignature => strip,
                    RegularExpression => strip,
                    Revocable => strip,
                    KeyExpirationTime => strip,
                    PlaceholderForBackwardCompatibility => strip,
                    Issuer => strip,
                    PrimaryUserID => strip,
                    SignersUserID => strip,
                    ReasonForRevocation => strip,
                    SignatureTarget => strip,
                    EmbeddedSignature => strip,
                    IssuerFingerprint => strip,
                    PreferredAEADAlgorithms => strip, // Note, "v5".
                    IntendedRecipient => strip,
                    AttestedCertifications => strip,

                    // Enum is non-exhaustive, conservative choice is
                    // to keep unknown subpackets.
                    _ => keep,
                });

                for t in strip_tags {
                    a.remove_all(t);
                }

                Ok(a)
            })?;

        // We can't add a copy of the primary key, as that's not
        // allowed by `Cert::insert_packets`.  But it's easy to
        // reorder direct key signatures as there is only a single
        // possible component, the primary key.
        acc.push(template
                 .set_type(SignatureType::DirectKey)
                 .set_signature_creation_time(sq.time)?
                 .set_key_expiration_time(cert.primary_key().key(),
                                          expiration_time)?
                 .sign_direct_key(&mut primary_signer, None)?
                 .into());

        for uidb in vc.userids() {
            if let RevocationStatus::Revoked(_) = uidb.revocation_status() {
                // The user ID is revoked.  Skip it.  (Adding a new
                // self signature would actually "unrevoke it"!)
                continue;
            }

            // Use the binding signature that is valid under our
            // policy as of the reference time.
            let template = uidb.binding_signature().clone();

            // Push a copy of the user ID to make reordering easier.
            acc.push(Packet::from(uidb.userid().clone()));
            acc.push(uidb.bind(
                &mut primary_signer,
                &cert,
                SignatureBuilder::from(template)
                    .set_signature_creation_time(sq.time)?
                    .set_key_expiration_time(cert.primary_key().key(),
                                             expiration_time)?)?
                     .into());
        }
    }

    // Merge and canonicalize.
    let cert = cert.insert_packets(acc)?;

    if let Some(sink) = output {
        let path = sink.path().map(Clone::clone);
        let mut output = sink.for_secrets().create_safe(&sq)?;
        if binary {
            cert.as_tsk().serialize(&mut output)?;
        } else {
            cert.as_tsk().armored().serialize(&mut output)?;
        }

        if let Some(path) = path {
            sq.hint(format_args!(
                "Updated certificate written to {}.  \
                 To make the update effective, it has to be published \
                 so that others can find it, for example using:",
                path.display()))
                .sq().arg("network").arg("keyserver").arg("publish")
                .arg_value("--file", path.display())
                .done();
        } else {
            sq.hint(format_args!(
                "To make the update effective, it has to be published \
                 so that others can find it."));
        }
    } else {
        let cert_store = sq.cert_store_or_else()?;

        let fipr = cert.fingerprint();
        if let Err(err) = cert_store.update(Arc::new(cert.into())) {
            wprintln!("Error importing updated cert: {}", err);
            return Err(err);
        } else {
            sq.hint(format_args!(
                "Imported updated cert into the cert store.  \
                 To make the update effective, it has to be published \
                 so that others can find it, for example using:"))
                .sq().arg("network").arg("keyserver").arg("publish")
                .arg_value("--cert", fipr)
                .done();
        }
    }

    Ok(())
}
