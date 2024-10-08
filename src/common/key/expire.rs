//! Changes key expiration.

use std::sync::Arc;

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;
use openpgp::Packet;
use openpgp::Result;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::serialize::Serialize;
use openpgp::types::RevocationStatus;
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
    let cert = sq.lookup_one(cert_handle, None, true)?;

    let mut primary_signer
        = sq.get_primary_key(&cert, Some(&[GetKeysOptions::AllowNotAlive]))?;

    let primary_handle = cert.key_handle();
    let all_handles = cert.keys().map(|k| k.key_handle()).collect::<Vec<_>>();

    // Fix the new expiration time.
    let expiration_time = expiration.to_systemtime(sq.time);

    // We update the primary key if no subkey is given, or it is
    // explicitly listed as a key to change.
    let mut update_primary_key = keys.is_empty();

    // We only update subkey bindings if they are explicitly given.
    let update_subkeys = ! keys.is_empty();

    let mut subkeys = cert.keys().subkeys();
    for h in keys {
        if ! all_handles.iter().any(|k| k.aliases(h)) {
            wprintln!("Selected key {} does not exist in the certificate.", h);
            wprintln!();
            wprintln!("The certificate has the following keys:");
            wprintln!();
            for k in &all_handles {
                wprintln!(" - {}", k);
            }
            return Err(anyhow::anyhow!("Selected key not found"));
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
            // Preferably use the binding signature under our policy,
            // fall back to the most recent binding signature.
            let template = ka.binding_signature(sq.policy, sq.time)
                .or(ka.self_signatures().next()
                    .ok_or(anyhow::anyhow!("no binding signature")))?
                .clone();

            // Push a copy of the key to make reordering easier.
            acc.push(Packet::from(ka.key().clone()));
            acc.push(ka.bind(
                &mut primary_signer,
                &cert,
                SignatureBuilder::from(template)
                    .set_signature_creation_time(sq.time)?
                    .set_key_expiration_time(ka.key(), expiration_time)?)?
                     .into());
        }
    }

    // To change the cert's expiration time, create a new direct key
    // signature and new binding signatures for the user IDs.
    if update_primary_key {
        use openpgp::cert::amalgamation::ValidAmalgamation;

        let template =
        // Preferably use the direct key signature under our policy,
            cert.primary_key().binding_signature(sq.policy, sq.time).ok()
        // fall back to the most recent direct key signature,
            .or_else(|| cert.primary_key().self_signatures().next())
        // fall back to the primary user ID's binding signature,
            .or_else(|| cert.with_policy(sq.policy, sq.time)
                     .and_then(|vcert| vcert.primary_userid())
                     .map(|uidb| uidb.binding_signature())
                     .ok())
        // fall back to the newest user ID binding signature.
            .or_else(|| {
                let mut sigs = cert.userids()
                    .filter_map(|uidb| uidb.self_signatures().next())
                    .collect::<Vec<_>>();
                sigs.sort_by_key(|s| s.signature_creation_time()
                                 .unwrap_or(std::time::UNIX_EPOCH));
                sigs.last().cloned()
            })
            .ok_or(anyhow::anyhow!("no primary key signature"))?
            .clone();

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

        for uidb in cert.userids() {
            if let RevocationStatus::Revoked(_)
                = uidb.revocation_status(sq.policy, sq.time)
            {
                // The user ID is revoked.  Skip it.  (Adding a new
                // self signature would actually "unrevoke it"!)
                continue;
            }

            // Use the binding signature that is valid under our
            // policy as of the reference time.  If there is none,
            // fall back to the most recent binding signature.
            let template = if let Ok(sig) = uidb.binding_signature(
                sq.policy, sq.time)
            {
                sig.clone()
            } else if let Some(sig) = uidb.self_signatures().next() {
                sig.clone()
            } else {
                // The user ID is not bound.  It may be certified by a
                // third-party, but not by the user.  This is
                // perfectly valid!  Just silently skip it.
                continue;
            };

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
                .command(format_args!(
                    "sq network keyserver publish {}",
                    path.display()));
        } else {
            sq.hint(format_args!(
                "To make the update effective, it has to be published \
                 so that others can find it."));
        }
    } else {
        let cert_store = sq.cert_store_or_else()?;

        let keyid = cert.keyid();
        if let Err(err) = cert_store.update(Arc::new(cert.into())) {
            wprintln!("Error importing updated cert: {}", err);
            return Err(err);
        } else {
            sq.hint(format_args!(
                "Imported updated cert into the cert store.  \
                 To make the update effective, it has to be published \
                 so that others can find it, for example using:"))
                .command(format_args!(
                    "sq network keyserver publish --cert {}",
                    keyid));
        }
    }

    Ok(())
}
