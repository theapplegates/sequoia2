use anyhow::Context;

use openpgp::cert::amalgamation::ValidAmalgamation;
use openpgp::packet::key;
use openpgp::packet::signature::subpacket::SubpacketTag;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::packet::Key;
use openpgp::packet::Signature;
use openpgp::parse::Parse;
use openpgp::policy::Policy;
use openpgp::serialize::Serialize;
use openpgp::types::SignatureType;
use openpgp::Cert;
use openpgp::KeyHandle;
use openpgp::Packet;
use openpgp::Result;
use sequoia_openpgp as openpgp;

use crate::Sq;
use crate::cli;

pub fn adopt(sq: Sq, command: cli::key::AdoptCommand) -> Result<()>
{
    let input = command.cert_file.open()?;
    let cert = Cert::from_buffered_reader(input)?;

    let null_policy_;
    let adoptee_policy: &dyn Policy = if command.allow_broken_crypto {
        null_policy_ = openpgp::policy::NullPolicy::new();
        &null_policy_
    } else {
        sq.policy
    };

    // Find the corresponding keys.
    let wanted: Vec<(
        KeyHandle,
        Result<(
            Cert,
            Key<key::PublicParts, key::SubordinateRole>,
            SignatureBuilder,
        )>,
    )> = command.key
        .into_iter()
        .map(|kh| {
            let cert = match sq.lookup_one_with_policy(
                kh.clone(), None, false, adoptee_policy, sq.time)
            {
                Ok(cert) => cert,
                Err(err) => return (kh, Err(err)),
            };

            let vc = match cert.with_policy(adoptee_policy, sq.time) {
                Ok(vc) => vc,
                Err(err) => return (kh, Err(err)),
            };

            let key = vc.keys().key_handle(kh.clone())
                .next().expect("have key");

            let sig = key.binding_signature();
            let builder: SignatureBuilder = match sig.typ() {
                SignatureType::SubkeyBinding => {
                    sig.clone().into()
                }
                SignatureType::DirectKey
                    | SignatureType::PositiveCertification
                    | SignatureType::CasualCertification
                    | SignatureType::PersonaCertification
                    | SignatureType::GenericCertification => {
                        // Convert to a binding signature.
                        let kf = match sig.key_flags().context(
                            "Missing required subpacket, KeyFlags")
                        {
                            Ok(kh) => kh,
                            Err(err) => return (kh, Err(err)),
                        };
                        match SignatureBuilder::new(SignatureType::SubkeyBinding)
                            .set_key_flags(kf)
                        {
                            Ok(b) => b,
                            Err(err) => return (kh, Err(err)),
                        }
                    }
                _ => panic!("Unsupported binding signature: {:?}", sig),
            };

            let builder = match builder.set_signature_creation_time(sq.time) {
                Ok(b) => b,
                Err(err) => return (kh, Err(err)),
            };

            let key = key.key().clone().role_into_subordinate();

            (kh, Ok((cert, key, builder)))
        })
        .collect();

    // If we are missing any keys, stop now.
    let mut missing = false;
    let wanted = wanted.into_iter()
        .filter_map(|(id, keyo)| {
            match keyo {
                Ok((cert, key, builder)) => Some((cert, key, builder)),
                Err(err) => {
                    if ! missing {
                        eprintln!("Missing keys:");
                    }

                    eprintln!("  - {}: {}", id, err);

                    missing = true;
                    None
                }
            }
        })
        .collect::<Vec<_>>();
    if missing {
        return Err(anyhow::anyhow!("Missing some keys"));
    }

    // Get a signer.
    let pk = cert.primary_key().key();
    let mut pk_signer = sq.get_primary_key(&cert, None)
        .with_context(|| {
            format!("Getting signer for {}'s primary key",
                    cert.fingerprint())
        })?.0;

    // Add the keys and signatures to cert.
    let mut packets: Vec<Packet> = vec![];
    for (cert, key, mut builder) in wanted.into_iter() {
        // Set key expiration.
        if let Some(e) = &command.expire {
            builder = builder.set_key_expiration_time(&key, e.timestamp())?;
        }

        // If there is a valid backsig, recreate it.
        let need_backsig = builder
            .key_flags()
            .map(|kf| kf.for_signing() || kf.for_certification())
            .expect("Missing keyflags");

        if need_backsig {
            // Derive a signer.
            let ka = cert.keys().key_handle(key.fingerprint())
                .next()
                .expect("have key");

            let mut subkey_signer = sq.get_signer(&ka)
                .with_context(|| {
                    format!("Getting signer for {}", ka.fingerprint())
                })?.0;

            let backsig = builder
                .embedded_signatures()
                .find(|backsig| {
                    (*backsig)
                        .clone()
                        .verify_primary_key_binding(&cert.primary_key(), &key)
                        .is_ok()
                })
                .map(|sig| SignatureBuilder::from(sig.clone()))
                .unwrap_or_else(|| {
                    SignatureBuilder::new(SignatureType::PrimaryKeyBinding)
                })
                .set_signature_creation_time(sq.time)?
                .sign_primary_key_binding(&mut subkey_signer, pk, &key)?;

            builder = builder.set_embedded_signature(backsig)?;
        } else {
            builder = builder.modify_hashed_area(|mut a| {
                a.remove_all(SubpacketTag::EmbeddedSignature);
                Ok(a)
            })?;
        }

        let mut sig = builder.sign_subkey_binding(&mut pk_signer, pk, &key)?;

        // Verify it.
        assert!(sig
            .verify_subkey_binding(pk_signer.public(), pk, &key)
            .is_ok());

        packets.push(key.into());
        packets.push(sig.into());
    }

    let cert = cert.clone().insert_packets(packets.clone())?;

    let mut sink = command.output.for_secrets().create_safe(sq.force)?;
    if command.binary {
        cert.as_tsk().serialize(&mut sink)?;
    } else {
        cert.as_tsk().armored().serialize(&mut sink)?;
    }

    let vc = cert.with_policy(sq.policy, None).expect("still valid");
    for pair in packets[..].chunks(2) {
        let newkey: &Key<key::PublicParts, key::UnspecifiedRole> = match pair[0]
        {
            Packet::PublicKey(ref k) => k.into(),
            Packet::PublicSubkey(ref k) => k.into(),
            Packet::SecretKey(ref k) => k.into(),
            Packet::SecretSubkey(ref k) => k.into(),
            ref p => panic!("Expected a key, got: {:?}", p),
        };
        let newsig: &Signature = match pair[1] {
            Packet::Signature(ref s) => s,
            ref p => panic!("Expected a sig, got: {:?}", p),
        };

        let mut found = false;
        for key in vc.keys() {
            if key.fingerprint() == newkey.fingerprint() {
                for sig in key.self_signatures() {
                    if sig == newsig {
                        found = true;
                        break;
                    }
                }
            }
        }
        assert!(found, "Subkey: {:?}\nSignature: {:?}", newkey, newsig);
    }

    Ok(())
}
