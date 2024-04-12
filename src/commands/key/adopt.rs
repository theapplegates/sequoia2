use anyhow::Context;

use itertools::Itertools;

use openpgp::cert::amalgamation::ValidAmalgamation;
use openpgp::cert::CertParser;
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

use crate::Config;
use crate::cli;
use crate::decrypt_key;

pub fn adopt(config: Config, command: cli::key::AdoptCommand) -> Result<()>
{
    let input = command.certificate.open()?;
    let cert = Cert::from_buffered_reader(input)?;
    let mut wanted: Vec<(
        KeyHandle,
        Option<(
            Key<key::PublicParts, key::SubordinateRole>,
            SignatureBuilder,
        )>,
    )> = command.key
        .into_iter()
        .map(|kh| (kh, None))
        .collect::<Vec<_>>();

    let null_policy = &openpgp::policy::NullPolicy::new();
    let adoptee_policy: &dyn Policy = if command.allow_broken_crypto {
        null_policy
    } else {
        config.policy
    };

    // Find the corresponding keys.
    for keyring in config.keyrings.iter() {
        for cert in CertParser::from_file(&keyring)
            .context(format!("Parsing: {}", &keyring.display()))?
        {
            let cert = cert.context(format!("Parsing {}", keyring.display()))?;

            let vc = match cert.with_policy(adoptee_policy, None) {
                Ok(vc) => vc,
                Err(err) => {
                    wprintln!(
                        "Ignoring {} from '{}': {}",
                        cert.keyid().to_hex(),
                        keyring.display(),
                        err
                    );
                    continue;
                }
            };

            for key in vc.keys() {
                for (id, ref mut keyo) in wanted.iter_mut() {
                    if id.aliases(key.key_handle()) {
                        match keyo {
                            Some((_, _)) =>
                            // We already saw this key.
                            {
                                ()
                            }
                            None => {
                                let sig = key.binding_signature();
                                let builder: SignatureBuilder = match sig.typ()
                                {
                                    SignatureType::SubkeyBinding => {
                                        sig.clone().into()
                                    }
                                    SignatureType::DirectKey
                                    | SignatureType::PositiveCertification
                                    | SignatureType::CasualCertification
                                    | SignatureType::PersonaCertification
                                    | SignatureType::GenericCertification => {
                                        // Convert to a binding
                                        // signature.
                                        let kf = sig.key_flags().context(
                                            "Missing required \
                                                      subpacket, KeyFlags",
                                        )?;
                                        SignatureBuilder::new(
                                            SignatureType::SubkeyBinding,
                                        )
                                        .set_key_flags(kf)?
                                    }
                                    _ => panic!(
                                        "Unsupported binding \
                                                 signature: {:?}",
                                        sig
                                    ),
                                };

                                let builder = builder
                                    .set_signature_creation_time(config.time)?;

                                *keyo = Some((
                                    key.key().clone().role_into_subordinate(),
                                    builder,
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    // If we are missing any keys, stop now.
    let missing: Vec<&KeyHandle> = wanted
        .iter()
        .filter_map(|(id, keyo)| match keyo {
            Some(_) => None,
            None => Some(id),
        })
        .collect();
    if !missing.is_empty() {
        return Err(anyhow::anyhow!(
            "Keys not found: {}",
            missing.iter().map(|&h| h.to_hex()).join(", ")
        ));
    }

    let passwords = &mut Vec::new();

    // Get a signer.
    let pk = cert.primary_key().key();
    let mut pk_signer =
        decrypt_key(pk.clone().parts_into_secret()?, passwords)?
            .into_keypair()?;

    // Add the keys and signatures to cert.
    let mut packets: Vec<Packet> = vec![];
    for (_, ka) in wanted.into_iter() {
        let (key, mut builder) = ka.expect("Checked for missing keys above.");

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
            let mut subkey_signer =
                decrypt_key(key.clone().parts_into_secret()?, passwords)?
                    .into_keypair()?;

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
                .set_signature_creation_time(config.time)?
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

    let mut sink = command.output.for_secrets().create_safe(config.force)?;
    if command.binary {
        cert.as_tsk().serialize(&mut sink)?;
    } else {
        cert.as_tsk().armored().serialize(&mut sink)?;
    }

    let vc = cert.with_policy(config.policy, None).expect("still valid");
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
