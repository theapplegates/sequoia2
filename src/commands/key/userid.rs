use std::time::SystemTime;

use anyhow::Context;

use itertools::Itertools;

use openpgp::cert::amalgamation::ValidAmalgamation;
use openpgp::packet::UserID;
use openpgp::packet::signature::subpacket::SubpacketTag;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::parse::Parse;
use openpgp::policy::HashAlgoSecurity;
use openpgp::policy::Policy;
use openpgp::serialize::Serialize;
use openpgp::types::SignatureType;
use openpgp::Cert;
use openpgp::Packet;
use openpgp::Result;
use sequoia_openpgp as openpgp;

use crate::commands::get_primary_keys;
use crate::sq_cli;
use crate::Config;

pub fn userid(
    config: Config,
    command: sq_cli::key::UseridCommand,
) -> Result<()> {
    match command {
        sq_cli::key::UseridCommand::Add(c) => userid_add(config, c)?,
        sq_cli::key::UseridCommand::Strip(c) => userid_strip(config, c)?,
    }

    Ok(())
}

fn userid_add(
    config: Config,
    command: sq_cli::key::UseridAddCommand,
) -> Result<()> {
    let input = command.input.open()?;
    let key = Cert::from_reader(input)?;

    // Fail if any of the User IDs to add already exist in the ValidCert
    let key_userids: Vec<_> =
        key.userids().map(|u| u.userid().value()).collect();
    let exists: Vec<_> = command
        .userid
        .iter()
        .filter(|s| key_userids.contains(&s.as_bytes()))
        .collect();
    if !exists.is_empty() {
        return Err(anyhow::anyhow!(
            "The certificate already contains the User ID(s) {}.",
            exists.iter().map(|s| format!("{:?}", s)).join(", ")
        ));
    }

    let creation_time = Some(config.time);

    // If a password is needed to use the key, the user will be prompted.
    let pk = get_primary_keys(
        &[key.clone()],
        &config.policy,
        command.private_key_store.as_deref(),
        creation_time,
        None,
    );

    let pk = pk.context("Adding a User ID requires the private key")?;

    assert_eq!(
        pk.len(),
        1,
        "Expect exactly one result from get_primary_keys()"
    );
    let mut pk = pk.into_iter().next().unwrap();

    let vcert = key
        .with_policy(&config.policy, creation_time)
        .with_context(|| {
            format!("Certificate {} is not valid", key.fingerprint())
        })?;

    // Use the primary User ID or direct key signature as template for the
    // SignatureBuilder.
    //
    // XXX: Long term, this functionality belongs next to
    // openpgp/src/cert/builder/key.rs.
    let mut sb = if let Ok(primary_user_id) = vcert.primary_userid() {
        SignatureBuilder::from(primary_user_id.binding_signature().clone())
    } else if let Ok(direct_key_sig) = vcert.direct_key_signature() {
        SignatureBuilder::from(direct_key_sig.clone())
            .set_type(SignatureType::PositiveCertification)
    } else {
        // If there is neither a valid uid binding signature, nor a
        // valid direct key signature, we shouldn't have gotten a
        // ValidCert above.
        unreachable!("ValidCert has to have one of the above.")
    };

    // Remove bad algorithms from preferred algorithm subpackets,
    // and make sure preference lists contain at least one good algorithm.

    // - symmetric_algorithms
    let mut symmetric_algorithms: Vec<_> =
        sb.preferred_symmetric_algorithms().unwrap_or(&[]).to_vec();
    symmetric_algorithms
        .retain(|algo| config.policy.symmetric_algorithm(*algo).is_ok());
    if symmetric_algorithms.is_empty() {
        symmetric_algorithms.push(Default::default());
    }
    sb = sb.set_preferred_symmetric_algorithms(symmetric_algorithms)?;

    // - hash_algorithms
    let mut hash_algorithms: Vec<_> =
        sb.preferred_hash_algorithms().unwrap_or(&[]).to_vec();
    hash_algorithms.retain(|algo| {
        config
            .policy
            .hash_cutoff(*algo, HashAlgoSecurity::CollisionResistance)
            .map(|cutoff| cutoff.lt(&SystemTime::now()))
            .unwrap_or(true)
    });
    if hash_algorithms.is_empty() {
        hash_algorithms.push(Default::default());
    }
    sb = sb.set_preferred_hash_algorithms(hash_algorithms)?;

    // Remove the following types of SubPacket, if they exist
    const REMOVE_SUBPACKETS: &[SubpacketTag] = &[
        // The Signature should be exportable.
        // https://openpgp-wg.gitlab.io/rfc4880bis/#name-exportable-certification
        // "If this packet is not present, the certification is exportable;
        // it is equivalent to a flag containing a 1."
        SubpacketTag::ExportableCertification,
        // PreferredAEADAlgorithms has been removed by WG.
        // It was replaced by `39  Preferred AEAD Ciphersuites`,
        //  see https://openpgp-wg.gitlab.io/rfc4880bis/#section-5.2.3.5-7)
        SubpacketTag::PreferredAEADAlgorithms,
        // Strip the primary userid SubPacket
        // (don't implicitly make a User ID primary)
        SubpacketTag::PrimaryUserID,
        // Other SubPacket types that shouldn't be in use in this context
        SubpacketTag::TrustSignature,
        SubpacketTag::RegularExpression,
        SubpacketTag::SignersUserID,
        SubpacketTag::ReasonForRevocation,
        SubpacketTag::SignatureTarget,
        SubpacketTag::EmbeddedSignature,
        SubpacketTag::AttestedCertifications,
    ];

    sb = sb.modify_hashed_area(|mut subpacket_area| {
        REMOVE_SUBPACKETS
            .iter()
            .for_each(|sp| subpacket_area.remove_all(*sp));

        Ok(subpacket_area)
    })?;

    // New User ID should only be made primary if explicitly specified by user.
    // xxx: add a parameter to set a new user id as primary?

    // Collect packets to add to the key (new User IDs and binding signatures)
    let mut add: Vec<Packet> = vec![];

    // Make new User IDs and binding signatures
    for uid in command.userid {
        let uid: UserID = uid.into();
        add.push(uid.clone().into());

        // Creation time.
        if let Some(t) = creation_time {
            sb = sb.set_signature_creation_time(t)?;
        };

        let binding = uid.bind(&mut pk, &key, sb.clone())?;
        add.push(binding.into());
    }

    // Merge additional User IDs into key
    let cert = key.insert_packets(add)?;

    let mut sink = command.output.create_safe(config.force)?;
    if command.binary {
        cert.as_tsk().serialize(&mut sink)?;
    } else {
        cert.as_tsk().armored().serialize(&mut sink)?;
    }
    Ok(())
}

fn userid_strip(
    config: Config,
    command: sq_cli::key::UseridStripCommand,
) -> Result<()> {
    let input = command.input.open()?;
    let key = Cert::from_reader(input)?;

    let orig_cert_valid = key.with_policy(&config.policy, None).is_ok();

    let strip: Vec<_> = command.userid;

    // Make sure that each User ID that the user requested to remove exists in
    // `key`, and *can* be removed.
    let key_userids: Vec<_> =
        key.userids().map(|u| u.userid().value()).collect();

    let missing: Vec<_> = strip
        .iter()
        .filter(|s| !key_userids.contains(&s.as_bytes()))
        .collect();
    if !missing.is_empty() {
        return Err(anyhow::anyhow!(
            "The certificate doesn't contain the User ID(s) {}.",
            missing.iter().map(|s| format!("{:?}", s)).join(", ")
        ));
    }

    let cert = key.retain_userids(|uid| {
        // Don't keep User IDs that were selected for removal
        !strip.iter().any(|rm| rm.as_bytes() == uid.userid().value())
    });

    if orig_cert_valid {
        if let Err(err) = cert.with_policy(&config.policy, None) {
            eprintln!(
                "Removing the User ID(s) has resulted in a invalid key:
{}

You could create a direct key signature or update the self
signatures on other User IDs to make the key valid again.",
                err
            );
        }
    }

    let mut sink = command.output.create_safe(config.force)?;
    if command.binary {
        cert.as_tsk().serialize(&mut sink)?;
    } else {
        cert.as_tsk().armored().serialize(&mut sink)?;
    }
    Ok(())
}
