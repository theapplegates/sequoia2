use chrono::DateTime;
use chrono::Utc;

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;
use openpgp::Result;
use openpgp::cert::prelude::*;
use openpgp::packet::prelude::*;
use openpgp::packet::signature::subpacket::NotationDataFlags;
use openpgp::parse::Parse;
use openpgp::serialize::Serialize;
use openpgp::types::SignatureType;
use openpgp::types::KeyFlags;

use crate::Config;
use crate::parse_notations;
use crate::commands::get_certification_keys;
use crate::commands::GetKeysOptions;
use crate::sq_cli::certify;

pub fn certify(config: Config, c: certify::Command)
    -> Result<()>
{
    let certifier = c.certifier;
    let cert = c.certificate;
    let userid = c.userid;

    let certifier = Cert::from_file(certifier)?;
    let private_key_store = c.private_key_store;
    // XXX: Change this interface: it's dangerous to guess whether an
    // identifier is a file or a key handle.
    let cert = if let Ok(kh) = cert.parse::<KeyHandle>() {
        config.lookup_one(&kh, Some(KeyFlags::empty().set_certification()), true)?
    } else {
        Cert::from_file(cert)?
    };

    let trust_depth: u8 = c.depth;
    let trust_amount: u8 = c.amount;
    let regex = c.regex;
    if trust_depth == 0 && !regex.is_empty() {
        return Err(
            anyhow::format_err!("A regex only makes sense \
                                 if the trust depth is greater than 0"));
    }

    let local = c.local;
    let non_revocable = c.non_revocable;

    let time = config.time;

    let vc = cert.with_policy(&config.policy, Some(time))?;

    // Find the matching User ID.
    let mut u = None;
    for ua in vc.userids() {
        if let Ok(a_userid) = std::str::from_utf8(ua.userid().value()) {
            if a_userid == userid {
                u = Some(ua.userid());
                break;
            }
        }
    }

    let userid = if let Some(userid) = u {
        userid
    } else {
        eprintln!("User ID: '{}' not found.\nValid User IDs:", userid);
        let mut have_valid = false;
        for ua in vc.userids() {
            if let Ok(u) = std::str::from_utf8(ua.userid().value()) {
                have_valid = true;
                eprintln!("  - {}", u);
            }
        }
        if ! have_valid {
            eprintln!("  - Certificate has no valid User IDs.");
        }
        return Err(anyhow::format_err!("No matching User ID found"));
    };

    // Create the certification.
    let mut builder
        = SignatureBuilder::new(SignatureType::GenericCertification);

    if trust_depth != 0 || trust_amount != 120 {
        builder = builder.set_trust_signature(trust_depth, trust_amount)?;
    }

    for regex in regex {
        builder = builder.add_regular_expression(regex)?;
    }

    if local {
        builder = builder.set_exportable_certification(false)?;
    }

    if non_revocable {
        builder = builder.set_revocable(false)?;
    }

    // Creation time.
    builder = builder.set_signature_creation_time(time)?;

    if let Some(validity) = c
        .expiry
        .as_duration(DateTime::<Utc>::from(config.time))?
    {
        builder = builder.set_signature_validity_period(validity)?;
    }

    let notations = parse_notations(c.notation)?;
    for (critical, n) in notations {
        builder = builder.add_notation(
            n.name(),
            n.value(),
            NotationDataFlags::empty().set_human_readable(),
            critical)?;
    };

    let mut options = Vec::new();
    if c.allow_not_alive_certifier {
        options.push(GetKeysOptions::AllowNotAlive);
    }
    if c.allow_revoked_certifier {
        options.push(GetKeysOptions::AllowRevoked);
    }

    // Sign it.
    let signers = get_certification_keys(
        &[certifier], &config.policy,
        private_key_store.as_deref(),
        Some(time),
        Some(&options))?;
    assert_eq!(signers.len(), 1);
    let mut signer = signers.into_iter().next().unwrap();

    let certification = builder
        .sign_userid_binding(
            &mut signer,
            cert.primary_key().component(),
            userid)?;
    let cert = cert.insert_packets(certification.clone())?;
    assert!(cert.clone().into_packets().any(|p| {
        match p {
            Packet::Signature(sig) => sig == certification,
            _ => false,
        }
    }));


    // And export it.
    let mut message = c.output.create_pgp_safe(
        config.force,
        c.binary,
        sequoia_openpgp::armor::Kind::PublicKey,
    )?;
    cert.serialize(&mut message)?;
    message.finalize()?;

    Ok(())
}
