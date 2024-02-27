use std::fmt;

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
use crate::cli::pki::certify;

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
    let trust_amount: u8 = c.amount.amount();
    let regex = c.regex;
    if trust_depth == 0 && !regex.is_empty() {
        return Err(
            anyhow::format_err!("A regex only makes sense \
                                 if the trust depth is greater than 0"));
    }

    let local = c.local;
    let non_revocable = c.non_revocable;

    let time = config.time;

    let vc = cert.with_policy(config.policy, Some(time))?;

    let query = if c.email {
        UserIDQuery::Email(userid)
    } else {
        UserIDQuery::Exact(userid)
    };

    // Find the matching User ID.
    let mut userids = Vec::new();
    for ua in vc.userids() {
        match &query {
            UserIDQuery::Exact(q) => {
                if ua.userid().value() == q.as_bytes() {
                    userids.push(ua.userid().clone());
                    break;
                }
            },
            UserIDQuery::Email(q) => {
                if ua.userid().email2().map(|u| u == Some(q.as_str()))
                    .unwrap_or(false)
                {
                    userids.push(ua.userid().clone());
                }
            },
        }
    }

    if userids.is_empty() && c.add_userid {
        userids.push(match &query {
            UserIDQuery::Exact(q) => UserID::from(q.as_str()),
            UserIDQuery::Email(q) => {
                // XXX: Ideally, we could just use the following
                // expression, but currently this returns the bare
                // email address without brackets, so currently we
                // only use it to validate the address...
                UserID::from_address(None, None, q.as_str())?;

                // ... and construct the value by foot:
                UserID::from(format!("<{}>", q))

                // See https://gitlab.com/sequoia-pgp/sequoia/-/issues/1076
            },
        });
    }

    if userids.is_empty() {
        wprintln!("User ID: '{}' not found.\nValid User IDs:", query);
        let mut have_valid = false;
        for ua in vc.userids() {
            if let Ok(u) = std::str::from_utf8(ua.userid().value()) {
                have_valid = true;
                wprintln!("  - {}", u);
            }
        }
        if ! have_valid {
            wprintln!("  - Certificate has no valid User IDs.");
        }
        return Err(anyhow::format_err!("No matching User ID found"));
    };

    // Get the signer to certify with.
    let mut options = Vec::new();
    if c.allow_not_alive_certifier {
        options.push(GetKeysOptions::AllowNotAlive);
    }
    if c.allow_revoked_certifier {
        options.push(GetKeysOptions::AllowRevoked);
    }

    let keys = get_certification_keys(
        &[certifier], config.policy,
        private_key_store.as_deref(),
        Some(time),
        Some(&options))?;
    assert_eq!(
        keys.len(), 1,
        "Expect exactly one result from get_certification_keys()"
    );
    let mut signer = keys.into_iter().next().unwrap().0;

    // Create the certifications.
    let mut new_packets: Vec<Packet> = Vec::new();
    for userid in userids {
        let mut builder
            = SignatureBuilder::new(SignatureType::GenericCertification);

        if trust_depth != 0 || trust_amount != 120 {
            builder = builder.set_trust_signature(trust_depth, trust_amount)?;
        }

        for regex in &regex {
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

        let notations = parse_notations(&c.notation)?;
        for (critical, n) in notations {
            builder = builder.add_notation(
                n.name(),
                n.value(),
                NotationDataFlags::empty().set_human_readable(),
                critical)?;
        };

        // Sign it.
        let certification = builder
            .sign_userid_binding(
                &mut signer,
                cert.primary_key().component(),
                &userid)?;

        new_packets.push(userid.into());
        new_packets.push(certification.into());
    }

    // And export it.
    let cert = cert.insert_packets(new_packets)?;
    let mut message = c.output.create_pgp_safe(
        config.force,
        c.binary,
        sequoia_openpgp::armor::Kind::PublicKey,
    )?;
    cert.serialize(&mut message)?;
    message.finalize()?;

    Ok(())
}

/// How to match on user IDs.
#[derive(Debug)]
enum UserIDQuery {
    /// Exact match.
    Exact(String),

    /// Match on the email address.
    Email(String),
}

impl fmt::Display for UserIDQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserIDQuery::Exact(q) => f.write_str(q),
            UserIDQuery::Email(q) => write!(f, "<{}>", q),
        }
    }
}
