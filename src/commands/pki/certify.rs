use std::fmt;
use std::sync::Arc;

use chrono::DateTime;
use chrono::Utc;

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;
use openpgp::Result;
use openpgp::packet::prelude::*;
use openpgp::packet::signature::subpacket::NotationDataFlags;
use openpgp::serialize::Serialize;
use openpgp::types::SignatureType;
use openpgp::types::KeyFlags;

use sequoia_cert_store as cert_store;
use cert_store::StoreUpdate;

use crate::Sq;
use crate::parse_notations;
use crate::sq::GetKeysOptions;
use crate::cli::pki::certify;
use crate::cli::types::FileOrStdin;
use crate::cli::types::FileStdinOrKeyHandle;
use crate::commands::FileOrStdout;

pub fn certify(sq: Sq, mut c: certify::Command)
    -> Result<()>
{
    let certifier: FileStdinOrKeyHandle = if let Some(file) = c.certifier_file {
        assert!(c.certifier.is_none());
        file.into()
    } else if let Some(kh) = c.certifier {
        kh.into()
    } else {
        panic!("clap enforces --certifier or --certifier-file is set");
    };

    // XXX: Change this interface: it's dangerous to guess whether an
    // identifier is a file or a key handle.
    let cert = if let Ok(kh) = c.certificate.parse::<KeyHandle>() {
        FileStdinOrKeyHandle::KeyHandle(kh)
    } else {
        FileStdinOrKeyHandle::FileOrStdin(
            FileOrStdin::new(Some(c.certificate.into())))
    };
    if cert.is_file() {
        // If the cert is read from a file, we default to stdout.
        // (None means write to the cert store.)
        if c.output.is_none() {
            c.output = Some(FileOrStdout::new(None));
        }
    }

    let userid = c.userid;

    let certifier = sq.lookup_one(
        certifier, Some(KeyFlags::empty().set_certification()), true)?;

    let cert = sq.lookup_one(cert, None, true)?;

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

    let time = sq.time;

    let vc = cert.with_policy(sq.policy, Some(time))?;

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

    let mut signer = sq.get_certification_key(certifier, Some(&options))?.0;

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
            .expiration
            .as_duration(DateTime::<Utc>::from(sq.time))?
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

    let cert = cert.insert_packets(new_packets)?;

    if let Some(output) = c.output {
        // And export it.
        let mut message = output.create_pgp_safe(
            sq.force,
            c.binary,
            sequoia_openpgp::armor::Kind::PublicKey,
        )?;
        cert.serialize(&mut message)?;
        message.finalize()?;
    } else {
        // Import it.
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
