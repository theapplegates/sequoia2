use std::str::from_utf8;
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Context;

use anyhow::anyhow;
use itertools::Itertools;

use sequoia_openpgp as openpgp;
use openpgp::cert::amalgamation::ValidAmalgamation;
use openpgp::cert::UserIDRevocationBuilder;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::packet::signature::subpacket::SubpacketTag;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::packet::UserID;
use openpgp::parse::Parse;
use openpgp::policy::HashAlgoSecurity;
use openpgp::policy::Policy;
use openpgp::serialize::Serialize;
use openpgp::types::ReasonForRevocation;
use openpgp::types::SignatureType;
use openpgp::Cert;
use openpgp::Packet;
use openpgp::Result;

use sequoia_cert_store as cert_store;
use cert_store::StoreUpdate;

use crate::Sq;
use crate::cli;
use crate::cli::key::UseridRevokeCommand;
use crate::cli::types::FileOrStdout;
use crate::common::NULL_POLICY;
use crate::common::RevocationOutput;
use crate::common::get_secret_signer;
use crate::common::userid::{lint_userids, lint_names, lint_emails};
use crate::parse_notations;

/// Handle the revocation of a User ID
struct UserIDRevocation {
    cert: Cert,
    revoker: Cert,
    revocation_packet: Packet,
    userid: String,
    uid: UserID,
}

impl UserIDRevocation {
    /// Create a new UserIDRevocation
    pub fn new(
        sq: &Sq,
        userid: String,
        force: bool,
        cert: Cert,
        revoker: Option<Cert>,
        reason: ReasonForRevocation,
        message: &str,
        notations: &[(bool, NotationData)],
    ) -> Result<Self> {
        let (revoker, mut signer)
            = get_secret_signer(sq, &cert, revoker.as_ref())?;

        let uid = UserID::from(userid.as_str());

        let revocation_packet = {
            // Create a revocation for a User ID.

            // Unless force is specified, we require the User ID to
            // have a valid self signature under the Null policy.  We
            // use the Null policy and not the standard policy,
            // because it is still useful to revoke a User ID whose
            // self signature is no longer valid.  For instance, the
            // binding signature may use SHA-1.
            if !force {
                let valid_cert = cert.with_policy(NULL_POLICY, None)?;
                let present = valid_cert
                    .userids()
                    .any(|u| u.userid() == &uid);

                if !present {
                    wprintln!(
                        "User ID, cert: Cert, secret: Option<Cert>: '{}' not found.\nValid User IDs:",
                        userid
                    );
                    let mut have_valid = false;
                    for ua in valid_cert.userids() {
                        if let Ok(u) = from_utf8(ua.userid().value()) {
                            have_valid = true;
                            wprintln!("  - {}", u);
                        }
                    }
                    if !have_valid {
                        wprintln!("  - Certificate has no valid User IDs.");
                    }
                    return Err(anyhow!(
                        "The certificate does not contain the specified User \
                        ID.  To create a revocation certificate for that User \
                        ID anyways, specify '--force'"
                    ));
                }
            }

            let mut rev = UserIDRevocationBuilder::new()
                .set_reason_for_revocation(reason, message.as_bytes())?;
            rev = rev.set_signature_creation_time(sq.time)?;
            for (critical, notation) in notations {
                rev = rev.add_notation(
                    notation.name(),
                    notation.value(),
                    Some(notation.flags().clone()),
                    *critical,
                )?;
            }
            let rev = rev.build(
                &mut signer,
                &cert,
                &uid,
                None,
            )?;
            Packet::Signature(rev)
        };

        Ok(UserIDRevocation {
            cert,
            revoker,
            revocation_packet,
            userid,
            uid,
        })
    }
}

impl RevocationOutput for UserIDRevocation
{
    fn cert(&self) -> Result<Cert> {
        let cert = Cert::from_packets(vec![
            self.cert.primary_key().key().clone().into(),
            self.uid.clone().into(),
            self.revocation_packet.clone(),
        ].into_iter())?;

        Ok(cert)
    }

    fn comment(&self) -> String {
        let s = format!("Includes a revocation certificate for User ID {}",
                        self.userid);
        // Truncate it, if it is too long.
        if s.len() > 70 {
            format!("{:.70}", s)
        } else {
            s
        }
    }

    fn revoker(&self) -> &Cert {
        &self.revoker
    }
}

pub fn dispatch(
    sq: Sq,
    command: cli::key::UseridCommand,
) -> Result<()> {
    match command {
        cli::key::UseridCommand::Add(c) => userid_add(sq, c)?,
        cli::key::UseridCommand::Revoke(c) => userid_revoke(sq, c)?,
        cli::key::UseridCommand::Strip(c) => userid_strip(sq, c)?,
    }

    Ok(())
}

fn userid_add(
    sq: Sq,
    mut command: cli::key::UseridAddCommand,
) -> Result<()> {
    let cert = if let Some(file) = command.cert_file {
        // If `--output` is not specified, default to writing to
        // stdout, not to the certificate store.
        if command.output.is_none() {
            command.output = Some(FileOrStdout::new(None));
        }

        let input = file.open()?;
        Cert::from_buffered_reader(input)?
    } else if let Some(kh) = command.cert {
        sq.lookup_one(&kh, None, false)?
    } else {
        panic!("--cert or --cert-file is required");
    };

    let mut signer = sq.get_primary_key(&cert, None)?.0;

    // Names, email addresses, and user IDs.
    lint_names(&command.names)?;
    for n in &command.names {
        command.userid.push(UserID::from(n.as_str()));
    }

    lint_emails(&command.emails)?;
    for n in &command.emails {
        command.userid.push(UserID::from_address(None, None, n)?);
    }

    // Make sure the user IDs are in canonical form.  If not, and
    // `--allow-non-canonical-userids` is not set, error out.
    if ! command.allow_non_canonical_userids {
        lint_userids(&command.userid)?;
    }

    // Fail if any of the User IDs to add already exist in the ValidCert
    let cert_userids: Vec<_> =
        cert.userids().map(|u| u.userid().value()).collect();
    let exists: Vec<_> = command
        .userid
        .iter()
        .filter(|s| cert_userids.contains(&s.value()))
        .collect();
    if !exists.is_empty() {
        return Err(anyhow::anyhow!(
            "The certificate already contains the User ID(s) {}.",
            exists.iter().map(|s| format!("{:?}", s)).join(", ")
        ));
    }

    let vcert = cert
        .with_policy(sq.policy, sq.time)
        .with_context(|| {
            format!("Certificate {} is not valid", cert.fingerprint())
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
        .retain(|algo| sq.policy.symmetric_algorithm(*algo).is_ok());
    if symmetric_algorithms.is_empty() {
        symmetric_algorithms.push(Default::default());
    }
    sb = sb.set_preferred_symmetric_algorithms(symmetric_algorithms)?;

    // - hash_algorithms
    let mut hash_algorithms: Vec<_> =
        sb.preferred_hash_algorithms().unwrap_or(&[]).to_vec();
    hash_algorithms.retain(|algo| {
        sq
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
    #[allow(deprecated)]
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
        sb = sb.set_signature_creation_time(sq.time)?;

        let binding = uid.bind(&mut signer, &cert, sb.clone())?;
        add.push(binding.into());
    }

    // Merge the new User IDs into cert.
    let cert = cert.insert_packets(add)?;

    if let Some(output) = command.output {
        let mut sink = output.for_secrets().create_safe(sq.force)?;
        if command.binary {
            cert.as_tsk().serialize(&mut sink)?;
        } else {
            cert.as_tsk().armored().serialize(&mut sink)?;
        }
    } else {
        let cert_store = sq.cert_store_or_else()?;
        cert_store.update(Arc::new(cert.into()))?;
    }

    Ok(())
}

fn userid_strip(
    sq: Sq,
    command: cli::key::UseridStripCommand,
) -> Result<()> {
    let input = command.input.open()?;
    let key = Cert::from_buffered_reader(input)?;

    let orig_cert_valid = key.with_policy(sq.policy, None).is_ok();

    let strip: Vec<_> = command.userid;

    // Make sure that each User ID that the user requested to remove exists in
    // `key`, and *can* be removed.
    let key_userids: Vec<_> =
        key.userids().map(|u| u.userid().value()).collect();

    let missing: Vec<_> = strip
        .iter()
        .filter(|s| !key_userids.contains(&s.value()))
        .collect();
    if !missing.is_empty() {
        return Err(anyhow::anyhow!(
            "The certificate doesn't contain the User ID(s) {}.",
            missing.iter().map(|s| format!("{:?}", s)).join(", ")
        ));
    }

    let cert = key.retain_userids(|uid| {
        // Don't keep User IDs that were selected for removal
        !strip.iter().any(|rm| rm == uid.component())
    });

    if orig_cert_valid {
        if let Err(err) = cert.with_policy(sq.policy, None) {
            wprintln!(
                "Removing the User ID(s) has resulted in a invalid key:
{}

You could create a direct key signature or update the self
signatures on other User IDs to make the key valid again.",
                err
            );
        }
    }

    let mut sink = command.output.for_secrets().create_safe(sq.force)?;
    if command.binary {
        cert.as_tsk().serialize(&mut sink)?;
    } else {
        cert.as_tsk().armored().serialize(&mut sink)?;
    }
    Ok(())
}

/// Revoke a UserID of an existing primary key
///
/// ## Errors
///
/// Returns an error if reading of the [`Cert`] fails, if retrieval of
/// [`NotationData`] fails or if the eventual revocation fails.
pub fn userid_revoke(
    sq: Sq,
    mut command: UseridRevokeCommand,
) -> Result<()> {
    let cert = if let Some(file) = command.cert_file {
        if command.output.is_none() {
            // None means to write to the cert store.  When reading
            // from a file, we want to write to stdout by default.
            command.output = Some(FileOrStdout::new(None));
        }

        let br = file.open()?;
        Cert::from_buffered_reader(br)?
    } else if let Some(kh) = command.cert {
        sq.lookup_one(&kh, None, true)?
    } else {
        panic!("clap enforces --cert or --cert-file");
    };

    let revoker = if let Some(file) = command.revoker_file {
        let br = file.open()?;
        Some(Cert::from_buffered_reader(br)?)
    } else if let Some(kh) = command.revoker {
        Some(sq.lookup_one(&kh, None, true)?)
    } else {
        None
    };

    let notations = parse_notations(command.notation)?;

    let revocation = UserIDRevocation::new(
        &sq,
        command.userid,
        sq.force,
        cert,
        revoker,
        command.reason.into(),
        &command.message,
        &notations,
    )?;

    revocation.write(&sq, command.output, command.binary)?;

    Ok(())
}
