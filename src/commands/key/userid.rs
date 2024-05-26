use std::str::from_utf8;
use std::time::SystemTime;

use anyhow::Context;

use anyhow::anyhow;
use itertools::Itertools;

use openpgp::armor::Kind;
use openpgp::armor::Writer;
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
use sequoia_openpgp as openpgp;

use crate::Sq;
use crate::cli::key::UseridRevokeCommand;
use crate::cli::types::FileOrStdout;
use crate::cli;
use crate::common::NULL_POLICY;
use crate::common::RevocationOutput;
use crate::common::get_secret_signer;
use crate::common::read_cert;
use crate::common::read_secret;
use crate::common::userid::lint_userids;
use crate::parse_notations;

/// Handle the revocation of a User ID
struct UserIDRevocation<'a, 'store, 'rstore> {
    sq: &'a Sq<'store, 'rstore>,
    cert: Cert,
    secret: Cert,
    revocation_packet: Packet,
    first_party_issuer: bool,
    userid: String,
    uid: UserID,
}

impl<'a, 'store, 'rstore> UserIDRevocation<'a, 'store, 'rstore> {
    /// Create a new UserIDRevocation
    pub fn new(
        sq: &'a Sq<'store, 'rstore>,
        userid: String,
        force: bool,
        cert: Cert,
        secret: Option<Cert>,
        reason: ReasonForRevocation,
        message: &str,
        notations: &[(bool, NotationData)],
    ) -> Result<Self> {
        let (secret, mut signer)
            = get_secret_signer(sq, &cert, secret.as_ref())?;

        let first_party_issuer = secret.fingerprint() == cert.fingerprint();
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
            sq,
            cert,
            secret,
            revocation_packet,
            first_party_issuer,
            userid,
            uid,
        })
    }
}

impl<'a, 'store, 'rstore> RevocationOutput
    for UserIDRevocation<'a, 'store, 'rstore>
{
    /// Write the revocation certificate to output
    fn write(
        &self,
        output: FileOrStdout,
        binary: bool,
        force: bool,
    ) -> Result<()> {
        let mut output = output.create_safe(force)?;

        // First, build a minimal revocation certificate containing
        // the primary key, the revoked component, and the revocation
        // signature.
        let rev_cert = Cert::from_packets(vec![
            self.cert.primary_key().key().clone().into(),
            self.uid.clone().into(),
            self.revocation_packet.clone(),
        ].into_iter())?;

        if binary {
            rev_cert.serialize(&mut output)
                .context("serializing revocation certificate")?;
        } else {
            // Add some more helpful ASCII-armor comments.
            let mut more: Vec<String> = vec![];

            // First, the thing that is being revoked.
            more.push(
                "including a revocation to revoke the User ID".to_string(),
            );
            more.push(format!("{}", self.userid));

            if !self.first_party_issuer {
                // Then if it was issued by a third-party.
                more.push("issued by".to_string());
                more.push(self.secret.fingerprint().to_spaced_hex());
                // This information may be published so only consider
                // self-signed user IDs to avoid leaking information
                // about the user's web of trust.
                let sanitized_uid = self.sq.best_userid(&self.secret, false);
                // Truncate it, if it is too long.
                more.push(format!("{:.70}", sanitized_uid));
            }

            let headers = &self.cert.armor_headers();
            let headers: Vec<(&str, &str)> = headers
                .iter()
                .map(|s| ("Comment", s.as_str()))
                .chain(more.iter().map(|value| ("Comment", value.as_str())))
                .collect();

            let mut writer =
                Writer::with_headers(&mut output, Kind::PublicKey, headers)?;
            rev_cert.serialize(&mut writer)
                .context("serializing revocation certificate")?;
            writer.finalize()?;
        }
        Ok(())
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
    command: cli::key::UseridAddCommand,
) -> Result<()> {
    let input = command.input.open()?;
    let key = Cert::from_buffered_reader(input)?;

    // Make sure the user IDs are in canonical form.  If not, and
    // `--allow-non-canonical-userids` is not set, error out.
    if ! command.allow_non_canonical_userids {
        lint_userids(&command.userid)?;
    }

    // Fail if any of the User IDs to add already exist in the ValidCert
    let key_userids: Vec<_> =
        key.userids().map(|u| u.userid().value()).collect();
    let exists: Vec<_> = command
        .userid
        .iter()
        .filter(|s| key_userids.contains(&s.value()))
        .collect();
    if !exists.is_empty() {
        return Err(anyhow::anyhow!(
            "The certificate already contains the User ID(s) {}.",
            exists.iter().map(|s| format!("{:?}", s)).join(", ")
        ));
    }

    let mut pk = match sq.get_primary_keys(&[key.clone()], None) {
        Ok(keys) => {
            assert!(
                keys.len() == 1,
                "Expect exactly one result from get_primary_keys()"
            );
            keys.into_iter().next().unwrap().0
        }
        Err(error) => {
            return Err(error)
        }
    };

    let vcert = key
        .with_policy(sq.policy, sq.time)
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

        let binding = uid.bind(&mut pk, &key, sb.clone())?;
        add.push(binding.into());
    }

    // Merge additional User IDs into key
    let cert = key.insert_packets(add)?;

    let mut sink = command.output.for_secrets().create_safe(sq.force)?;
    if command.binary {
        cert.as_tsk().serialize(&mut sink)?;
    } else {
        cert.as_tsk().armored().serialize(&mut sink)?;
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
    command: UseridRevokeCommand,
) -> Result<()> {
    let cert = read_cert(command.input.as_deref())?;

    let secret = read_secret(command.secret_key_file.as_deref())?;

    let notations = parse_notations(command.notation)?;

    let revocation = UserIDRevocation::new(
        &sq,
        command.userid,
        sq.force,
        cert,
        secret,
        command.reason.into(),
        &command.message,
        &notations,
    )?;

    revocation.write(command.output, command.binary, sq.force)?;

    Ok(())
}
