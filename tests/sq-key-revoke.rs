use assert_cmd::Command;

use chrono::Duration;
use openpgp::parse::Parse;
use openpgp::types::ReasonForRevocation;
use openpgp::types::RevocationStatus;
use openpgp::types::SignatureType;
use openpgp::Cert;
use openpgp::Packet;
use openpgp::PacketPile;
use openpgp::Result;
use sequoia_openpgp as openpgp;

mod common;
use common::compare_notations;
use common::sq_key_generate;
use common::STANDARD_POLICY;

#[test]
fn sq_key_revoke() -> Result<()> {
    let (tmpdir, path, time) = sq_key_generate(None)?;

    let cert = Cert::from_file(&path)?;
    let valid_cert = cert.with_policy(STANDARD_POLICY, Some(time.into()))?;
    let fingerprint = &valid_cert.clone().fingerprint();

    let message = "message";

    // revoke for various reasons, with or without notations added, or with
    // a revocation whose reference time is one hour after the creation of the
    // certificate
    for (reason, reason_str, notations, revocation_time) in [
        (
            ReasonForRevocation::KeyCompromised,
            "compromised",
            None,
            None,
        ),
        (
            ReasonForRevocation::KeyCompromised,
            "compromised",
            None,
            Some(time + Duration::hours(1)),
        ),
        (
            ReasonForRevocation::KeyCompromised,
            "compromised",
            Some(&[("foo", "bar"), ("hallo@sequoia-pgp.org", "VALUE")]),
            None,
        ),
        (ReasonForRevocation::KeyRetired, "retired", None, None),
        (
            ReasonForRevocation::KeyRetired,
            "retired",
            None,
            Some(time + Duration::hours(1)),
        ),
        (
            ReasonForRevocation::KeyRetired,
            "retired",
            Some(&[("foo", "bar"), ("hallo@sequoia-pgp.org", "VALUE")]),
            None,
        ),
        (ReasonForRevocation::KeySuperseded, "superseded", None, None),
        (
            ReasonForRevocation::KeySuperseded,
            "superseded",
            None,
            Some(time + Duration::hours(1)),
        ),
        (
            ReasonForRevocation::KeySuperseded,
            "superseded",
            Some(&[("foo", "bar"), ("hallo@sequoia-pgp.org", "VALUE")]),
            None,
        ),
        (ReasonForRevocation::Unspecified, "unspecified", None, None),
        (
            ReasonForRevocation::Unspecified,
            "unspecified",
            None,
            Some(time + Duration::hours(1)),
        ),
        (
            ReasonForRevocation::Unspecified,
            "unspecified",
            Some(&[("foo", "bar"), ("hallo@sequoia-pgp.org", "VALUE")]),
            None,
        ),
    ] {
        let revocation = &path.parent().unwrap().join(format!(
            "revocation_{}_{}_{}.rev",
            reason_str,
            if notations.is_some() {
                "notations"
            } else {
                "no_notations"
            },
            if revocation_time.is_some() {
                "time"
            } else {
                "no_time"
            }
        ));

        let mut cmd = Command::cargo_bin("sq")?;
        cmd.args([
            "--no-cert-store",
            "--no-key-store",
            "key",
            "revoke",
            "--output",
            &revocation.to_string_lossy(),
            "--certificate-file",
            &path.to_string_lossy(),
            reason_str,
            message,
        ]);
        if let Some(notations) = notations {
            for (k, v) in notations {
                cmd.args(["--notation", k, v]);
            }
        }
        if let Some(time) = revocation_time {
            cmd.args([
                "--time",
                &time.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            ]);
        }
        let output = cmd.output()?;
        if !output.status.success() {
            panic!(
                "sq exited with non-zero status code: {}",
                String::from_utf8(output.stderr)?
            );
        }

        // We should get the primary key and the revocation signature.
        let packet_pile = PacketPile::from_file(&revocation)?;

        assert_eq!(
            packet_pile.children().count(),
            2,
            "expected the primary key and the revocation signature"
        );

        if let Some(Packet::Signature(sig)) = packet_pile.path_ref(&[1]) {
            // the issuer is the certificate owner
            assert_eq!(
                sig.get_issuers().into_iter().next(),
                Some(fingerprint.into())
            );

            let cert = Cert::from_file(&path)?;
            let revoked_cert = cert.insert_packets(sig.clone()).unwrap();
            let status = revoked_cert
                .with_policy(STANDARD_POLICY, revocation_time.map(Into::into))
                .unwrap()
                .revocation_status();

            println!("{:?}", sig);
            println!("{:?}", status);
            // Verify the revocation.
            assert!(matches!(status, RevocationStatus::Revoked(_)));

            // it is a key revocation
            assert_eq!(sig.typ(), SignatureType::KeyRevocation);

            // our reason for revocation and message matches
            assert_eq!(
                sig.reason_for_revocation(),
                Some((reason, message.as_bytes()))
            );

            // the notations of the revocation match the ones
            // we passed in
            compare_notations(sig, notations)?;
        } else {
            panic!("Expected a signature, got: {:?}", packet_pile);
        }
    }

    tmpdir.close()?;

    Ok(())
}

#[test]
fn sq_key_revoke_thirdparty() -> Result<()> {
    let (tmpdir, path, _) = sq_key_generate(None)?;
    let cert = Cert::from_file(&path)?;

    let (thirdparty_tmpdir, thirdparty_path, thirdparty_time) =
        sq_key_generate(Some(&["bob <bob@example.org"]))?;
    let thirdparty_cert = Cert::from_file(&thirdparty_path)?;
    let thirdparty_valid_cert = thirdparty_cert
        .with_policy(STANDARD_POLICY, Some(thirdparty_time.into()))?;
    let thirdparty_fingerprint = &thirdparty_valid_cert.clone().fingerprint();

    let message = "message";

    // revoke for various reasons, with or without notations added, or with
    // a revocation whose reference time is one hour after the creation of the
    // certificate
    for (reason, reason_str, notations, revocation_time) in [
        (
            ReasonForRevocation::KeyCompromised,
            "compromised",
            None,
            None,
        ),
        (
            ReasonForRevocation::KeyCompromised,
            "compromised",
            None,
            Some(thirdparty_time + Duration::hours(1)),
        ),
        (
            ReasonForRevocation::KeyCompromised,
            "compromised",
            Some(&[("foo", "bar"), ("hallo@sequoia-pgp.org", "VALUE")]),
            None,
        ),
        (ReasonForRevocation::KeyRetired, "retired", None, None),
        (
            ReasonForRevocation::KeyRetired,
            "retired",
            None,
            Some(thirdparty_time + Duration::hours(1)),
        ),
        (
            ReasonForRevocation::KeyRetired,
            "retired",
            Some(&[("foo", "bar"), ("hallo@sequoia-pgp.org", "VALUE")]),
            None,
        ),
        (ReasonForRevocation::KeySuperseded, "superseded", None, None),
        (
            ReasonForRevocation::KeySuperseded,
            "superseded",
            None,
            Some(thirdparty_time + Duration::hours(1)),
        ),
        (
            ReasonForRevocation::KeySuperseded,
            "superseded",
            Some(&[("foo", "bar"), ("hallo@sequoia-pgp.org", "VALUE")]),
            None,
        ),
        (ReasonForRevocation::Unspecified, "unspecified", None, None),
        (
            ReasonForRevocation::Unspecified,
            "unspecified",
            None,
            Some(thirdparty_time + Duration::hours(1)),
        ),
        (
            ReasonForRevocation::Unspecified,
            "unspecified",
            Some(&[("foo", "bar"), ("hallo@sequoia-pgp.org", "VALUE")]),
            None,
        ),
    ] {
        let revocation = &path.parent().unwrap().join(format!(
            "revocation_{}_{}_{}.rev",
            reason_str,
            if notations.is_some() {
                "notations"
            } else {
                "no_notations"
            },
            if revocation_time.is_some() {
                "time"
            } else {
                "no_time"
            }
        ));

        let mut cmd = Command::cargo_bin("sq")?;
        cmd.args([
            "--no-cert-store",
            "--no-key-store",
            "key",
            "revoke",
            "--output",
            &revocation.to_string_lossy(),
            "--certificate-file",
            &path.to_string_lossy(),
            "--revocation-file",
            &thirdparty_path.to_string_lossy(),
            reason_str,
            message,
        ]);
        if let Some(notations) = notations {
            for (k, v) in notations {
                cmd.args(["--notation", k, v]);
            }
        }
        if let Some(time) = revocation_time {
            cmd.args([
                "--time",
                &time.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            ]);
        }
        let output = cmd.output()?;
        if !output.status.success() {
            panic!(
                "sq exited with non-zero status code: {}",
                String::from_utf8(output.stderr)?
            );
        }

        // read revocation cert
        let revocation_cert = Cert::from_file(&revocation)?;
        assert!(! revocation_cert.is_tsk());

        // evaluate revocation status
        let status = revocation_cert.revocation_status(
            STANDARD_POLICY, revocation_time.map(Into::into));
        if let RevocationStatus::CouldBe(sigs) = status {
            // there is only one signature packet
            assert_eq!(sigs.len(), 1);
            let sig = sigs.into_iter().next().unwrap();

            // it is a key revocation
            assert_eq!(sig.typ(), SignatureType::KeyRevocation);

            // the issuer is a thirdparty revoker
            assert_eq!(
                sig.get_issuers().into_iter().next().as_ref(),
                Some(&thirdparty_fingerprint.clone().into())
            );

            // the revocation can be verified
            if sig
                .clone()
                .verify_primary_key_revocation(
                    &thirdparty_cert.primary_key(),
                    &cert.primary_key(),
                )
                .is_err()
            {
                panic!("revocation is not valid")
            }

            // our reason for revocation and message matches
            assert_eq!(
                sig.reason_for_revocation(),
                Some((reason, message.as_bytes()))
            );

            // the notations of the revocation match the ones
            // we passed in
            compare_notations(sig, notations)?;
        } else {
            panic!("there are no signatures in {:?}", status);
        }
    }

    tmpdir.close()?;
    thirdparty_tmpdir.close()?;

    Ok(())
}
