use assert_cmd::Command;

use chrono::Duration;
use openpgp::packet::Key;
use openpgp::parse::Parse;
use openpgp::types::ReasonForRevocation;
use openpgp::types::RevocationStatus;
use openpgp::types::SignatureType;
use openpgp::Cert;
use openpgp::Result;
use sequoia_openpgp as openpgp;

mod common;
use common::compare_notations;
use common::sq_key_generate;
use common::STANDARD_POLICY;

#[test]
fn sq_key_subkey_generate_authentication_subkey() -> Result<()> {
    let (tmpdir, path, _) = sq_key_generate(None).unwrap();
    let output = path.parent().unwrap().join("new_key.pgp");

    let mut cmd = Command::cargo_bin("sq")?;
    cmd.args([
        "--no-cert-store",
        "key",
        "subkey",
        "add",
        "--output",
        &output.to_string_lossy(),
        "--can-authenticate",
        &path.to_string_lossy(),
    ]);
    cmd.assert().success();

    let cert = Cert::from_file(&output)?;
    let valid_cert = cert.with_policy(STANDARD_POLICY, None)?;

    assert_eq!(
        valid_cert.keys().filter(|x| x.for_authentication()).count(),
        2
    );
    tmpdir.close()?;
    Ok(())
}

#[test]
fn sq_key_subkey_generate_encryption_subkey() -> Result<()> {
    let (tmpdir, path, _) = sq_key_generate(None).unwrap();
    let output = path.parent().unwrap().join("new_key.pgp");

    let mut cmd = Command::cargo_bin("sq")?;
    cmd.args([
        "--no-cert-store",
        "key",
        "subkey",
        "add",
        "--output",
        &output.to_string_lossy(),
        "--can-encrypt=universal",
        &path.to_string_lossy(),
    ]);
    cmd.assert().success();

    let cert = Cert::from_file(&output)?;
    let valid_cert = cert.with_policy(STANDARD_POLICY, None)?;

    assert_eq!(
        valid_cert
            .keys()
            .filter(|x| x.for_storage_encryption())
            .count(),
        2
    );
    assert_eq!(
        valid_cert
            .keys()
            .filter(|x| x.for_transport_encryption())
            .count(),
        2
    );
    tmpdir.close()?;
    Ok(())
}

#[test]
fn sq_key_subkey_generate_signing_subkey() -> Result<()> {
    let (tmpdir, path, _) = sq_key_generate(None).unwrap();
    let output = path.parent().unwrap().join("new_key.pgp");

    let mut cmd = Command::cargo_bin("sq")?;
    cmd.args([
        "--no-cert-store",
        "key",
        "subkey",
        "add",
        "--output",
        &output.to_string_lossy(),
        "--can-sign",
        &path.to_string_lossy(),
    ]);
    cmd.assert().success();

    let cert = Cert::from_file(&output)?;
    let valid_cert = cert.with_policy(STANDARD_POLICY, None)?;

    assert_eq!(valid_cert.keys().filter(|x| x.for_signing()).count(), 2);
    tmpdir.close()?;
    Ok(())
}

#[test]
fn sq_key_subkey_revoke() -> Result<()> {
    let (tmpdir, path, time) = sq_key_generate(None)?;

    let cert = Cert::from_file(&path)?;
    let valid_cert = cert.with_policy(STANDARD_POLICY, Some(time.into()))?;
    let fingerprint = valid_cert.clone().fingerprint();
    let subkey: Key<_, _> = valid_cert
        .with_policy(STANDARD_POLICY, Some(time.into()))
        .unwrap()
        .keys()
        .subkeys()
        .nth(0)
        .unwrap()
        .key()
        .clone();
    let subkey_fingerprint = subkey.fingerprint();
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
            "key",
            "subkey",
            "revoke",
            "--output",
            &revocation.to_string_lossy(),
            "--certificate-file",
            &path.to_string_lossy(),
            &subkey_fingerprint.to_string(),
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
            panic!("sq exited with non-zero status code: {:?}", output.stderr);
        }

        // whether we found a revocation signature
        let mut found_revoked = false;

        // read revocation cert
        let cert = Cert::from_file(&revocation)?;
        assert!(! cert.is_tsk());
        let valid_cert =
            cert.with_policy(STANDARD_POLICY, revocation_time.map(Into::into))?;
        valid_cert
            .with_policy(STANDARD_POLICY, revocation_time.map(Into::into))
            .unwrap()
            .keys()
            .subkeys()
            .for_each(|x| {
                if x.fingerprint() == subkey_fingerprint {
                    let status = x.revocation_status(
                        STANDARD_POLICY,
                        revocation_time.map(Into::into),
                    );

                    // the subkey is revoked
                    assert!(matches!(status, RevocationStatus::Revoked(_)));

                    if let RevocationStatus::Revoked(sigs) = status {
                        // there is only one signature packet
                        assert_eq!(sigs.len(), 1);
                        let sig = sigs.into_iter().next().unwrap();

                        // it is a subkey revocation
                        assert_eq!(sig.typ(), SignatureType::SubkeyRevocation);

                        // the issuer is the certificate owner
                        assert_eq!(
                            sig.get_issuers().into_iter().next().as_ref(),
                            Some(&fingerprint.clone().into())
                        );

                        // our reason for revocation and message matches
                        assert_eq!(
                            sig.reason_for_revocation(),
                            Some((reason, message.as_bytes()))
                        );

                        // the notations of the revocation match the ones
                        // we passed in
                        assert!(compare_notations(sig, notations).is_ok());

                        found_revoked = true;
                    }
                }
            });

        if !found_revoked {
            panic!("the revoked subkey is not found in the revocation cert");
        }
    }

    tmpdir.close()?;

    Ok(())
}

#[test]
fn sq_key_subkey_revoke_thirdparty() -> Result<()> {
    let (tmpdir, path, time) = sq_key_generate(None)?;
    let (thirdparty_tmpdir, thirdparty_path, thirdparty_time) =
        sq_key_generate(Some(&["bob <bob@example.org"]))?;

    let cert = Cert::from_file(&path)?;
    let valid_cert = cert.with_policy(STANDARD_POLICY, Some(time.into()))?;
    let subkey: Key<_, _> = valid_cert
        .with_policy(STANDARD_POLICY, Some(time.into()))
        .unwrap()
        .keys()
        .subkeys()
        .nth(0)
        .unwrap()
        .key()
        .clone();
    let subkey_fingerprint = subkey.fingerprint();

    let thirdparty_cert = Cert::from_file(&thirdparty_path)?;
    let thirdparty_valid_cert = thirdparty_cert
        .with_policy(STANDARD_POLICY, Some(thirdparty_time.into()))?;
    let thirdparty_fingerprint = thirdparty_valid_cert.clone().fingerprint();

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
            "key",
            "subkey",
            "revoke",
            "--output",
            &revocation.to_string_lossy(),
            "--certificate-file",
            &path.to_string_lossy(),
            "--revocation-file",
            &thirdparty_path.to_string_lossy(),
            &subkey_fingerprint.to_string(),
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
            panic!("sq exited with non-zero status code: {:?}", output.stderr);
        }

        // whether we found a revocation signature
        let mut found_revoked = false;

        // read revocation cert
        let cert = Cert::from_file(&revocation)?;
        assert!(! cert.is_tsk());
        let valid_cert =
            cert.with_policy(STANDARD_POLICY, revocation_time.map(Into::into))?;

        assert_eq!(valid_cert.userids().count(), 1);
        valid_cert
            .with_policy(STANDARD_POLICY, revocation_time.map(Into::into))
            .unwrap()
            .keys()
            .subkeys()
            .for_each(|x| {
                if x.fingerprint() == subkey_fingerprint {
                    if let RevocationStatus::CouldBe(sigs) = x
                        .revocation_status(
                            STANDARD_POLICY,
                            revocation_time.map(Into::into),
                        )
                    {
                        // there is only one signature packet
                        assert_eq!(sigs.len(), 1);
                        let sig = sigs.into_iter().next().unwrap();

                        // it is a subkey revocation
                        assert_eq!(sig.typ(), SignatureType::SubkeyRevocation);

                        // the issuer is a thirdparty revoker
                        assert_eq!(
                            sig.get_issuers().into_iter().next().as_ref(),
                            Some(&thirdparty_fingerprint.clone().into())
                        );

                        // the revocation can be verified
                        if sig
                            .clone()
                            .verify_subkey_revocation(
                                &thirdparty_cert.primary_key(),
                                &cert.primary_key(),
                                &subkey,
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
                        assert!(compare_notations(sig, notations).is_ok());

                        found_revoked = true;
                    } else {
                        panic!("there are no signatures in {:?}", x);
                    }
                }
            });

        if !found_revoked {
            panic!("the revoked subkey is not found in the revocation cert");
        }
    }

    tmpdir.close()?;
    thirdparty_tmpdir.close()?;

    Ok(())
}
