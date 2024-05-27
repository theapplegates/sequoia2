use assert_cmd::Command;

use tempfile::TempDir;

use chrono::Duration;

use openpgp::packet::UserID;
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
fn sq_key_userid_revoke() -> Result<()> {
    let userids = &["alice <alice@example.org>", "alice <alice@other.org>"];
    // revoke the last userid
    let userid_revoke = userids.last().unwrap();
    let (tmpdir, cert_path, time) = sq_key_generate(Some(userids))?;
    let cert_path = cert_path.display().to_string();

    let cert = Cert::from_file(&cert_path)?;
    let valid_cert = cert.with_policy(STANDARD_POLICY, Some(time.into()))?;
    let fingerprint = valid_cert.clone().fingerprint();

    let message = "message";

    // revoke for various reasons, with or without notations added, or with
    // a revocation whose reference time is one hour after the creation of the
    // certificate
    for (reason, reason_str, notations, revocation_time) in [
        (ReasonForRevocation::UIDRetired, "retired", None, None),
        (
            ReasonForRevocation::UIDRetired,
            "retired",
            None,
            Some(time + Duration::hours(1)),
        ),
        (
            ReasonForRevocation::UIDRetired,
            "retired",
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
        eprintln!("==========================");
        eprintln!("reason: {}, message: {}, notations: {:?}, time: {:?}",
                  reason, reason_str, notations, revocation_time);

        for keystore in [false, true].into_iter() {
            eprintln!("--------------------------");
            eprintln!("keystore: {}", keystore);

            let home = TempDir::new().unwrap();
            let home = home.path().display().to_string();

            let revocation = &tmpdir.path().join(format!(
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

            if keystore {
                // When using the keystore, we need to import the key.

                let mut cmd = Command::cargo_bin("sq")?;
                cmd.args([
                    "--home", &home,
                    "key",
                    "import",
                    &cert_path,
                ]);
                let output = cmd.output()?;
                if !output.status.success() {
                    panic!(
                        "sq exited with non-zero status code: {}",
                        String::from_utf8(output.stderr)?
                    );
                }
            }

            let mut cmd = Command::cargo_bin("sq")?;
            cmd.args([
                "--home", &home,
                "key",
                "userid",
                "revoke",
                userid_revoke,
                reason_str,
                message,
            ]);

            if keystore {
                cmd.args([
                    "--cert", &cert.fingerprint().to_string(),
                ]);
            } else {
                cmd.args([
                    "--cert-file", &cert_path,
                    "--output", &revocation.display().to_string(),
                ]);
            }

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

            if keystore {
                // When using the keystore, we need to export the
                // revoked certificate.

                let mut cmd = Command::cargo_bin("sq")?;
                cmd.args([
                    "--home", &home,
                    "cert",
                    "export",
                    "--cert", &cert.fingerprint().to_string(),
                ]);
                let output = cmd.output()?;
                if !output.status.success() {
                    panic!(
                        "sq exited with non-zero status code: {}",
                        String::from_utf8(output.stderr)?
                    );
                }
                std::fs::write(&revocation, &output.stdout)
                    .expect(&format!("Writing {}", &revocation.display()));
            }

            // read revocation cert
            let rev = Cert::from_file(&revocation)?;
            assert!(! rev.is_tsk());
            let cert = cert.clone().merge_public(rev)?;
            let valid_cert =
                cert.with_policy(STANDARD_POLICY, revocation_time.map(Into::into))?;

            // whether we found a revocation signature
            let mut found_revoked = false;

            valid_cert.userids().for_each(|x| {
                if x.value() == userid_revoke.as_bytes() {
                    if let RevocationStatus::Revoked(sigs) = x.revocation_status(
                        STANDARD_POLICY,
                        revocation_time.map(Into::into),
                    ) {
                        // there is only one signature packet
                        assert_eq!(sigs.len(), 1);
                        let sig = sigs.into_iter().next().unwrap();

                        // it is a certification revocation
                        assert_eq!(
                            sig.typ(),
                            SignatureType::CertificationRevocation
                        );

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
                panic!("the revoked userid is not found in the revocation cert");
            }
        }
    }

    tmpdir.close()?;

    Ok(())
}

#[test]
fn sq_key_userid_revoke_thirdparty() -> Result<()> {
    let userids = &["alice <alice@example.org>", "alice <alice@other.org>"];
    // revoke the last userid
    let userid_revoke = userids.last().unwrap();

    let (tmpdir, cert_path, _) = sq_key_generate(Some(userids))?;
    let cert_path = cert_path.display().to_string();
    let cert = Cert::from_file(&cert_path)?;

    let (thirdparty_tmpdir, thirdparty_path, thirdparty_time) =
        sq_key_generate(Some(&["bob <bob@example.org>"]))?;
    let thirdparty_path = thirdparty_path.display().to_string();
    let thirdparty_cert = Cert::from_file(&thirdparty_path)?;
    let thirdparty_valid_cert = thirdparty_cert
        .with_policy(STANDARD_POLICY, Some(thirdparty_time.into()))?;
    let thirdparty_fingerprint = thirdparty_valid_cert.clone().fingerprint();

    let message = "message";

    // revoke for various reasons, with or without notations added, or with
    // a revocation whose reference time is one hour after the creation of the
    // certificate
    for (reason, reason_str, notations, revocation_time) in [
        (ReasonForRevocation::UIDRetired, "retired", None, None),
        (
            ReasonForRevocation::UIDRetired,
            "retired",
            None,
            Some(thirdparty_time + Duration::hours(1)),
        ),
        (
            ReasonForRevocation::UIDRetired,
            "retired",
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
        for keystore in [false, true].into_iter() {
            let home = TempDir::new().unwrap();
            let home = home.path().display().to_string();

            let revocation = &tmpdir.path().join(format!(
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

            if keystore {
                // When using the keystore, we need to import the key.

                for path in &[ &cert_path, &thirdparty_path ] {
                    let mut cmd = Command::cargo_bin("sq")?;
                    cmd.args([
                        "--home", &home,
                        "key",
                        "import",
                        &path,
                    ]);
                    let output = cmd.output()?;
                    if !output.status.success() {
                        panic!(
                            "sq exited with non-zero status code: {}",
                            String::from_utf8(output.stderr)?
                        );
                    }
                }
            }

            let mut cmd = Command::cargo_bin("sq")?;
            cmd.args([
                "--home", &home,
                "key",
                "userid",
                "revoke",
                userid_revoke,
                reason_str,
                message,
            ]);

            if keystore {
                cmd.args([
                    "--cert", &cert.fingerprint().to_string(),
                    "--revoker", &thirdparty_cert.fingerprint().to_string(),
                ]);
            } else {
                cmd.args([
                    "--output",
                    &revocation.to_string_lossy(),
                    "--cert-file",
                    &cert_path,
                    "--revoker-file",
                    &thirdparty_path,
                ]);
            }

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

            if keystore {
                // When using the keystore, we need to export the
                // revoked certificate.

                let mut cmd = Command::cargo_bin("sq")?;
                cmd.args([
                    "--home", &home,
                    "cert",
                    "export",
                    "--cert", &cert.fingerprint().to_string(),
                ]);
                let output = cmd.output()?;
                if !output.status.success() {
                    panic!(
                        "sq exited with non-zero status code: {}",
                        String::from_utf8(output.stderr)?
                    );
                }
                std::fs::write(&revocation, &output.stdout)
                    .expect(&format!("Writing {}", &revocation.display()));
            }

            // read revocation cert
            let rev = Cert::from_file(&revocation)?;
            assert!(! rev.is_tsk());
            let revocation_cert = cert.clone().merge_public(rev)?;
            let revocation_valid_cert = revocation_cert
                .with_policy(STANDARD_POLICY, revocation_time.map(Into::into))?;

            // whether we found a revocation signature
            let mut found_revoked = false;

            revocation_valid_cert.userids().for_each(|x| {
                if x.value() == userid_revoke.as_bytes() {
                    if let RevocationStatus::CouldBe(sigs) = x.revocation_status(
                        STANDARD_POLICY,
                        revocation_time.map(Into::into),
                    ) {
                        // there is only one signature packet
                        assert_eq!(sigs.len(), 1);
                        let sig = sigs.into_iter().next().unwrap();

                        // it is a certification revocation
                        assert_eq!(
                            sig.typ(),
                            SignatureType::CertificationRevocation
                        );

                        // the issuer is a thirdparty revoker
                        assert_eq!(
                            sig.get_issuers().into_iter().next().as_ref(),
                            Some(&thirdparty_fingerprint.clone().into())
                        );

                        // the revocation can be verified
                        if sig
                            .clone()
                            .verify_userid_revocation(
                                &thirdparty_cert.primary_key(),
                                &revocation_cert.primary_key(),
                                &UserID::from(*userid_revoke),
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
                    }
                }
            });

            if !found_revoked {
                panic!("the revoked userid is not found in the revocation cert");
            }
        }
    }

    tmpdir.close()?;
    thirdparty_tmpdir.close()?;

    Ok(())
}
