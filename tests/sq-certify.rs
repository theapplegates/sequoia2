use std::fs::File;
use std::time;
use std::time::Duration;

use tempfile::TempDir;
use assert_cmd::Command;
use predicates::prelude::*;

use sequoia_openpgp as openpgp;
use openpgp::Result;
use openpgp::cert::prelude::*;
use openpgp::KeyHandle;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::packet::signature::subpacket::NotationDataFlags;
use openpgp::packet::UserID;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::{Serialize, SerializeInto};

const P: &StandardPolicy = &StandardPolicy::new();

#[test]
fn sq_certify() -> Result<()> {
    let tmp_dir = TempDir::new().unwrap();
    let alice_pgp = tmp_dir.path().join("alice.pgp");
    let bob_pgp = tmp_dir.path().join("bob.pgp");

    let (alice, _) =
        CertBuilder::general_purpose(None, Some("alice@example.org"))
        .generate()?;
    let mut file = File::create(&alice_pgp)?;
    alice.as_tsk().serialize(&mut file)?;

    let (bob, _) =
        CertBuilder::general_purpose(None, Some("bob@example.org"))
        .generate()?;
    let mut file = File::create(&bob_pgp)?;
    bob.serialize(&mut file)?;


    // A simple certification.
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("--no-key-store")
        .arg("pki").arg("certify")
        .arg("--certifier-file").arg(alice_pgp.to_str().unwrap())
        .arg(bob_pgp.to_str().unwrap())
        .arg("bob@example.org")
        .assert()
        .success()
        .stdout(predicate::function(|output: &[u8]| -> bool {
            let cert = Cert::from_bytes(output).unwrap();
            assert_eq!(cert.bad_signatures().count(), 0,
                       "Bad signatures in cert\n\n{}",
                       String::from_utf8(cert.armored().to_vec().unwrap()).unwrap());

            let vc = cert.with_policy(P, None).unwrap();

            for ua in vc.userids() {
                if ua.userid().value() == b"bob@example.org" {
                    let certifications: Vec<_>
                        = ua.certifications().collect();
                    assert_eq!(certifications.len(), 1);
                    let c = certifications[0];

                    assert_eq!(c.trust_signature(), None);
                    assert_eq!(c.regular_expressions().count(), 0);
                    assert_eq!(c.revocable().unwrap_or(true), true);
                    assert_eq!(c.exportable_certification().unwrap_or(true), true);
                    // By default, we set a duration.
                    assert!(c.signature_validity_period().is_some());

                    return true;
                }
            }
            false
        },
    ));

    // No expiry.
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("--no-key-store")
        .arg("pki").arg("certify")
        .arg("--certifier-file").arg(alice_pgp.to_str().unwrap())
        .arg(bob_pgp.to_str().unwrap())
        .arg("bob@example.org")
        .args(["--expiry", "never"])
        .assert()
        .success()
        .stdout(predicate::function(|output: &[u8]| -> bool {
            let cert = Cert::from_bytes(output).unwrap();
            assert_eq!(cert.bad_signatures().count(), 0,
                       "Bad signatures in cert\n\n{}",
                       String::from_utf8(cert.armored().to_vec().unwrap()).unwrap());

            let vc = cert.with_policy(P, None).unwrap();

            for ua in vc.userids() {
                if ua.userid().value() == b"bob@example.org" {
                    let certifications: Vec<_>
                        = ua.certifications().collect();
                    assert_eq!(certifications.len(), 1);
                    let c = certifications[0];

                    assert_eq!(c.trust_signature(), None);
                    assert_eq!(c.regular_expressions().count(), 0);
                    assert_eq!(c.revocable().unwrap_or(true), true);
                    assert_eq!(c.exportable_certification().unwrap_or(true), true);
                    assert!(c.signature_validity_period().is_none());

                    return true;
                }
            }

            false
        }));

    // Have alice certify bob@example.org for 0xB0B.
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("--no-key-store")
        .arg("pki").arg("certify")
        .arg("--certifier-file").arg(alice_pgp.to_str().unwrap())
        .arg(bob_pgp.to_str().unwrap())
        .arg("bob@example.org")
        .args(["--depth", "10"])
        .args(["--amount", "5"])
        .args(["--regex", "a"])
        .args(["--regex", "b"])
        .arg("--local")
        .arg("--non-revocable")
        .args(["--expiry", "1d"])
        .assert()
        .success()
        .stdout(predicate::function(|output: &[u8]| -> bool {
            let cert = Cert::from_bytes(output).unwrap();
            assert_eq!(cert.bad_signatures().count(), 0,
                       "Bad signatures in cert\n\n{}",
                       String::from_utf8(cert.armored().to_vec().unwrap()).unwrap());

            let vc = cert.with_policy(P, None).unwrap();

            for ua in vc.userids() {
                if ua.userid().value() == b"bob@example.org" {
                    let certifications: Vec<_>
                        = ua.certifications().collect();
                    assert_eq!(certifications.len(), 1);
                    let c = certifications[0];

                    assert_eq!(c.trust_signature(), Some((10, 5)));
                    assert_eq!(&c.regular_expressions().collect::<Vec<_>>()[..],
                               &[ b"a", b"b" ]);
                    assert_eq!(c.revocable(), Some(false));
                    assert_eq!(c.exportable_certification(), Some(false));
                    assert_eq!(c.signature_validity_period(),
                               Some(Duration::new(24 * 60 * 60, 0)));

                    return true;
                }
            }

            false
        }));

    // It should fail if the User ID doesn't exist.
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("--no-key-store")
        .arg("pki").arg("certify")
        .arg("--certifier-file").arg(alice_pgp.to_str().unwrap())
        .arg(bob_pgp.to_str().unwrap())
        .arg("bob")
        .assert()
        .failure();

    // With a notation.
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("--no-key-store")
        .arg("pki").arg("certify")
        .args(["--notation", "foo", "bar"])
        .args(["--notation", "!foo", "xyzzy"])
        .args(["--notation", "hello@example.org", "1234567890"])
        .arg("--certifier-file").arg(alice_pgp.to_str().unwrap())
        .arg(bob_pgp.to_str().unwrap())
        .arg("bob@example.org")
        .assert()
        .success()
        .stdout(predicate::function(|output: &[u8]| -> bool {
            let cert = Cert::from_bytes(output).unwrap();
            assert_eq!(cert.bad_signatures().count(), 0,
                       "Bad signatures in cert\n\n{}",
                       String::from_utf8(cert.armored().to_vec().unwrap()).unwrap());

            // The standard policy will reject the
            // certification, because it has an unknown
            // critical notation.
            let vc = cert.with_policy(P, None).unwrap();
            for ua in vc.userids() {
                if ua.userid().value() == b"bob@example.org" {
                    assert_eq!(ua.bundle().certifications().len(), 1);
                    let certifications: Vec<_>
                        = ua.certifications().collect();
                    assert_eq!(certifications.len(), 0);
                }
            }

            // Accept the critical notation.
            let p = &mut StandardPolicy::new();
            p.good_critical_notations(&["foo"]);
            let vc = cert.with_policy(p, None).unwrap();

            for ua in vc.userids() {
                if ua.userid().value() == b"bob@example.org" {
                    // There should be a single signature.
                    assert_eq!(ua.bundle().certifications().len(), 1);

                    let certifications: Vec<_>
                        = ua.certifications().collect();
                    assert_eq!(certifications.len(), 1);

                    let c = certifications[0];

                    assert_eq!(c.trust_signature(), None);
                    assert_eq!(c.regular_expressions().count(), 0);
                    assert_eq!(c.revocable().unwrap_or(true), true);
                    assert_eq!(c.exportable_certification().unwrap_or(true), true);
                    // By default, we set a duration.
                    assert!(c.signature_validity_period().is_some());

                    let hr = NotationDataFlags::empty().set_human_readable();
                    let notations = &mut [
                        (NotationData::new("foo", "bar", hr.clone()), false),
                        (NotationData::new("foo", "xyzzy", hr.clone()), false),
                        (NotationData::new("hello@example.org", "1234567890", hr), false)
                    ];

                    for n in c.notation_data() {
                        if n.name() == "salt@notations.sequoia-pgp.org" {
                            continue;
                        }

                        for (m, found) in notations.iter_mut() {
                            if n == m {
                                assert!(!*found);
                                *found = true;
                            }
                        }
                    }
                    for (n, found) in notations.iter() {
                        assert!(found, "Missing: {:?}", n);
                    }

                    return true;
                }
            }

            false
        }));

    Ok(())
}

#[test]
fn sq_certify_creation_time() -> Result<()>
{
    // $ date +'%Y%m%dT%H%M%S%z'; date +'%s'
    let iso8601 = "20220120T163236+0100";
    let t = 1642692756;
    let t = time::UNIX_EPOCH + time::Duration::new(t, 0);

    let dir = TempDir::new()?;

    let gen = |userid: &str| {
        let builder = CertBuilder::new()
            .add_signing_subkey()
            .set_creation_time(t)
            .add_userid(userid);
        builder.generate().map(|(key, _rev)| key)
    };

    // Alice certifies bob's key.

    let alice = "<alice@example.org>";
    let alice_key = gen(alice)?;

    let alice_pgp = dir.path().join("alice.pgp");
    {
        let mut file = File::create(&alice_pgp)?;
        alice_key.as_tsk().serialize(&mut file)?;
    }

    let bob = "<bob@other.org>";
    let bob_key = gen(bob)?;

    let bob_pgp = dir.path().join("bob.pgp");
    {
        let mut file = File::create(&bob_pgp)?;
        bob_key.serialize(&mut file)?;
    }

    // Build up the command line.
    let mut cmd = Command::cargo_bin("sq")?;
    cmd.args(["--no-cert-store",
              "--no-key-store",
              "pki", "certify",
              "--certifier-file", &alice_pgp.to_string_lossy(),
              &bob_pgp.to_string_lossy(), bob,
              "--time", iso8601 ]);

    let assertion = cmd.assert().try_success()?;
    let stdout = String::from_utf8_lossy(&assertion.get_output().stdout);

    let cert = Cert::from_bytes(&*stdout)?;
    assert_eq!(cert.bad_signatures().count(), 0,
               "Bad signatures in cert\n\n{}",
               String::from_utf8(cert.armored().to_vec().unwrap()).unwrap());

    let vc = cert.with_policy(P, t)?;

    assert_eq!(vc.primary_key().creation_time(), t);

    let mut userid = None;
    for u in vc.userids() {
        if u.userid().value() == bob.as_bytes() {
            userid = Some(u);
            break;
        }
    }

    if let Some(userid) = userid {
        let certifications: Vec<_> = userid.certifications().collect();
        assert_eq!(certifications.len(), 1);
        let certification = certifications.into_iter().next().unwrap();

        assert_eq!(certification.get_issuers().into_iter().next(),
                   Some(KeyHandle::from(alice_key.fingerprint())));

        assert_eq!(certification.signature_creation_time(), Some(t));
    } else {
        panic!("missing user id");
    }

    Ok(())
}

#[test]
fn sq_certify_with_expired_key() -> Result<()>
{
    let seconds_in_day = 24 * 60 * 60;

    let validity = time::Duration::new(30 * seconds_in_day, 0);
    let creation_time = time::SystemTime::now() - 2 * validity;

    let dir = TempDir::new()?;

    // Alice's expired key certifies bob's not expired key.

    let alice = "<alice@example.org>";
    let alice_key = CertBuilder::new()
        .add_signing_subkey()
        .set_creation_time(creation_time)
        .set_validity_period(validity)
        .add_userid(alice)
        .generate()
        .map(|(key, _rev)| key)?;

    let alice_pgp = dir.path().join("alice.pgp");
    {
        let mut file = File::create(&alice_pgp)?;
        alice_key.as_tsk().serialize(&mut file)?;
    }

    // Bob's key has the same creation time, but it does not expire.
    let bob = "<bob@other.org>";
    let bob_key = CertBuilder::new()
        .add_signing_subkey()
        .set_creation_time(creation_time)
        .add_userid(bob)
        .generate()
        .map(|(key, _rev)| key)?;

    let bob_pgp = dir.path().join("bob.pgp");
    {
        let mut file = File::create(&bob_pgp)?;
        bob_key.serialize(&mut file)?;
    }

    // Make sure using an expired key fails by default.
    let mut cmd = Command::cargo_bin("sq")?;
    cmd.args(["--no-cert-store",
              "--no-key-store",
              "pki", "certify",
              "--certifier-file", &alice_pgp.to_string_lossy(),
              &bob_pgp.to_string_lossy(), bob ]);
    cmd.assert().failure();


    // Try again.
    let mut cmd = Command::cargo_bin("sq")?;
    cmd.args(["--no-cert-store",
              "--no-key-store",
              "pki", "certify",
              "--allow-not-alive-certifier",
              "--certifier-file", &alice_pgp.to_string_lossy(),
              &bob_pgp.to_string_lossy(), bob ]);

    let assertion = cmd.assert().try_success()?;
    let stdout = String::from_utf8_lossy(&assertion.get_output().stdout);

    let cert = Cert::from_bytes(&*stdout)?;
    assert_eq!(cert.bad_signatures().count(), 0,
               "Bad signatures in cert\n\n{}",
               String::from_utf8(cert.armored().to_vec().unwrap()).unwrap());

    let vc = cert.with_policy(P, None)?;

    assert!(
        creation_time.duration_since(vc.primary_key().creation_time()).unwrap()
            < time::Duration::new(1, 0));

    let mut userid = None;
    for u in vc.userids() {
        if u.userid().value() == bob.as_bytes() {
            userid = Some(u);
            break;
        }
    }

    if let Some(userid) = userid {
        let certifications: Vec<_> = userid.certifications().collect();
        assert_eq!(certifications.len(), 1);
        let certification = certifications.into_iter().next().unwrap();

        assert_eq!(certification.get_issuers().into_iter().next(),
                   Some(KeyHandle::from(alice_key.fingerprint())));
    } else {
        panic!("missing user id");
    }

    Ok(())
}

#[test]
fn sq_certify_with_revoked_key() -> Result<()>
{
    let seconds_in_day = 24 * 60 * 60;

    let creation_time =
        time::SystemTime::now() - time::Duration::new(seconds_in_day, 0);

    let dir = TempDir::new()?;

    // Alice's revoked key certifies bob's not expired key.

    let alice = "<alice@example.org>";
    let (alice_key, revocation) = CertBuilder::new()
        .add_signing_subkey()
        .set_creation_time(creation_time)
        .add_userid(alice)
        .generate()?;
    let alice_key = alice_key.insert_packets(revocation)?;

    let alice_pgp = dir.path().join("alice.pgp");
    {
        let mut file = File::create(&alice_pgp)?;
        alice_key.as_tsk().serialize(&mut file)?;
    }

    // Bob's key has the same creation time, but it does not expire.
    let bob = "<bob@other.org>";
    let bob_key = CertBuilder::new()
        .add_signing_subkey()
        .set_creation_time(creation_time)
        .add_userid(bob)
        .generate()
        .map(|(key, _rev)| key)?;

    let bob_pgp = dir.path().join("bob.pgp");
    {
        let mut file = File::create(&bob_pgp)?;
        bob_key.serialize(&mut file)?;
    }

    // Make sure using an expired key fails by default.
    let mut cmd = Command::cargo_bin("sq")?;
    cmd.args(["--no-cert-store",
              "--no-key-store",
              "pki", "certify",
              "--certifier-file", &alice_pgp.to_string_lossy(),
              &bob_pgp.to_string_lossy(), bob ]);
    cmd.assert().failure();


    // Try again.
    let mut cmd = Command::cargo_bin("sq")?;
    cmd.args(["--no-cert-store",
              "--no-key-store",
              "pki", "certify",
              "--allow-revoked-certifier",
              "--certifier-file", &alice_pgp.to_string_lossy(),
              &bob_pgp.to_string_lossy(), bob ]);

    let assertion = cmd.assert().try_success()?;
    let stdout = String::from_utf8_lossy(&assertion.get_output().stdout);

    let cert = Cert::from_bytes(&*stdout)?;
    assert_eq!(cert.bad_signatures().count(), 0,
               "Bad signatures in cert\n\n{}",
               String::from_utf8(cert.armored().to_vec().unwrap()).unwrap());

    let vc = cert.with_policy(P, None)?;

    assert!(
        creation_time.duration_since(vc.primary_key().creation_time()).unwrap()
            < time::Duration::new(1, 0));

    let mut userid = None;
    for u in vc.userids() {
        if u.userid().value() == bob.as_bytes() {
            userid = Some(u);
            break;
        }
    }

    if let Some(userid) = userid {
        let certifications: Vec<_> = userid.certifications().collect();
        assert_eq!(certifications.len(), 1);
        let certification = certifications.into_iter().next().unwrap();

        assert_eq!(certification.get_issuers().into_iter().next(),
                   Some(KeyHandle::from(alice_key.fingerprint())));
    } else {
        panic!("missing user id");
    }

    Ok(())
}

// Certify a certificate in the cert store.
#[test]
fn sq_certify_using_cert_store() -> Result<()>
{
    let dir = TempDir::new()?;

    let certd = dir.path().join("cert.d").display().to_string();
    std::fs::create_dir(&certd).expect("mkdir works");

    let alice_pgp = dir.path().join("alice.pgp").display().to_string();
    let bob_pgp = dir.path().join("bob.pgp").display().to_string();

    // Generate keys.
    let mut cmd = Command::cargo_bin("sq")?;
    cmd.args(["--cert-store", &certd,
              "key", "generate",
              "--expiry", "never",
              "--userid", "<alice@example.org>",
              "--output", &alice_pgp]);
    cmd.assert().success();

    let alice = Cert::from_file(&alice_pgp)?;

    let mut cmd = Command::cargo_bin("sq")?;
    cmd.args(["--cert-store", &certd,
              "key", "generate",
              "--expiry", "never",
              "--userid", "<bob@example.org>",
              "--output", &bob_pgp]);
    cmd.assert().success();

    let bob = Cert::from_file(&bob_pgp)?;

    // Import bob's (but not alice's!).
    let mut cmd = Command::cargo_bin("sq")?;
    cmd.args(["--cert-store", &certd,
              "cert", "import", &bob_pgp]);
    cmd.assert().success();


    // Have alice certify bob.
    let mut cmd = Command::cargo_bin("sq")?;
    cmd.args(["--cert-store", &certd,
              "pki", "certify",
              "--certifier-file", &alice_pgp,
              &bob.fingerprint().to_string(),
              "<bob@example.org>"]);

    let output = cmd.output().expect("success");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success());

    // Make sure the certificate on stdout is bob and that alice
    // signed it.
    let parser = CertParser::from_bytes(stdout.as_bytes())
        .expect("valid");
    let found = parser.collect::<Result<Vec<Cert>>>()
        .expect("valid");

    assert_eq!(found.len(), 1,
               "stdout:\n{}\nstderr:\n{}",
               stdout, stderr);
    let found = found.into_iter().next().expect("have one");

    assert_eq!(found.fingerprint(), bob.fingerprint());
    assert_eq!(found.userids().count(), 1);

    let ua = found.userids().next().expect("have one");
    let certifications: Vec<_> = ua.certifications().collect();
    assert_eq!(certifications.len(), 1);
    let certification = certifications.into_iter().next().unwrap();

    assert_eq!(certification.get_issuers().into_iter().next(),
               Some(KeyHandle::from(alice.fingerprint())));
    certification.clone().verify_userid_binding(
        alice.primary_key().key(),
        bob.primary_key().key(),
        &UserID::from("<bob@example.org>"))
        .expect("valid certification");

    Ok(())
}
