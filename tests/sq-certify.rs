use std::fs::File;
use std::time;
use std::time::Duration;

use sequoia_openpgp as openpgp;
use openpgp::Result;
use openpgp::KeyHandle;
use openpgp::Packet;
use openpgp::PacketPile;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::packet::signature::subpacket::NotationDataFlags;
use openpgp::packet::UserID;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::{Serialize, SerializeInto};

mod common;
use common::Sq;

const P: &StandardPolicy = &StandardPolicy::new();

#[test]
fn sq_certify() -> Result<()> {
    let sq = Sq::new();

    let (_alice, alice_pgp, _alice_rev)
        = sq.key_generate(&[], &["<alice@example.org>"]);
    let (_bob, bob_pgp, _bob_rev)
        = sq.key_generate(&[], &["<bob@example.org>"]);

    // A simple certification.
    let cert = sq.pki_certify(&[], &alice_pgp, &bob_pgp, "<bob@example.org>");
    assert_eq!(cert.bad_signatures().count(), 0,
               "Bad signatures in cert\n\n{}",
               String::from_utf8(cert.armored().to_vec().unwrap()).unwrap());

    let vc = cert.with_policy(P, None).unwrap();

    let mut ok = false;
    for ua in vc.userids() {
        if ua.userid().value() == b"<bob@example.org>" {
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

            ok = true;
            break;
        }
    }
    assert!(ok, "Didn't find user id");

    // No expiry.
    let cert = sq.pki_certify(&["--expiry", "never"],
                              &alice_pgp, &bob_pgp, "<bob@example.org>");
    assert_eq!(cert.bad_signatures().count(), 0,
               "Bad signatures in cert\n\n{}",
               String::from_utf8(cert.armored().to_vec().unwrap()).unwrap());

    let vc = cert.with_policy(P, None).unwrap();

    let mut ok = false;
    for ua in vc.userids() {
        if ua.userid().value() == b"<bob@example.org>" {
            let certifications: Vec<_>
                = ua.certifications().collect();
            assert_eq!(certifications.len(), 1);
            let c = certifications[0];

            assert_eq!(c.trust_signature(), None);
            assert_eq!(c.regular_expressions().count(), 0);
            assert_eq!(c.revocable().unwrap_or(true), true);
            assert_eq!(c.exportable_certification().unwrap_or(true), true);
            assert!(c.signature_validity_period().is_none());

            ok = true;
            break;
        }
    }
    assert!(ok, "Didn't find user id");

    // Have alice certify <bob@example.org> for 0xB0B.
    let cert = sq.pki_certify(
        &["--depth", "10",
          "--amount", "5",
          "--regex", "a",
          "--regex", "b",
          "--local",
          "--non-revocable",
          "--expiry", "1d",
        ],
        &alice_pgp, &bob_pgp, "<bob@example.org>");
    assert_eq!(cert.bad_signatures().count(), 0,
               "Bad signatures in cert\n\n{}",
               String::from_utf8(cert.armored().to_vec().unwrap()).unwrap());

    let vc = cert.with_policy(P, None).unwrap();

    let mut ok = false;
    for ua in vc.userids() {
        if ua.userid().value() == b"<bob@example.org>" {
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

            ok = true;
            break;
        }
    }
    assert!(ok, "Didn't find user id");

    // It should fail if the User ID doesn't exist.
    assert!(sq.pki_certify_p(&[], &alice_pgp, &bob_pgp, "bob", false).is_err());

    // With a notation.
    let cert = sq.pki_certify(
        &[
            "--notation", "foo", "bar",
            "--notation", "!foo", "xyzzy",
            "--notation", "hello@example.org", "1234567890",
        ],
        &alice_pgp, &bob_pgp, "<bob@example.org>");
    assert_eq!(cert.bad_signatures().count(), 0,
               "Bad signatures in cert\n\n{}",
               String::from_utf8(cert.armored().to_vec().unwrap()).unwrap());

    // The standard policy will reject the
    // certification, because it has an unknown
    // critical notation.
    let vc = cert.with_policy(P, None).unwrap();
    for ua in vc.userids() {
        if ua.userid().value() == b"<bob@example.org>" {
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

    let mut ok = false;
    for ua in vc.userids() {
        if ua.userid().value() == b"<bob@example.org>" {
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

            ok = true;
            break;
        }
    }
    assert!(ok, "Didn't find user id");

    Ok(())
}

#[test]
fn sq_certify_creation_time() -> Result<()>
{
    // $ date +'%Y%m%dT%H%M%S%z'; date +'%s'
    let t = 1642692756;
    let t = time::UNIX_EPOCH + time::Duration::new(t, 0);

    let sq = Sq::at(t);

    let alice = "<alice@example.org>";
    let (alice_key, alice_pgp, _alice_rev)
        = sq.key_generate(&[], &[ alice ]);

    let bob = "<bob@other.org>";
    let (_bob_key, bob_pgp, _bob_rev)
        = sq.key_generate(&[], &[ bob ]);


    // Alice certifies bob's key.

    let cert = sq.pki_certify(&[], &alice_pgp, &bob_pgp, bob);

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

    // Alice's certificate expires in 30 days.
    let validity_seconds = 30 * seconds_in_day;
    let validity = time::Duration::new(validity_seconds, 0);

    let creation_time = time::SystemTime::now() - 2 * validity;
    let mut sq = Sq::at(creation_time);

    let alice = "<alice@example.org>";
    let (alice_key, alice_pgp, _) = sq.key_generate(
        &["--expiry", &format!("{}s", validity_seconds) ],
        &[ alice ]);

    // Bob's certificate has the same creation time, but it does not
    // expire.
    let bob = "<bob@other.org>";
    let (_bob_key, bob_pgp, _) = sq.key_generate(&[], &[ bob ]);

    // Alice's expired key certifies bob's not expired key.
    sq.tick(validity_seconds + 1);

    // Make sure using an expired key fails by default.
    assert!(sq.pki_certify_p(
        &[], &alice_pgp, &bob_pgp, bob, false).is_err());

    // Try again.
    let cert = sq.pki_certify(
        &["--allow-not-alive-certifier"],
        &alice_pgp, &bob_pgp, bob);

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

    let delta = seconds_in_day;
    let creation_time =
        time::SystemTime::now() - time::Duration::new(delta, 0);

    let mut sq = Sq::at(creation_time);

    // Create a certificate for alice and immediately revoke it.
    let alice = "<alice@example.org>";
    let (alice_key, alice_pgp, revocation)
        = sq.key_generate(&[], &[ alice ]);

    let revocation = PacketPile::from_file(revocation)
        .expect("can parse revocation certificate");
    let revocation = revocation
        .descendants()
        .filter(|p| {
            if let Packet::Signature(_) = p {
                true
            } else {
                false
            }
        })
        .cloned().collect::<Vec<_>>();

    let alice_key = alice_key.insert_packets(revocation)?;
    {
        let mut file = File::create(&alice_pgp)?;
        alice_key.as_tsk().serialize(&mut file)?;
    }
    eprintln!("Alice:\n{}", sq.inspect(&alice_pgp));

    let bob = "<bob@other.org>";
    let (_bob_key, bob_pgp, _) = sq.key_generate(&[], &[ bob ]);
    eprintln!("Bob:\n{}", sq.inspect(&bob_pgp));

    sq.tick(delta);

    // Make sure using an expired key fails by default.
    assert!(sq.pki_certify_p(
        &[], &alice_pgp, &bob_pgp, bob, false).is_err());

    // Try again.
    let cert = sq.pki_certify(
        &["--allow-revoked-certifier"],
        &alice_pgp, &bob_pgp, bob);

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
    let sq = Sq::new();

    let (alice, alice_pgp, _alice_rev)
        = sq.key_generate(&[], &["<alice@example.org>"]);
    let (bob, bob_pgp, _bob_rev)
        = sq.key_generate(&[], &["<bob@example.org>"]);

    // Import bob's (but not alice's!).
    sq.cert_import(&bob_pgp);

    // Have alice certify bob.
    let found = sq.pki_certify(
        &[], &alice_pgp,
        &bob.fingerprint().to_string(), "<bob@example.org>");

    // Make sure the certificate on stdout is bob and that alice
    // signed it.
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
