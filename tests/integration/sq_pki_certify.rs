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

use super::common::FileOrKeyHandle;
use super::common::Sq;

const P: &StandardPolicy = &StandardPolicy::new();

#[test]
fn sq_pki_certify() -> Result<()> {
    let mut sq = Sq::new();

    let (alice, alice_pgp, _alice_rev)
        = sq.key_generate(&[], &["<alice@example.org>"]);
    let (_bob, bob_pgp, _bob_rev)
        = sq.key_generate(&[], &["<bob@example.org>"]);

    for keystore in [false, true] {
        if keystore {
            sq.key_import(&alice_pgp);
        }

        let alice_handle: FileOrKeyHandle = if keystore {
            alice.key_handle().into()
        } else {
            alice_pgp.clone().into()
        };

        let mut bob_pgp = vec![ bob_pgp.clone() ];

        let mut certification_count = 0;

        // A simple certification.
        sq.tick(1);
        let bob_pgp_new = sq.scratch_file("bob");
        let cert = sq.pki_certify(
            &[], &alice_handle, bob_pgp.last().unwrap(), "<bob@example.org>",
            Some(&*bob_pgp_new));
        bob_pgp.push(bob_pgp_new);
        certification_count += 1;
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

        // No expiration.
        sq.tick(1);
        let bob_pgp_new = sq.scratch_file(None);
        let cert = sq.pki_certify(
            &["--expiration", "never"],
            &alice_handle, bob_pgp.last().unwrap(), "<bob@example.org>",
            Some(&*bob_pgp_new));
        bob_pgp.push(bob_pgp_new);
        certification_count += 1;
        assert_eq!(cert.bad_signatures().count(), 0,
                   "Bad signatures in cert\n\n{}",
                   String::from_utf8(cert.armored().to_vec().unwrap()).unwrap());

        let vc = cert.with_policy(P, None).unwrap();

        let mut ok = false;
        for ua in vc.userids() {
            if ua.userid().value() == b"<bob@example.org>" {
                let certifications: Vec<_>
                    = ua.certifications().collect();
                assert_eq!(certifications.len(), certification_count,
                           "Expected exactly one certification");
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
        sq.tick(1);
        let bob_pgp_new = sq.scratch_file(None);
        let cert = sq.pki_certify(
            &["--depth", "10",
              "--amount", "5",
              "--regex", "a",
              "--regex", "b",
              "--local",
              "--non-revocable",
              "--expiration", "1d",
            ],
            &alice_handle, bob_pgp.last().unwrap(), "<bob@example.org>",
            Some(&*bob_pgp_new));
        bob_pgp.push(bob_pgp_new);
        certification_count += 1;
        assert_eq!(cert.bad_signatures().count(), 0,
                   "Bad signatures in cert\n\n{}",
                   String::from_utf8(cert.armored().to_vec().unwrap()).unwrap());

        let vc = cert.with_policy(P, None).unwrap();

        let mut ok = false;
        for ua in vc.userids() {
            if ua.userid().value() == b"<bob@example.org>" {
                let certifications: Vec<_>
                    = ua.certifications().collect();
                assert_eq!(certifications.len(), certification_count);
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
        assert!(sq.pki_certify_p(
            &[], &alice_handle, bob_pgp.last().unwrap(), "bob",
            None, false).is_err());

        // With a notation.
        sq.tick(1);
        let bob_pgp_new = sq.scratch_file(None);
        let cert = sq.pki_certify(
            &[
                "--notation", "foo", "bar",
                "--notation", "!foo", "xyzzy",
                "--notation", "hello@example.org", "1234567890",
            ],
            &alice_handle, bob_pgp.last().unwrap(), "<bob@example.org>",
            Some(&*bob_pgp_new));
        bob_pgp.push(bob_pgp_new);
        certification_count += 1;
        assert_eq!(cert.bad_signatures().count(), 0,
                   "Bad signatures in cert\n\n{}",
                   String::from_utf8(cert.armored().to_vec().unwrap()).unwrap());

        // The standard policy will reject the
        // certification, because it has an unknown
        // critical notation.
        let vc = cert.with_policy(P, None).unwrap();
        for ua in vc.userids() {
            if ua.userid().value() == b"<bob@example.org>" {
                assert_eq!(
                    ua.bundle().certifications2().count(),
                    certification_count);
                let certifications: Vec<_>
                    = ua.certifications().collect();
                assert_eq!(
                    certifications.len(),
                    // Subtract the bad one.
                    certification_count - 1);
            }
        }

        // Accept the critical notation.
        let p = &mut StandardPolicy::new();
        p.good_critical_notations(&["foo"]);
        let vc = cert.with_policy(p, None).unwrap();

        let mut ok = false;
        for ua in vc.userids() {
            if ua.userid().value() == b"<bob@example.org>" {
                assert_eq!(ua.bundle().certifications2().count(),
                           certification_count);

                let certifications: Vec<_>
                    = ua.certifications().collect();
                assert_eq!(certifications.len(), certification_count);

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
    }
    Ok(())
}

#[test]
fn sq_pki_certify_creation_time() -> Result<()>
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


    for keystore in [false, true] {
        if keystore {
            sq.key_import(&alice_pgp);
        }

        let alice_handle: FileOrKeyHandle = if keystore {
            alice_key.key_handle().into()
        } else {
            alice_pgp.clone().into()
        };

        // Alice certifies bob's key.
        let cert = sq.pki_certify(&[], &alice_handle, &bob_pgp, bob, None);

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
    }

    Ok(())
}

#[test]
fn sq_pki_certify_with_expired_key() -> Result<()>
{
    let seconds_in_day = 24 * 60 * 60;

    // Alice's certificate expires in 30 days.
    let validity_seconds = 30 * seconds_in_day;
    let validity = time::Duration::new(validity_seconds, 0);

    let creation_time = time::SystemTime::now() - 2 * validity;
    let mut sq = Sq::at(creation_time);

    let alice = "<alice@example.org>";
    let (alice_key, alice_pgp, _) = sq.key_generate(
        &["--expiration", &format!("{}s", validity_seconds) ],
        &[ alice ]);

    // Bob's certificate has the same creation time, but it does not
    // expire.
    let bob = "<bob@other.org>";
    let (_bob_key, bob_pgp, _) = sq.key_generate(&[], &[ bob ]);

    for keystore in [false, true] {
        if keystore {
            sq.key_import(&alice_pgp);
        }

        let alice_handle: FileOrKeyHandle = if keystore {
            alice_key.key_handle().into()
        } else {
            alice_pgp.clone().into()
        };

        // Alice's expired key certifies bob's not expired key.
        sq.tick(validity_seconds + 1);

        // Make sure using an expired key fails by default.
        assert!(sq.pki_certify_p(
            &[], &alice_handle, &bob_pgp, bob, Some(&*bob_pgp), false).is_err());
    }

    Ok(())
}

#[test]
fn sq_pki_certify_with_revoked_key() -> Result<()>
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

    for keystore in [false, true] {
        if keystore {
            sq.key_import(&alice_pgp);
        }

        let alice_handle: FileOrKeyHandle = if keystore {
            alice_key.key_handle().into()
        } else {
            alice_pgp.clone().into()
        };

        sq.tick(delta);

        // Make sure using an expired key fails by default.
        assert!(sq.pki_certify_p(
            &[], &alice_handle, &bob_pgp, bob, None, false).is_err());
    }

    Ok(())
}

// Certify a certificate in the cert store.
#[test]
fn sq_pki_certify_using_cert_store() -> Result<()>
{
    let mut sq = Sq::new();

    let (alice_key, alice_pgp, _alice_rev)
        = sq.key_generate(&[], &["<alice@example.org>"]);
    let (bob_key, bob_pgp, _bob_rev)
        = sq.key_generate(&[], &["<bob@example.org>"]);

    // Import bob's (but not yet alice's!).
    sq.cert_import(&bob_pgp);

    let mut certification_count = 0;
    for keystore in [false, true] {
        if keystore {
            sq.key_import(&alice_pgp);
        }

        let alice_handle: FileOrKeyHandle = if keystore {
            alice_key.key_handle().into()
        } else {
            alice_pgp.clone().into()
        };

        sq.tick(1);

        // Have alice certify bob.
        let found = sq.pki_certify(
            &[], &alice_handle,
            bob_key.key_handle(), "<bob@example.org>",
            None);
        certification_count += 1;

        // Make sure the certificate on stdout is bob and that alice
        // signed it.
        assert_eq!(found.fingerprint(), bob_key.fingerprint());
        assert_eq!(found.userids().count(), 1);

        let ua = found.userids().next().expect("have one");
        let certifications: Vec<_> = ua.certifications().collect();
        assert_eq!(certifications.len(), certification_count);
        let certification = certifications.into_iter().next().unwrap();

        assert_eq!(certification.get_issuers().into_iter().next(),
                   Some(KeyHandle::from(alice_key.fingerprint())));
        certification.clone().verify_userid_binding(
            alice_key.primary_key().key(),
            bob_key.primary_key().key(),
            &UserID::from("<bob@example.org>"))
            .expect("valid certification");
    }

    Ok(())
}
