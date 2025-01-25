use crate::integration::common::CertArg;
use crate::integration::common::Sq;

#[test]
fn list() {
    let mut sq = Sq::new();

    let alice_email = "alice@example.org";
    let alice_userid = &format!("Alice <{}>", alice_email);
    let (alice, alice_pgp, _alice_rev)
        = sq.key_generate(&[], &[ alice_userid ]);
    sq.key_import(&alice_pgp);

    let bob_email = "bob@example.org";
    let bob_userid = &format!("Bob <{}>", bob_email);
    let (bob, bob_pgp, _bob_rev)
        = sq.key_generate(&[], &[ bob_userid ]);
    sq.key_import(&bob_pgp);

    let carol_email = "carol@example.org";
    let carol_userid = &format!("Carol <{}>", carol_email);
    let (carol, carol_pgp, _carol_rev)
        = sq.key_generate(&[], &[ carol_userid ]);
    sq.key_import(&carol_pgp);

    // Alice hasn't certified anything.  `sq pki vouch list` with no
    // filter should show nothing, but still return success.
    sq.pki_vouch_list(&[], CertArg::from(&alice), None);

    // Alice hasn't certified Bob, so this should fail.
    assert!(sq.try_pki_vouch_list(
        &[],
        CertArg::from(&alice),
        CertArg::from(&bob)).is_err());

    sq.tick(10);

    // Alice certifies Bob (the certification expires in a day).

    sq.pki_vouch_add(
        &["--expiration", "1d"],
        &alice.key_handle(), &bob.key_handle(), &[bob_userid],
        None);

    // Now listing the certifications for Bob's certificate should
    // work.
    sq.pki_vouch_list(&[], CertArg::from(&alice),
                      CertArg::from(&bob));
    assert!(sq.try_pki_vouch_list(
        &[], CertArg::from(&alice),
        CertArg::from(&carol)).is_err());

    // It won't work after the certification has expired.
    assert!(sq.try_pki_vouch_list(
        &["--time", "+2d"],
        CertArg::from(&alice),
        CertArg::from(&bob)).is_err());

    // Nor will it work before the certification was made.
    assert!(sq.try_pki_vouch_list(
        &["--time", "-5s"],
        CertArg::from(&alice),
        CertArg::from(&bob)).is_err());
}

#[test]
fn list_with_unauthenticated_handle() {
    // Make sure it isn't possible to use --cert-email, etc. with an
    // unauthenticated handle.
    let sq = Sq::new();

    let alice_name = "Alice Lovelace";
    let alice_domain = "example.org";
    let alice_email = &format!("alice@{}", alice_domain);
    let alice_userid = &format!("{} <{}>", alice_name, alice_email);

    let (alice_cert, alice_cert_path, _rev_path)
        = sq.key_generate(&[], &[ alice_userid, ]);

    sq.key_import(&alice_cert_path);

    let bob_name = "Bob Lovelace";
    let bob_domain = "example.org";
    let bob_email = &format!("bob@{}", bob_domain);
    let bob_userid = &format!("{} <{}>", bob_name, bob_email);

    let (bob_cert, bob_cert_path, _rev_path)
        = sq.key_generate(&[], &[ bob_userid, ]);

    sq.key_import(&bob_cert_path);

    sq.pki_vouch_add(
        &["--expiration", "1d"],
        &alice_cert.key_handle(), bob_cert.key_handle(), &[bob_userid],
        None);

    // We need to link a user ID otherwise sq pki vouch list will
    // refuse to list the certificate.
    sq.pki_link_add(
        &["--amount", "40"], alice_cert.key_handle(), &[ alice_userid ]);

    for linked in [false, true] {
        if linked {
            // The second time through we link the certificates and
            // make sure the certificate designator actually work.
            sq.pki_link_add(
                &[], alice_cert.key_handle(), &[ alice_userid ]);
            sq.pki_link_add(
                &[], bob_cert.key_handle(), &[ bob_userid ]);
        }


        sq.pki_vouch_list(&[], CertArg::from(&alice_cert), None);
        assert_eq!(sq.try_pki_vouch_list(&[],
                                         CertArg::UserID(alice_userid),
                                         None).is_ok(),
                   linked);
        assert_eq!(sq.try_pki_vouch_list(&[],
                                         CertArg::Email(alice_email),
                                         None).is_ok(),
                   linked);

        sq.pki_vouch_list(&[],
                          CertArg::from(&alice_cert),
                          CertArg::from(&bob_cert));
        assert_eq!(sq.try_pki_vouch_list(&[],
                                         CertArg::from(&alice_cert),
                                         CertArg::UserID(bob_userid)).is_ok(),
                   linked);
        assert_eq!(sq.try_pki_vouch_list(&[],
                                         CertArg::from(&alice_cert),
                                         CertArg::Email(bob_email)).is_ok(),
                   linked);
        assert_eq!(sq.try_pki_vouch_list(&[],
                                         CertArg::from(&alice_cert),
                                         CertArg::Domain(bob_domain)).is_ok(),
                   linked);
    }
}
