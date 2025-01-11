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
    let bob_key_handle = &bob.key_handle().to_string()[..];
    sq.key_import(&bob_pgp);

    let carol_email = "carol@example.org";
    let carol_userid = &format!("Carol <{}>", carol_email);
    let (carol, carol_pgp, _carol_rev)
        = sq.key_generate(&[], &[ carol_userid ]);
    let carol_key_handle = &carol.key_handle().to_string()[..];
    sq.key_import(&carol_pgp);

    // Alice hasn't certified anything.  `sq pki vouch list` with no
    // filter should show nothing, but still return success.
    sq.pki_vouch_list(&[], alice.key_handle());

    // Alice hasn't certified Bob, so this should fail.
    assert!(sq.try_pki_vouch_list(
        &["--cert", bob_key_handle], alice.key_handle()).is_err());

    sq.tick(10);

    // Alice certifies Bob (the certification expires in a day).

    sq.pki_vouch_add(
        &["--expiration", "1d"],
        &alice.key_handle(), bob.key_handle(), &[bob_userid],
        None);

    // Now listing the certifications for Bob's certificate should
    // work.
    sq.pki_vouch_list(&["--cert", bob_key_handle], alice.key_handle());
    assert!(sq.try_pki_vouch_list(
        &["--cert", carol_key_handle], alice.key_handle()).is_err());

    // It won't work after the certification has expired.
    assert!(sq.try_pki_vouch_list(
        &["--time", "+2d", "--cert", bob_key_handle], alice.key_handle()).is_err());

    // Nor will it work before the certification was made.
    assert!(sq.try_pki_vouch_list(
        &["--time", "-5s", "--cert", bob_key_handle], alice.key_handle()).is_err());
}
