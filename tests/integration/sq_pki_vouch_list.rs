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

    let alice_kh = &alice_cert.fingerprint().to_string();

    sq.key_import(&alice_cert_path);

    let bob_name = "Bob Lovelace";
    let bob_domain = "example.org";
    let bob_email = &format!("bob@{}", bob_domain);
    let bob_userid = &format!("{} <{}>", bob_name, bob_email);

    let (bob_cert, bob_cert_path, _rev_path)
        = sq.key_generate(&[], &[ bob_userid, ]);

    let bob_kh = &bob_cert.fingerprint().to_string();

    sq.key_import(&bob_cert_path);

    sq.pki_vouch_add(
        &["--expiration", "1d"],
        &alice_cert.key_handle(), bob_cert.key_handle(), &[bob_userid],
        None);

    // We need to link a user ID otherwise sq pki link list will
    // refuse to list the certificate.
    sq.pki_link_add(
        &["--amount", "40"], alice_cert.key_handle(), &[ alice_userid ]);

    let list = |args: &[&str], success: bool| {
        let mut cmd = sq.command();
        cmd.args([ "pki", "vouch", "list" ]);
        for arg in args {
            cmd.arg(arg);
        }

        let output = sq.run(cmd, None);
        if output.status.success() {
            assert!(success);
        } else {
            assert!(! success);
        }
    };

    list(&["--certifier", alice_kh], true);
    list(&["--certifier-userid", alice_userid], false);
    list(&["--certifier-email", alice_email], false);
    list(&["--certifier-domain", alice_domain], false);
    list(&["--certifier-grep", &alice_name[1..]], false);

    list(&["--certifier", alice_kh, "--cert", bob_kh], true);
    list(&["--certifier", alice_kh, "--cert-userid", bob_userid], false);
    list(&["--certifier", alice_kh, "--cert-email", bob_email], false);
    list(&["--certifier", alice_kh, "--cert-domain", bob_domain], false);
    list(&["--certifier", alice_kh, "--cert-grep", &bob_name[1..]], false);
}
