use super::common::Sq;
use super::common::UserIDArg;

#[test]
fn list() {
    let sq = Sq::new();

    let alice_name = "Alice Lovelace";

    // Self-signed and linked.
    let alice_authenticated_domain = "example.org";
    let alice_authenticated_email
        = &format!("alice@{}", alice_authenticated_domain);
    let alice_authenticated_userid
        = &format!("{} <{}>", alice_name, alice_authenticated_email);
    let alice_name = "Alice Lovelace";

    // Self-signed, but not linked.
    let alice_unauthenticated_domain = "some.org";
    let alice_unauthenticated_email
        = &format!("alice@{}", alice_unauthenticated_domain);
    let alice_unauthenticated_userid
        = &format!("{} <{}>", alice_name, alice_unauthenticated_email);

    // Self-signed, and partially (but insufficiently) authenticated.
    let alice_insufficient_domain = "insufficient.org";
    let alice_insufficient_email
        = &format!("alice@{}", alice_insufficient_domain);
    let alice_insufficient_userid
        = &format!("{} <{}>", alice_name, alice_insufficient_email);

    let (alice_cert, alice_cert_path, _rev_path)
        = sq.key_generate(
            &[],
            &[
                alice_authenticated_userid,
                alice_unauthenticated_userid,
                alice_insufficient_userid,
            ]);

    sq.key_import(&alice_cert_path);
    sq.pki_link_add(&[], alice_cert.key_handle(), &[ alice_authenticated_userid ]);
    sq.pki_link_add(&["--amount=1"], alice_cert.key_handle(),
                    &[ alice_insufficient_userid ]);

    // Not self-signed, but linked.
    let alice_petname_domain = "other.org";
    let alice_petname_email
        = &format!("alice@{}", alice_petname_domain);
    let alice_petname_userid
        = &format!("{} <{}>", alice_name, alice_petname_email);

    sq.pki_link_add(&[], alice_cert.key_handle(),
                    &[ UserIDArg::AddUserID(alice_petname_userid) ]);

    let unknown_domain = "unknown.org";
    let unknown_email = &format!("alice@{}", unknown_domain);
    let unknown_userid = &format!("{} <{}>", alice_name, unknown_email);

    let list = |args: &[&str], success: bool, gossip_success: bool| {
        assert_eq!(sq.cert_list_maybe(args).is_ok(), success);

        let mut gossip_args: Vec<&str> = args.to_vec();
        gossip_args.push("--gossip");
        assert_eq!(sq.cert_list_maybe(&gossip_args[..]).is_ok(), gossip_success);
    };

    // By fingerprint.
    list(&[&alice_cert.fingerprint().to_string()], true, true);
    list(&["--cert", &alice_cert.fingerprint().to_string()], true, true);
    // By key ID.
    list(&[&alice_cert.keyid().to_string()], true, true);
    list(&["--cert", &alice_cert.keyid().to_string()], true, true);

    // By user ID.
    list(&[alice_authenticated_userid], true, true);
    list(&["--cert-userid", alice_authenticated_userid], true, true);

    list(&[alice_unauthenticated_userid], false, true);
    list(&["--cert-userid", alice_unauthenticated_userid], false, true);

    list(&[alice_insufficient_userid], false, true);
    list(&["--cert-userid", alice_insufficient_userid], false, true);

    list(&[alice_petname_userid], true, true);
    list(&["--cert-userid", alice_petname_userid], true, true);

    list(&[unknown_userid], false, false);
    list(&["--cert-userid", unknown_userid], false, false);

    // By email.
    list(&[alice_authenticated_email], true, true);
    list(&["--cert-email", alice_authenticated_email], true, true);

    list(&[alice_unauthenticated_email], false, true);
    list(&["--cert-email", alice_unauthenticated_email], false, true);

    list(&[alice_insufficient_email], false, true);
    list(&["--cert-email", alice_insufficient_email], false, true);

    list(&[alice_petname_email], true, true);
    list(&["--cert-email", alice_petname_email], true, true);

    list(&[unknown_email], false, false);
    list(&["--cert-email", unknown_email], false, false);

    // By domain.
    list(&[alice_authenticated_domain], true, true);
    list(&["--cert-domain", alice_authenticated_domain], true, true);

    list(&[alice_unauthenticated_domain], false, true);
    list(&["--cert-domain", alice_unauthenticated_domain], false, true);

    list(&[alice_insufficient_domain], false, true);
    list(&["--cert-domain", alice_insufficient_domain], false, true);

    list(&[alice_petname_domain], true, true);
    list(&["--cert-domain", alice_petname_domain], true, true);

    list(&[unknown_domain], false, false);
    list(&["--cert-domain", unknown_domain], false, false);

    // Grep.
    list(&[alice_name], true, true);
    list(&["--cert-grep", alice_name], true, true);

    list(&[&alice_authenticated_userid[1..]], true, true);
    list(&["--cert-grep", &alice_authenticated_userid[1..]], true, true);

    list(&[&alice_unauthenticated_userid[1..]], false, true);
    list(&["--cert-grep", &alice_unauthenticated_userid[1..]], false, true);

    list(&[&alice_insufficient_userid[1..]], false, true);
    list(&["--cert-grep", &alice_insufficient_userid[1..]], false, true);

    list(&[&alice_petname_userid[1..]], true, true);
    list(&["--cert-grep", &alice_petname_userid[1..]], true, true);

    list(&[&unknown_userid[1..]], false, false);
    list(&["--cert-grep", &unknown_userid[1..]], false, false);

    // By substring.
    list(&["lice"], true, true);
    list(&["LICE"], true, true);
    list(&["example.or"], true, true);
    list(&["ExAmPlE.Or"], true, true);

    // When we use --userid, then we don't do substring matching.
    list(&["--cert-userid", &alice_authenticated_userid[1..]], false, false);

    // When we use --email, then we don't do substring matching.
    list(&["--cert-email", &alice_authenticated_email[1..]], false, false);
}

/// Check that multiple simultaneous queries work.
#[test]
fn list_multiple_queries() {
    let sq = Sq::new();

    let alice_email = "alice@example.org";
    let alice_name = "Alice Lovelace";
    let alice_userid = &format!("{} <{}>", alice_name, alice_email);
    let (alice_cert, alice_cert_path, _rev_path)
        = sq.key_generate(&[], &[ alice_userid ]);

    sq.key_import(&alice_cert_path);

    let alice_petname_email = "alice@alice.org";
    let alice_petname_userid
        = &format!("{} <{}>", alice_name, alice_petname_email);

    let bob_email = "bob@example.org";
    let bob_name = "Bob";
    let bob_userid = &format!("{} <{}>", bob_name, bob_email);
    let (bob_cert, bob_cert_path, _rev_path)
        = sq.key_generate(&[], &[ bob_userid ]);

    sq.key_import(&bob_cert_path);

    let bob_petname_email = "bob@bob.org";
    let bob_petname_userid
        = &format!("{} <{}>", bob_name, bob_petname_email);

    let unknown_domain = "unknown.org";
    let unknown_email = "alice@unknown.org";
    //let unknown_userid = &format!("Unknown <{}>", unknown_email);

    // We don't link the self-signed user IDs, just the petnames.
    sq.pki_link_add(&[], alice_cert.key_handle(),
                    &[UserIDArg::AddUserID(alice_petname_userid)]);
    sq.pki_link_add(&[], bob_cert.key_handle(),
                    &[UserIDArg::AddUserID(bob_petname_userid)]);

    let list = |args: &[&str], success: bool, gossip_success: bool| {
        assert_eq!(sq.cert_list_maybe(args).is_ok(), success);

        let mut gossip_args: Vec<&str> = args.to_vec();
        gossip_args.push("--gossip");
        assert_eq!(sq.cert_list_maybe(&gossip_args[..]).is_ok(), gossip_success);
    };

    // Smoke test: make sure we the individual queries work.
    list(&[alice_email], false, true);
    list(&["--cert-email", alice_email], false, true);

    list(&[bob_email], false, true);
    list(&["--cert-email", bob_email], false, true);

    list(&[alice_petname_email], true, true);
    list(&["--cert-email", alice_petname_email], true, true);

    list(&[bob_petname_email], true, true);
    list(&["--cert-email", bob_petname_email], true, true);

    list(&[unknown_email], false, false);
    list(&["--cert-email", unknown_email], false, false);

    list(&["--cert-domain", "example.org"], false, true);
    list(&["--cert-domain", "alice.org"], true, true);
    list(&["--cert-domain", "bob.org"], true, true);
    list(&["--cert-domain", unknown_domain], false, false);

    // Multiple queries where all queries have an authenticated match.
    list(&["--cert-email", alice_petname_email,
           "--cert-email", bob_petname_email],
         true, true);
    list(&["--cert-domain", "alice.org",
           "--cert-domain", "bob.org"],
         true, true);
    list(&["--cert", &alice_cert.key_handle().to_string(),
           "--cert-domain", "bob.org"],
         true, true);
    list(&["--cert-domain", "alice.org",
           "--cert-domain", "bob.org",
           "--cert", &alice_cert.key_handle().to_string()],
         true, true);

    // Multiple queries where one query has a match, but that match
    // doesn't authenticate.
    list(&["--cert-email", alice_email,
           "--cert-email", bob_petname_email],
         false, true);
    list(&["--cert-email", alice_petname_email,
           "--cert-email", bob_email],
         false, true);
    list(&["--cert-email", alice_petname_email,
           "--cert-email", unknown_email],
         false, false);

    list(&["--cert-domain", "example.org",
           "--cert-domain", "bob.org"],
         false, true);
    list(&["--cert-domain", "example.org",
           "--cert-domain", unknown_domain],
         false, false);
}

#[test]
fn list_empty() {
    let sq = Sq::new();

    // Listing an empty certificate store should not be an error.
    sq.cert_list(&[]);

    // Listing an empty certificate store with a pattern (that doesn't
    // match anything) should be.
    assert!(sq.cert_list_maybe(&["not found"]).is_err());

    let (cert, cert_path, _rev_path)
        = sq.key_generate(&[], &[ "alice" ]);
    sq.key_import(cert_path);

    // Not linked => error.
    assert!(sq.cert_list_maybe(&["alice"]).is_err());
    // Not found => error.
    assert!(sq.cert_list_maybe(&["not found"]).is_err());

    // Linked and found => ok.
    sq.pki_link_add(&[], cert.key_handle(), &["alice"]);
    sq.cert_list(&["alice"]);
}

/// Tests that listing a cert without user IDs works.
#[test]
fn list_no_userids() {
    let sq = Sq::new();
    let (cert, cert_path, _rev_path)
        = sq.key_generate::<&str>(&[], &[]);
    sq.key_import(&cert_path);
    let fp = cert.fingerprint().to_string();

    // When listing by fingerprint, the certificate is considered
    // authenticated.
    let output = sq.cert_list(&[&fp]);
    assert!(std::str::from_utf8(&output).unwrap().contains(&fp));

    let output = sq.cert_list(&["--gossip", &fp]);
    assert!(std::str::from_utf8(&output).unwrap().contains(&fp));
}
