use crate::integration::common::Sq;
use crate::integration::common::UserIDArg;

#[test]
fn list_empty() {
    let sq = Sq::new();

    // Listing an empty key store should not be an error.
    sq.pki_link_list(&[]);

    // Listing an empty key store with a pattern (that doesn't
    // match anything) should be.
    assert!(sq.try_pki_link_list(&["not found"]).is_err());

    let (cert, cert_path, _rev_path)
        = sq.key_generate(&[], &[ "alice" ]);
    sq.key_import(cert_path);

    // Not linked => error.
    assert!(sq.try_pki_link_list(&["alice"]).is_err());

    // Not found => error.
    assert!(sq.try_pki_link_list(&["not found"]).is_err());

    // Linked and found => ok.
    sq.pki_link_add(&[], cert.key_handle(), &["alice"]);
    sq.pki_link_list(&["alice"]);
}

#[test]
fn list_uncertified_cert_designator() {
    // Consider a certificate with the following user IDs:
    //
    // - alice@one.org
    // - alice@two.org
    //
    // The user authorizes alice@one.org as a trusted introducer.
    // This means that alice@two.org can be authenticated (trust root
    // -> alice@one.org -> alice@two.org) and can be used as a
    // certificate designator.  Consequently, `sq pki link list
    // --cert-email alice@two.org` should work, and the whole command
    // should succeed because *some* user ID has been linked.

    let mut sq = Sq::new();

    let alice_one_email = "alice@one.org";
    let alice_one_userid = &format!("Alice <{}>", alice_one_email);

    let alice_two_email = "alice@two.org";
    let alice_two_userid = &format!("Alice <{}>", alice_two_email);

    let (alice, alice_pgp, _) = sq.key_generate(
        &[], &[ alice_one_userid, alice_two_userid ]);

    let alice_kh = &alice.key_handle().to_string();

    sq.key_import(&alice_pgp);

    // alice@one.org is not authenticated, and can't be used as a
    // certificate designator.
    assert!(sq.pki_authenticate(
        &[], alice_kh, UserIDArg::Email(alice_one_email)).is_err());
    assert!(sq.try_pki_link_list(&["--cert-email", alice_one_email]).is_err());

    // alice@two.org is not authenticated, and can't be used as a
    // certificate designator.
    assert!(sq.pki_authenticate(
        &[], alice_kh, UserIDArg::Email(alice_two_email)).is_err());
    assert!(sq.try_pki_link_list(&["--cert-email", alice_two_email]).is_err());

    sq.tick(1);

    sq.pki_link_authorize(
        &["--unconstrained"], alice.key_handle(), &[ alice_one_userid ]);

    // alice@one.org is authenticated, so we should be able to use it
    // to designate the certificate.
    assert!(sq.pki_authenticate(
        &[], alice_kh, UserIDArg::Email(alice_one_email)).is_ok());
    sq.pki_link_list(&["--cert-email", alice_one_email]);

    // alice@two.org is authenticated, so we should be able to use it
    // to designate the certificate even though it was not linked.
    assert!(sq.pki_authenticate(
        &[], alice_kh, UserIDArg::Email(alice_two_email)).is_ok());
    sq.pki_link_list(&["--cert-email", alice_two_email]);
}
