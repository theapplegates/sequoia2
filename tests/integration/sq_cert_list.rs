use super::common::Sq;

#[test]
fn list() {
    let sq = Sq::new();

    let email = "alice@example.org";
    let name = "Alice Lovelace";
    let userid = &format!("{} <{}>", name, email);
    let (cert, cert_path, _rev_path)
        = sq.key_generate(&[], &[ userid ]);

    sq.key_import(&cert_path);
    sq.pki_link_add(&[], cert.key_handle(), &[ userid ]);

    // By fingerprint.
    sq.cert_list(&[&cert.fingerprint().to_string()]);

    // By user ID.
    sq.cert_list(&[userid]);
    sq.cert_list(&["--cert-userid", userid]);

    // By email.
    sq.cert_list(&[email]);
    sq.cert_list(&["--cert-email", email]);

    // By name.
    sq.cert_list(&[name]);

    // By substring.
    sq.cert_list(&["lice"]);
    sq.cert_list(&["LICE"]);
    sq.cert_list(&["example.or"]);
    sq.cert_list(&["ExAmPlE.Or"]);

    // When we use --userid, then we don't do substring matching.
    assert!(sq.cert_list_maybe(&["--cert-userid", &userid[1..]]).is_err());

    // When we use --email, then we don't do substring matching.
    assert!(sq.cert_list_maybe(&["--cert-email", &email[1..]]).is_err());
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
