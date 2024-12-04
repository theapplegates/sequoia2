use crate::integration::common::Sq;

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
