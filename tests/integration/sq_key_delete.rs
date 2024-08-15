use sequoia_openpgp as openpgp;
use openpgp::Result;

use super::common::Sq;

#[test]
fn sq_key_delete() -> Result<()> {
    let sq = Sq::new();

    let (cert, cert_file, _rev_file) = sq.key_generate(&[], &["alice"]);
    assert!(cert.is_tsk());

    // Delete all the secret key material from a certificate stored in
    // a file.  Make sure the result contains no secret key material.
    let updated = sq.key_delete(&cert_file, None);
    assert!(! updated.is_tsk());

    // Do the same for a certificate whose secret key material is
    // managed by the keystore.
    sq.key_import(cert_file);

    let cert = sq.key_export(cert.key_handle());
    assert!(cert.is_tsk());

    let updated = sq.key_delete(cert.key_handle(), None);
    assert!(! updated.is_tsk());

    // If we really stripped the secret key material, then `sq key
    // export` will fail.
    assert!(sq.key_export_maybe(cert.key_handle()).is_err());

    Ok(())
}
