use std::collections::HashSet;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Fingerprint;
use openpgp::Result;
use openpgp::cert::amalgamation::ValidAmalgamation;
use openpgp::parse::Parse;
use openpgp::types::RevocationStatus;

use super::common::Sq;
use super::common::STANDARD_POLICY;

#[test]
fn sq_key_delete() -> Result<()> {
    let sq = Sq::new();

    let (cert, cert_file, _rev_file) = sq.key_generate(&[], &["alice"]);
    assert!(cert.is_tsk());

    // Delete all the secret key material from a certificate stored in
    // a file.  Make sure the result contains no secret key material.
    let updated = sq.key_delete(&cert_file,
                                std::path::PathBuf::from("-").as_path());
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

#[test]
fn unbound_subkey() {
    // Make sure we don't delete secret key material if there is an
    // unbound subkey.

    let sq = Sq::new();

    let cert_path = sq.test_data()
        .join("keys")
        .join("unbound-subkey.pgp");

    let cert = Cert::from_file(&cert_path).expect("can read");
    let vc = cert.with_policy(STANDARD_POLICY, sq.now())
        .expect("valid cert");

    // One subkey should be considered invalid.
    let bound: HashSet<Fingerprint>
        = HashSet::from_iter(vc.keys().map(|ka| ka.fingerprint()));
    let all: HashSet<Fingerprint>
        = HashSet::from_iter(cert.keys().map(|ka| ka.fingerprint()));
    assert!(bound.len() < all.len());

    let result = sq.key_delete(&cert_path, None);
    for ka in result.keys() {
        if bound.contains(&ka.fingerprint()) {
            assert!(! ka.has_secret());
        } else {
            assert!(ka.has_secret());
        }
    }
}

#[test]
fn soft_revoked_subkey() {
    // Make sure we can delete a soft revoked subkey.

    let sq = Sq::new();

    let cert_path = sq.test_data()
        .join("keys")
        .join("soft-revoked-subkey.pgp");

    let cert = Cert::from_file(&cert_path).expect("can read");
    let vc = cert.with_policy(STANDARD_POLICY, sq.now())
        .expect("valid cert");

    // Make sure the revoked key is there and is really revoked.
    let mut revoked = None;
    for k in vc.keys().subkeys() {
        if let RevocationStatus::Revoked(_) = k.revocation_status() {
            assert!(revoked.is_none(),
                    "Only expected a single revoked subkey");
            revoked = Some(k.key_handle());
        }
    }
    if revoked.is_none() {
        panic!("Expected a revoked subkey, but didn't fine one");
    }

    let updated = sq.key_delete(cert_path, None);
    assert!(! updated.is_tsk());
}

#[test]
fn hard_revoked_subkey() {
    // Make sure we can delete a hard revoked subkey.

    let sq = Sq::new();

    let cert_path = sq.test_data()
        .join("keys")
        .join("hard-revoked-subkey.pgp");

    let cert = Cert::from_file(&cert_path).expect("can read");
    let vc = cert.with_policy(STANDARD_POLICY, sq.now())
        .expect("valid cert");

    // Make sure the revoked key is there and is really revoked.
    let mut revoked = None;
    for k in vc.keys().subkeys() {
        if let RevocationStatus::Revoked(_) = k.revocation_status() {
            assert!(revoked.is_none(),
                    "Only expected a single revoked subkey");
            revoked = Some(k.key_handle());
        }
    }
    if revoked.is_none() {
        panic!("Expected a revoked subkey, but didn't fine one");
    }

    let updated = sq.key_delete(cert_path, None);
    assert!(! updated.is_tsk());
}

#[test]
fn sha1_subkey() {
    // Make sure we can't delete secret key material if there is a
    // subkey that is bound using SHA-1.

    let sq = Sq::new();

    let cert_path = sq.test_data()
        .join("keys")
        .join("sha1-subkey-priv.pgp");

    let cert = Cert::from_file(&cert_path).expect("can read");
    let vc = cert.with_policy(STANDARD_POLICY, sq.now())
        .expect("valid cert");

    // Make sure the subkey key is there and really uses SHA-1.
    let valid_subkeys: Vec<_> = vc.keys().subkeys()
        .map(|ka| ka.fingerprint())
        .collect();
    let all_subkeys: Vec<_> = cert.keys().subkeys()
        .map(|ka| ka.fingerprint())
        .collect();

    assert_eq!(valid_subkeys.len(), 0);
    assert_eq!(all_subkeys.len(), 1);

    assert!(sq.try_key_delete(cert_path, None).is_err());
}
