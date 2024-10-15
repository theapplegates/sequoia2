use std::ffi::OsStr;
use std::path::Path;

use super::common::{Sq, STANDARD_POLICY};

use sequoia_openpgp as openpgp;
use openpgp::{
    Cert,
    Result,
    cert::amalgamation::ValidateAmalgamation,
};

#[test]
fn update_files() -> Result<()> {
    // See https://gitlab.com/sequoia-pgp/sequoia/-/issues/1111
    let now = std::time::SystemTime::now()
        - std::time::Duration::new(60 * 60, 0);

    let sq = Sq::at(now);

    let alice_userid = "<alice@example.org>";
    let (alice, alice_pgp, _alice_rev)
        = sq.key_generate(&[], &["<alice@example.org>"]);
    let (_bob, bob_pgp, _bob_rev)
        = sq.key_generate(&[], &["<bob@example.org>"]);

    // Attest the certifications.
    //
    // public is first merged into private.
    let attest = |sq: &Sq, public: &Path| {
        let priv_file = sq.scratch_file(
            &*format!("{}-priv",
                      public.file_name()
                      .unwrap_or(OsStr::new(""))
                      .to_str().unwrap_or("")));

        sq.toolbox_keyring_merge(
            vec![ public, &alice_pgp ], None,
            &*priv_file);

        let attestation_file = sq.scratch_file(
            &*format!("{}-attestation", public.display()));

        let attestation = sq.key_approvals_update(
            &priv_file, &["--add-all"], &*attestation_file);

        eprintln!("{}", sq.inspect(&attestation_file));

        assert_eq!(attestation.bad_signatures().count(), 0);

        let attestation_ua = attestation.userids().next().unwrap();
        assert_eq!(attestation_ua.attestations().count(), 1);

    };

    // Attest nothing.
    attest(&sq, &alice_pgp);

    // Have Bob certify Alice.
    let alice2_pub_pgp = sq.scratch_file("alice2_pub");
    let alice2 = sq.pki_certify(&[],
                                &bob_pgp,
                                &alice_pgp,
                                &[alice_userid],
                                &*alice2_pub_pgp);
    assert_eq!(alice2.fingerprint(), alice.fingerprint());

    // Attest Bob's certification.
    attest(&sq, &alice2_pub_pgp);

    Ok(())
}

const ALICE_USERID: &str = "<alice@example.org>";
const BOB_USERID: &str = "<bob@example.org>";

fn make_keys(sq: &Sq) -> Result<(Cert, Cert)> {
    let (alice, alice_pgp, _alice_rev)
        = sq.key_generate(&[], &[ALICE_USERID]);
    let (bob, bob_pgp, _bob_rev)
        = sq.key_generate(&[], &[BOB_USERID]);

    sq.key_import(alice_pgp);
    sq.key_import(bob_pgp);

    Ok((alice, bob))
}


#[test]
fn update_all() -> Result<()> {
    // See https://gitlab.com/sequoia-pgp/sequoia/-/issues/1111
    let now = std::time::SystemTime::now()
        - std::time::Duration::new(60 * 60, 0);

    let sq = Sq::at(now);
    let (alice, bob) = make_keys(&sq)?;

    // Attest the zero certifications.
    let attestation = sq.key_approvals_update(
        alice.key_handle(), &["--add-all"], None);

    assert_eq!(attestation.bad_signatures().count(), 0);
    let attestation_ua = attestation.userids().next().unwrap();
    assert_eq!(attestation_ua.attestations().count(), 1);
    assert_eq!(attestation_ua.with_policy(STANDARD_POLICY, None).unwrap()
               .attested_certifications().count(), 0);

    // Have Bob certify Alice.
    let alice2 = sq.pki_certify(&[],
                                bob.key_handle(),
                                alice.key_handle(),
                                &[ALICE_USERID],
                                None);
    assert_eq!(alice2.fingerprint(), alice.fingerprint());

    // Attest Bob's certification.
    let attestation = sq.key_approvals_update(
        &alice.key_handle(), &["--add-all"], None);

    assert_eq!(attestation.bad_signatures().count(), 0);
    let attestation_ua = attestation.userids().next().unwrap();
    assert_eq!(attestation_ua.attestations().count(), 2);
    assert_eq!(attestation_ua.with_policy(STANDARD_POLICY, None).unwrap()
               .attested_certifications().count(), 1);

    // Drop the approval of Bob's certification.
    let attestation = sq.key_approvals_update(
        &alice.key_handle(), &["--remove-all"], None);

    assert_eq!(attestation.bad_signatures().count(), 0);
    let attestation_ua = attestation.userids().next().unwrap();
    assert_eq!(attestation_ua.attestations().count(), 3);
    assert_eq!(attestation_ua.with_policy(STANDARD_POLICY, None).unwrap()
               .attested_certifications().count(), 0);

    Ok(())
}

#[test]
fn update_by() -> Result<()> {
    // See https://gitlab.com/sequoia-pgp/sequoia/-/issues/1111
    let now = std::time::SystemTime::now()
        - std::time::Duration::new(60 * 60, 0);

    let sq = Sq::at(now);
    let (alice, bob) = make_keys(&sq)?;
    let bob_fp = bob.fingerprint().to_string();

    // Attest the zero certifications.
    let attestation = sq.key_approvals_update(
        alice.key_handle(), &["--add-by", &bob_fp], None);

    assert_eq!(attestation.bad_signatures().count(), 0);
    let attestation_ua = attestation.userids().next().unwrap();
    assert_eq!(attestation_ua.attestations().count(), 1);
    assert_eq!(attestation_ua.with_policy(STANDARD_POLICY, None).unwrap()
               .attested_certifications().count(), 0);

    // Have Bob certify Alice.
    let alice2 = sq.pki_certify(&[],
                                bob.key_handle(),
                                alice.key_handle(),
                                &[ALICE_USERID],
                                None);
    assert_eq!(alice2.fingerprint(), alice.fingerprint());

    // Attest Bob's certification.
    let attestation = sq.key_approvals_update(
        &alice.key_handle(), &["--add-by", &bob_fp], None);

    assert_eq!(attestation.bad_signatures().count(), 0);
    let attestation_ua = attestation.userids().next().unwrap();
    assert_eq!(attestation_ua.attestations().count(), 2);
    assert_eq!(attestation_ua.with_policy(STANDARD_POLICY, None).unwrap()
               .attested_certifications().count(), 1);

    // Drop the approval of Bob's certification.
    let attestation = sq.key_approvals_update(
        &alice.key_handle(), &["--remove-by", &bob_fp], None);

    assert_eq!(attestation.bad_signatures().count(), 0);
    let attestation_ua = attestation.userids().next().unwrap();
    assert_eq!(attestation_ua.attestations().count(), 3);
    assert_eq!(attestation_ua.with_policy(STANDARD_POLICY, None).unwrap()
               .attested_certifications().count(), 0);

    Ok(())
}


#[test]
fn update_authenticated() -> Result<()> {
    // See https://gitlab.com/sequoia-pgp/sequoia/-/issues/1111
    let now = std::time::SystemTime::now()
        - std::time::Duration::new(60 * 60, 0);

    let sq = Sq::at(now);
    let (alice, bob) = make_keys(&sq)?;
    let bob_fp = bob.fingerprint().to_string();

    // Have Bob certify Alice.
    let alice2 = sq.pki_certify(&[],
                                bob.key_handle(),
                                alice.key_handle(),
                                &[ALICE_USERID],
                                None);
    assert_eq!(alice2.fingerprint(), alice.fingerprint());

    // Attest the zero certifications.
    let attestation = sq.key_approvals_update(
        alice.key_handle(), &["--add-authenticated"], None);

    assert_eq!(attestation.bad_signatures().count(), 0);
    let attestation_ua = attestation.userids().next().unwrap();
    assert_eq!(attestation_ua.attestations().count(), 1);
    assert_eq!(attestation_ua.with_policy(STANDARD_POLICY, None).unwrap()
               .attested_certifications().count(), 0);

    // Link Bob's cert to his user ID.
    let mut link = sq.command();
    link.args(&["pki", "link", "add", "--cert", &bob_fp, BOB_USERID]);
    sq.run(link, true);

    // Attest Bob's certification.
    let attestation = sq.key_approvals_update(
        &alice.key_handle(), &["--add-authenticated"], None);

    assert_eq!(attestation.bad_signatures().count(), 0);
    let attestation_ua = attestation.userids().next().unwrap();
    assert_eq!(attestation_ua.attestations().count(), 2);
    assert_eq!(attestation_ua.with_policy(STANDARD_POLICY, None).unwrap()
               .attested_certifications().count(), 1);

    Ok(())
}
