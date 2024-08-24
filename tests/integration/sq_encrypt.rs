use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;
use openpgp::Result;

use crate::integration::common::Sq;

#[test]
fn sq_encrypt_using_cert_store() -> Result<()>
{
    let sq = Sq::new();

    // Generate a key.
    let (cert, key_pgp, _key_rev) = sq.key_generate(
        &["--expiration", "never"],
        &["<alice@example.org>"]);
    let key_pgp = key_pgp.to_str().expect("valid UTF-8");

    // Try to encrypt a message.  This should fail, because we
    // haven't imported the key.
    for kh in cert.keys().map(|ka| KeyHandle::from(ka.fingerprint()))
        .chain(cert.keys().map(|ka| KeyHandle::from(ka.keyid())))
    {
        assert!(
            sq.encrypt_maybe(&["--recipient-cert", &kh.to_string()], b"")
                .is_err());
    }

    // Import the certificate.
    sq.cert_import(key_pgp);

    const MESSAGE: &[u8] = b"\na secret message\n\nor two\n";

    // Now we should be able to encrypt a message to it, and
    // decrypt it.
    for kh in cert.keys().map(|ka| KeyHandle::from(ka.fingerprint()))
        .chain(cert.keys().map(|ka| KeyHandle::from(ka.keyid())))
    {
        let ciphertext = sq.encrypt(
            &["--recipient-cert", &kh.to_string()], MESSAGE);

        let plaintext = sq.decrypt(
            &["--recipient-file", &key_pgp], ciphertext);

        assert_eq!(MESSAGE, plaintext);
    }

    Ok(())
}

#[test]
fn sq_encrypt_recipient_userid() -> Result<()>
{
    let sq = Sq::new();

    // Generate the keys.
    let (alice, alice_pgp, _alice_rev) = sq.key_generate(
        &["--expiration", "never"],
        &["<alice@example.org>"]);
    let alice_pgp = alice_pgp.to_str().expect("valid UTF-8");

    let bob_userids = &[
        "<bob@some.org>",
        "Bob <bob@other.org>",
        "<bob@other.org>",
    ];
    let bob_emails = &[
        "bob@some.org",
        "bob@other.org",
    ];

    let bob_certified_userids = &[
        "Bob <bob@other.org>",
    ];
    let bob_certified_emails = &[
        "bob@other.org",
    ];

    let (bob, bob_pgp, _bob_rev) = sq.key_generate(
        &["--expiration", "never"],
        bob_userids);
    let bob_pgp = bob_pgp.to_str().expect("valid UTF-8");

    // Import the certificates.
    sq.cert_import(alice_pgp);
    sq.cert_import(bob_pgp);

    const MESSAGE: &[u8] = &[0x42; 24 * 1024 + 23];
    let encrypt = |trust_roots: &[&str],
                   recipients: &[(&str, &str)],
                   decryption_keys: &[&str]|
    {
        let mut args = Vec::new();

        for trust_root in trust_roots {
            args.push("--trust-root");
            args.push(trust_root);
        }

        for (option, recipient) in recipients.iter() {
            args.push(option);
            args.push(recipient);
        }

        let result = sq.encrypt_maybe(&args, MESSAGE);

        if decryption_keys.is_empty() {
            assert!(result.is_err(), "should have failed");
        } else {
            let ciphertext = result.expect("should have succeeded");

            let args = decryption_keys.iter()
                .flat_map(|k| vec![ "--recipient-file", k ])
                .collect::<Vec<&str>>();
            let plaintext = sq.decrypt(&args, ciphertext);

            assert_eq!(MESSAGE, plaintext);
        }
    };

    // Encryption by fingerprint should work.
    encrypt(&[],
            &[("--recipient-cert", &bob.fingerprint().to_string())],
            &[&bob_pgp]);

    // Encryption by email address and user id should fail if the
    // binding can't be authenticated.
    for email in bob_emails.iter() {
        encrypt(&[],
                &[("--recipient-email", email)],
                &[]);
    }
    for userid in bob_userids.iter() {
        encrypt(&[],
                &[("--recipient-userid", userid)],
                &[]);
    }

    // Alice certifies Bob's certificate.
    for userid in bob_certified_userids {
        let certification
            = sq.scratch_file(Some(&format!("alice-certifies-{}", userid)[..]));
        sq.pki_certify(&[], alice_pgp, bob_pgp, userid,
                       Some(certification.as_path()));
        sq.cert_import(certification);
    }

    // Still don't use a trust root.  This should still fail.
    for email in bob_emails.iter() {
        encrypt(&[],
                &[("--recipient-email", email)],
                &[]);
    }
    for userid in bob_userids.iter() {
        encrypt(&[],
                &[("--recipient-userid", userid)],
                &[]);
    }

    // Make Alice the trust root.  This should succeed.
    for email in bob_emails.iter() {
        if bob_certified_emails.contains(email) {
            encrypt(&[&alice.fingerprint().to_string()],
                    &[("--recipient-email", email)],
                    &[ &bob_pgp ]);
        } else {
            encrypt(&[&alice.fingerprint().to_string()],
                    &[("--recipient-email", email)],
                    &[]);
        }
    }
    for userid in bob_userids.iter() {
        if bob_certified_userids.contains(userid) {
            encrypt(&[&alice.fingerprint().to_string()],
                    &[("--recipient-userid", userid)],
                    &[ &bob_pgp ]);
        } else {
            encrypt(&[&alice.fingerprint().to_string()],
                    &[("--recipient-userid", userid)],
                    &[]);
        }
    }

    // Make Bob a trust root.  This should succeed for all
    // self-signed user ids.
    for email in bob_emails.iter() {
        encrypt(&[&bob.fingerprint().to_string()],
                &[("--recipient-email", email)],
                &[&bob_pgp]);
    }
    for userid in bob_userids.iter() {
        encrypt(&[&bob.fingerprint().to_string()],
                &[("--recipient-userid", userid)],
                &[&bob_pgp]);
    }

    Ok(())
}

// Encrypt a message to two recipients: one whose certificate is
// in the certificate store, and one whose certificated is in a
// keyring.
#[test]
fn sq_encrypt_keyring() -> Result<()>
{
    let sq = Sq::new();

    // Generate the keys.
    let (alice, alice_pgp, _alice_rev) = sq.key_generate(
        &["--expiration", "never"],
        &["<alice@example.org>"]);
    let alice_pgp = alice_pgp.to_str().expect("valid UTF-8");
    let alice_fpr = alice.fingerprint().to_string();

    let (bob, bob_pgp, _bob_rev) = sq.key_generate(
        &["--expiration", "never"],
        &["<bob@example.org>"]);
    let bob_pgp = bob_pgp.to_str().expect("valid UTF-8");
    let bob_fpr = bob.fingerprint().to_string();

    const MESSAGE: &[u8] = &[0x42; 24 * 1024 + 23];
    let encrypt = |keyrings: &[&str],
                   recipients: &[&str],
                   decryption_keys: &[&str]|
    {
        let mut args = Vec::new();

        for keyring in keyrings.iter() {
            args.push("--keyring");
            args.push(keyring);
        }

        for recipient in recipients.iter() {
            args.push("--recipient-cert");
            args.push(recipient);
        }

        let result = sq.encrypt_maybe(&args, MESSAGE);

        match result {
            Err(err) => {
                assert!(decryption_keys.is_empty(),
                        "Error encrypting message: {}", err);
            }
            Ok(ciphertext) => {
                for key in decryption_keys.iter() {
                    let plaintext
                        = sq.decrypt(&["--recipient-file", &key], &ciphertext);
                    assert_eq!(MESSAGE, plaintext);
                }
            }
        }
    };

    encrypt(&[&alice_pgp, &bob_pgp],
            &[&alice_fpr, &bob_fpr],
            &[&alice_pgp, &bob_pgp]);

    // Import Alice's certificate.
    sq.cert_import(&alice_pgp);

    encrypt(&[&alice_pgp, &bob_pgp],
            &[&alice_fpr, &bob_fpr],
            &[&alice_pgp, &bob_pgp]);

    encrypt(&[&bob_pgp],
            &[&alice_fpr, &bob_fpr],
            &[&alice_pgp, &bob_pgp]);


    Ok(())
}

#[test]
fn sq_encrypt_with_password() -> Result<()>
{
    let sq = Sq::new();

    let password = "hunter2";
    let password_file = sq.base().join("password");
    std::fs::write(&password_file, password)?;

    const MESSAGE: &str = "\na secret message\n\nor two\n";

    let plain_file = sq.base().join("plaintext");
    std::fs::write(&plain_file, MESSAGE)?;

    let cipher_file = sq.base().join("ciphertext");
    let mut cmd = sq.command();
    cmd.args(["encrypt",
              "--with-password-file", &password_file.display().to_string(),
              "--output", &cipher_file.display().to_string(),
              &plain_file.display().to_string()]);
    sq.run(cmd, Some(true));

    let mut cmd = sq.command();
    cmd.args(["decrypt",
              "--password-file", &password_file.display().to_string(),
              &cipher_file.display().to_string()]);
    let output = sq.run(cmd, Some(true));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout, MESSAGE);

    Ok(())
}
