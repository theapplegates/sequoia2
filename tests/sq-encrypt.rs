use assert_cmd::Command;
use tempfile::TempDir;

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;
use openpgp::Result;
use openpgp::cert::prelude::*;
use openpgp::parse::Parse;

mod integration {
    use super::*;

    #[test]
    fn sq_encrypt_using_cert_store() -> Result<()>
    {
        let dir = TempDir::new()?;

        let certd = dir.path().join("cert.d").display().to_string();
        std::fs::create_dir(&certd).expect("mkdir works");
        let key_pgp = dir.path().join("key.pgp").display().to_string();

        // Generate a key.
        let mut cmd = Command::cargo_bin("sq")?;
        cmd.args(["--cert-store", &certd,
                  "key", "generate",
                  "--expiration", "never",
                  "--userid", "<alice@example.org>",
                  "--output", &key_pgp]);
        cmd.assert().success();

        let cert = Cert::from_file(&key_pgp)?;

        // Try to encrypt a message.  This should fail, because we
        // haven't imported the key.
        for kh in cert.keys().map(|ka| KeyHandle::from(ka.fingerprint()))
            .chain(cert.keys().map(|ka| KeyHandle::from(ka.keyid())))
        {
            let mut cmd = Command::cargo_bin("sq")?;
            cmd.args(["--cert-store", &certd,
                      "encrypt",
                      "--recipient-cert",
                      &kh.to_string()])
                .write_stdin("a secret message")
                .assert().failure();
        }

        // Import the key.
        let mut cmd = Command::cargo_bin("sq")?;
        cmd.args(["--cert-store", &certd,
                  "cert", "import", &key_pgp]);
        cmd.assert().success();

        const MESSAGE: &str = "\na secret message\n\nor two\n";

        // Now we should be able to encrypt a message to it, and
        // decrypt it.
        for kh in cert.keys().map(|ka| KeyHandle::from(ka.fingerprint()))
            .chain(cert.keys().map(|ka| KeyHandle::from(ka.keyid())))
        {
            let mut cmd = Command::cargo_bin("sq")?;
            cmd.args(["--cert-store", &certd,
                      "encrypt",
                      "--recipient-cert",
                      &kh.to_string()])
                .write_stdin(MESSAGE);

            let output = cmd.output().expect("success");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(output.status.success(),
                    "encryption succeeds for {}\nstdout:\n{}\nstderr:\n{}",
                    kh, stdout, stderr);

            let mut cmd = Command::cargo_bin("sq")?;
            cmd.args(["decrypt",
                      "--recipient-file",
                      &key_pgp])
                .write_stdin(stdout.as_bytes());

            let output = cmd.output().expect("success");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(output.status.success(),
                    "decryption succeeds for {}\nstdout:\n{}\nstderr:\n{}",
                    kh, stdout, stderr);
        }

        Ok(())
    }

    #[test]
    fn sq_encrypt_recipient_userid() -> Result<()>
    {
        let dir = TempDir::new()?;

        let certd = dir.path().join("cert.d").display().to_string();
        std::fs::create_dir(&certd).expect("mkdir works");

        let alice_pgp = dir.path().join("alice.pgp").display().to_string();
        let bob_pgp = dir.path().join("bob.pgp").display().to_string();

        // Generate the keys.
        let mut cmd = Command::cargo_bin("sq")?;
        cmd.args(["--cert-store", &certd,
                  "key", "generate",
                  "--expiration", "never",
                  "--userid", "<alice@example.org>",
                  "--output", &alice_pgp]);
        cmd.assert().success();
        let alice = Cert::from_file(&alice_pgp)?;

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

        let mut cmd = Command::cargo_bin("sq")?;
        cmd.args(["--cert-store", &certd,
                  "key", "generate",
                  "--expiration", "never",
                  "--output", &bob_pgp]);
        for userid in bob_userids.iter() {
            cmd.args(["--userid", userid]);
        }
        cmd.assert().success();
        let bob = Cert::from_file(&bob_pgp)?;

        // Import the certificates.
        let mut cmd = Command::cargo_bin("sq")?;
        cmd.args(["--cert-store", &certd,
                  "cert", "import", &alice_pgp]);
        cmd.assert().success();

        let mut cmd = Command::cargo_bin("sq")?;
        cmd.args(["--cert-store", &certd,
                  "cert", "import", &bob_pgp]);
        cmd.assert().success();

        const MESSAGE: &[u8] = &[0x42; 24 * 1024 + 23];
        let encrypt = |trust_roots: &[&str],
                       recipients: &[(&str, &str)],
                       decryption_keys: &[&str]|
        {
            let mut cmd = Command::cargo_bin("sq").unwrap();
            cmd.args(["--cert-store", &certd]);
            for trust_root in trust_roots {
                cmd.args(["--trust-root", trust_root]);
            }
            cmd.arg("encrypt");

            // Make a string for debugging.
            let mut cmd_display = "sq encrypt".to_string();

            for (option, recipient) in recipients.iter() {
                cmd.args([option, recipient]);

                cmd_display.push_str(" ");
                cmd_display.push_str(option);
                cmd_display.push_str(" ");
                cmd_display.push_str(recipient);
            }
            cmd.write_stdin(MESSAGE);

            let output = cmd.output().expect("success");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            if decryption_keys.is_empty() {
                assert!(! output.status.success(),
                        "'{}' should have failed\nstdout:\n{}\nstderr:\n{}",
                        cmd_display, stdout, stderr);
            } else {
                assert!(output.status.success(),
                        "'{}' should have succeeded\nstdout:\n{}\nstderr:\n{}",
                        cmd_display, stdout, stderr);

                for key in decryption_keys.iter() {
                    let mut cmd = Command::cargo_bin("sq").unwrap();
                    cmd.args(["--no-cert-store",
                              "--no-key-store",
                              "decrypt",
                              "--recipient-file",
                              &key])
                        .write_stdin(stdout.as_bytes());

                    let output = cmd.output().expect("success");
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    assert!(output.status.success(),
                            "'{}' decryption should succeed\nstdout:\n{}\nstderr:\n{}",
                            cmd_display, stdout, stderr);
                }
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
            let mut cmd = Command::cargo_bin("sq")?;
            cmd.args(["--cert-store", &certd,
                      "pki", "certify",
                      "--certifier-file", &alice_pgp,
                      &bob_pgp, userid]);

            let output = cmd.output().expect("success");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            assert!(output.status.success(),
                    "'sq pki certify {} ...' should have succeeded\
                     \nstdout:\n{}\nstderr:\n{}",
                    userid, stdout, stderr);
            let mut cmd = Command::cargo_bin("sq")?;
            cmd.args(["--cert-store", &certd,
                      "cert", "import"])
                .write_stdin(stdout.as_bytes());
            cmd.assert().success();
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
        let dir = TempDir::new()?;

        let certd = dir.path().join("cert.d").display().to_string();
        std::fs::create_dir(&certd).expect("mkdir works");

        let alice_pgp = dir.path().join("alice.pgp").display().to_string();
        let bob_pgp = dir.path().join("bob.pgp").display().to_string();

        // Generate the keys.
        let mut cmd = Command::cargo_bin("sq")?;
        cmd.args(["--cert-store", &certd,
                  "key", "generate",
                  "--expiration", "never",
                  "--userid", "<alice@example.org>",
                  "--output", &alice_pgp]);
        cmd.assert().success();
        let alice = Cert::from_file(&alice_pgp)?;
        let alice_fpr = alice.fingerprint().to_string();

        let mut cmd = Command::cargo_bin("sq")?;
        cmd.args(["--cert-store", &certd,
                  "key", "generate",
                  "--expiration", "never",
                  "--userid", "<bob@example.org>",
                  "--output", &bob_pgp]);
        cmd.assert().success();
        let bob = Cert::from_file(&bob_pgp)?;
        let bob_fpr = bob.keyid().to_string();

        const MESSAGE: &[u8] = &[0x42; 24 * 1024 + 23];
        let encrypt = |keyrings: &[&str],
                       recipients: &[&str],
                       decryption_keys: &[&str]|
        {
            let mut cmd = Command::cargo_bin("sq").unwrap();
            cmd.args(["--cert-store", &certd]);

            // Make a string for debugging.
            let mut cmd_display = "sq".to_string();

            for keyring in keyrings.iter() {
                cmd.args(["--keyring", keyring]);

                cmd_display.push_str(" --keyring ");
                cmd_display.push_str(keyring);
            }

            cmd_display.push_str(" encrypt");
            cmd.arg("encrypt");

            for recipient in recipients.iter() {
                cmd.args(["--recipient-cert", recipient]);

                cmd_display.push_str(" --recipient-cert ");
                cmd_display.push_str(recipient);
            }
            cmd.write_stdin(MESSAGE);

            let output = cmd.output().expect("success");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            if decryption_keys.is_empty() {
                assert!(! output.status.success(),
                        "'{}' should have failed\nstdout:\n{}\nstderr:\n{}",
                        cmd_display, stdout, stderr);
            } else {
                assert!(output.status.success(),
                        "'{}' should have succeeded\nstdout:\n{}\nstderr:\n{}",
                        cmd_display, stdout, stderr);

                for key in decryption_keys.iter() {
                    let mut cmd = Command::cargo_bin("sq").unwrap();
                    cmd.args(["--no-cert-store",
                              "--no-key-store",
                              "decrypt",
                              "--recipient-file",
                              &key])
                        .write_stdin(stdout.as_bytes());

                    let output = cmd.output().expect("success");
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    assert!(output.status.success(),
                            "'{}' decryption should succeed\nstdout:\n{}\nstderr:\n{}",
                            cmd_display, stdout, stderr);
                }
            }
        };

        encrypt(&[&alice_pgp, &bob_pgp],
                &[&alice_fpr, &bob_fpr],
                &[&alice_pgp, &bob_pgp]);

        // Import Alice's certificate.
        let mut cmd = Command::cargo_bin("sq")?;
        cmd.args(["--cert-store", &certd,
                  "cert", "import", &alice_pgp]);
        let output = cmd.output().expect("success");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(),
                "sq import should succeed\nstdout:\n{}\nstderr:\n{}",
                stdout, stderr);

        encrypt(&[&alice_pgp, &bob_pgp],
                &[&alice_fpr, &bob_fpr],
                &[&alice_pgp, &bob_pgp]);

        encrypt(&[&bob_pgp],
                &[&alice_fpr, &bob_fpr],
                &[&alice_pgp, &bob_pgp]);


        Ok(())
    }
}
