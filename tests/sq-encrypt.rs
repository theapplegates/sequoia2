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
                  "--expires", "never",
                  "--userid", "<alice@example.org>",
                  "--export", &key_pgp]);
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
                  "import", &key_pgp]);
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
}
