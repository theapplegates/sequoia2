use assert_cmd::Command;

use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::Cert;
use openpgp::Result;
use sequoia_openpgp as openpgp;

mod integration {
    use super::*;

    use std::path::PathBuf;
    use tempfile::TempDir;

    const P: &StandardPolicy = &StandardPolicy::new();

    /// Generate a new key in a temporary directory and return its TempDir,
    /// PathBuf and creation times in a Result
    fn sq_key_generate() -> Result<(TempDir, PathBuf, String, u64)> {
        let tmpdir = TempDir::new().unwrap();
        let path = tmpdir.path().join("key.pgp");
        let timestamp = "20220120T163236+0100";
        let seconds = 1642692756;

        let mut cmd = Command::cargo_bin("sq")?;
        cmd.args([
            "--no-cert-store",
            "key",
            "generate",
            "--time",
            timestamp,
            "--expires", "never",
            "--export",
            &*path.to_string_lossy(),
        ]);
        cmd.assert().success();

        let original_cert = Cert::from_file(&path)?;
        let original_valid_cert = original_cert.with_policy(P, None)?;
        assert_eq!(
            original_valid_cert
                .keys()
                .filter(|x| x.for_authentication())
                .count(),
            1
        );
        assert_eq!(
            original_valid_cert
                .keys()
                .filter(|x| x.for_certification())
                .count(),
            1
        );
        assert_eq!(
            original_valid_cert
                .keys()
                .filter(|x| x.for_signing())
                .count(),
            1
        );
        assert_eq!(
            original_valid_cert
                .keys()
                .filter(|x| x.for_storage_encryption())
                .count(),
            1
        );
        assert_eq!(
            original_valid_cert
                .keys()
                .filter(|x| x.for_transport_encryption())
                .count(),
            1
        );

        Ok((tmpdir, path, timestamp.to_string(), seconds))
    }

    #[test]
    fn sq_key_subkey_generate_authentication_subkey() -> Result<()> {
        let (tmpdir, path, _, _) = sq_key_generate().unwrap();
        let output = path.parent().unwrap().join("new_key.pgp");

        let mut cmd = Command::cargo_bin("sq")?;
        cmd.args([
            "--no-cert-store",
            "key",
            "subkey",
            "add",
            "--output",
            &output.to_string_lossy(),
            "--can-authenticate",
            &path.to_string_lossy(),
        ]);
        cmd.assert().success();

        let cert = Cert::from_file(&output)?;
        let valid_cert = cert.with_policy(P, None)?;

        assert_eq!(
            valid_cert.keys().filter(|x| x.for_authentication()).count(),
            2
        );
        tmpdir.close()?;
        Ok(())
    }

    #[test]
    fn sq_key_subkey_generate_encryption_subkey() -> Result<()> {
        let (tmpdir, path, _, _) = sq_key_generate().unwrap();
        let output = path.parent().unwrap().join("new_key.pgp");

        let mut cmd = Command::cargo_bin("sq")?;
        cmd.args([
            "--no-cert-store",
            "key",
            "subkey",
            "add",
            "--output",
            &output.to_string_lossy(),
            "--can-encrypt=universal",
            &path.to_string_lossy(),
        ]);
        cmd.assert().success();

        let cert = Cert::from_file(&output)?;
        let valid_cert = cert.with_policy(P, None)?;

        assert_eq!(
            valid_cert
                .keys()
                .filter(|x| x.for_storage_encryption())
                .count(),
            2
        );
        assert_eq!(
            valid_cert
                .keys()
                .filter(|x| x.for_transport_encryption())
                .count(),
            2
        );
        tmpdir.close()?;
        Ok(())
    }

    #[test]
    fn sq_key_subkey_generate_signing_subkey() -> Result<()> {
        let (tmpdir, path, _, _) = sq_key_generate().unwrap();
        let output = path.parent().unwrap().join("new_key.pgp");

        let mut cmd = Command::cargo_bin("sq")?;
        cmd.args([
            "--no-cert-store",
            "key",
            "subkey",
            "add",
            "--output",
            &output.to_string_lossy(),
            "--can-sign",
            &path.to_string_lossy(),
        ]);
        cmd.assert().success();

        let cert = Cert::from_file(&output)?;
        let valid_cert = cert.with_policy(P, None)?;

        assert_eq!(valid_cert.keys().filter(|x| x.for_signing()).count(), 2);
        tmpdir.close()?;
        Ok(())
    }
}
