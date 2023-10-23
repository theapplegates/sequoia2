use std::path::PathBuf;

use anyhow::anyhow;
use assert_cmd::Command;

use chrono::DateTime;
use chrono::Duration;
use chrono::Utc;

use openpgp::packet::Signature;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::Cert;
use openpgp::Result;
use sequoia_openpgp as openpgp;

use tempfile::TempDir;

pub const STANDARD_POLICY: &StandardPolicy = &StandardPolicy::new();

/// Generate a new key in a temporary directory and return its TempDir,
/// PathBuf and creation time in a Result
pub fn sq_key_generate(
    userids: Option<&[&str]>,
) -> Result<(TempDir, PathBuf, DateTime<Utc>)> {
    let tmpdir = TempDir::new().unwrap();
    let path = tmpdir.path().join("key.pgp");
    let mut time = Utc::now();
    // Round it down to a whole second to match the resolution of
    // OpenPGP's timestamp.
    time = time - Duration::nanoseconds(time.timestamp_subsec_nanos() as i64);
    let userids = if let Some(userids) = userids {
        userids
    } else {
        &["alice <alice@example.org>"]
    };

    let mut cmd = Command::cargo_bin("sq")?;
    cmd.args([
        "--no-cert-store",
        "key",
        "generate",
        "--time",
        &time.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        "--expiry",
        "never",
        "--output",
        &*path.to_string_lossy(),
    ]);
    for userid in userids {
        cmd.args(["--userid", userid]);
    }
    cmd.assert().success();

    let original_cert = Cert::from_file(&path)?;
    let original_valid_cert =
        original_cert.with_policy(STANDARD_POLICY, None)?;
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

    Ok((tmpdir, path, time))
}

/// Ensure notations can be found in a Signature
///
/// ## Errors
///
/// Returns an error if a notation can not be found in the Signature
pub fn compare_notations(
    signature: &Signature,
    notations: Option<&[(&str, &str); 2]>,
) -> Result<()> {
    if let Some(notations) = notations {
        let found_notations: Vec<(&str, String)> = signature
            .notation_data()
            .map(|n| (n.name(), String::from_utf8_lossy(n.value()).into()))
            .collect();

        for (key, value) in notations {
            if !found_notations.contains(&(key, String::from(*value))) {
                return Err(anyhow!(format!(
                    "Expected notation \"{}: {}\" in {:?}",
                    key, value, found_notations
                )));
            }
        }
    }
    Ok(())
}
