use std::path::PathBuf;
use tempfile::TempDir;
use assert_cmd::Command;

use sequoia_openpgp as openpgp;
use openpgp::Result;

use chrono::Utc;
use chrono::DateTime;

/// Returns the time formatted as an ISO 8106 string.
pub fn time_as_string(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[test]
fn sq_autocrypt_import() -> Result<()>
{
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let eml = manifest_dir.join("tests").join("data").join("autocrypt")
        .join("E43FF9D5-ABE5-42D4-852F-4692FB643B10@probier.email.eml");
    let certd = TempDir::new()?;

    // Import the message, first without being able to decrypt it.
    let mut cmd = Command::cargo_bin("sq")?;
    cmd.arg("--cert-store").arg(certd.path())
        .arg("autocrypt").arg("import")
        .arg(&eml);
    eprintln!("Running: {:?}", cmd);
    cmd.assert().success();

    let mut cmd = Command::cargo_bin("sq")?;
    cmd.arg("--cert-store").arg(certd.path())
        .arg("cert").arg("export")
        .arg("--cert").arg("A614C91D0392D83EE6B1C4A4DD4147FEF78AD630");
    let output = cmd.output().expect("can run");
    assert!(output.status.success());

    let mut cmd = Command::cargo_bin("sq")?;
    cmd.arg("--cert-store").arg(certd.path())
        .arg("toolbox").arg("packet").arg("dump")
        .write_stdin(output.stdout);
    let output = cmd.output().expect("can run");
    assert!(output.status.success());
    eprintln!("{}", String::from_utf8_lossy(&output.stdout));

    // We can now partially authenticate the sender.
    let mut cmd = Command::cargo_bin("sq")?;
    cmd.arg("--cert-store").arg(certd.path())
        .arg("pki").arg("authenticate")
        .arg("--amount=40")
        .arg("A614C91D0392D83EE6B1C4A4DD4147FEF78AD630")
        .arg("--email").arg("pink@probier.email");
    eprintln!("Running: {:?}", cmd);
    eprintln!("pre: {}", time_as_string(std::time::SystemTime::now().into()));
    let output = cmd.output().expect("can run");
    eprintln!("post: {}", time_as_string(std::time::SystemTime::now().into()));
    assert!(output.status.success());

    // Import the message with the decryption key.
    let mut cmd = Command::cargo_bin("sq")?;
    cmd.arg("--cert-store").arg(certd.path())
        .arg("autocrypt").arg("import")
        .arg("--session-key")
        .arg("9:770BFC3442DDE8DA263973474D6487DE8F6940FC0AED5EC632E9D53CAA28CC95")
        .arg(&eml);
    eprintln!("Running: {:?}", cmd);
    cmd.assert().success();

    // We can now weakly authenticate the peers.
    let mut cmd = Command::cargo_bin("sq")?;
    cmd.arg("--cert-store").arg(certd.path())
        .arg("pki").arg("authenticate")
        .arg("--amount=1")
        .arg("CBCD8F030588653EEDD7E2659B7DD433F254904A")
        .arg("--email").arg("justus@sequoia-pgp.org");
    eprintln!("Running: {:?}", cmd);
    cmd.assert().success();

    let mut cmd = Command::cargo_bin("sq")?;
    cmd.arg("--cert-store").arg(certd.path())
        .arg("pki").arg("authenticate")
        .arg("--amount=1")
        .arg("BB6B7E5F8343B2BE990EB7A7F3AF066F267892C1")
        .arg("--email").arg("hilal-maria@probier.email");
    eprintln!("Running: {:?}", cmd);
    cmd.assert().success();

    Ok(())
}
