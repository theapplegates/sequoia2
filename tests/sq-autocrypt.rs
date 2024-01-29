use std::path::PathBuf;
use tempfile::TempDir;
use assert_cmd::Command;

use sequoia_openpgp as openpgp;
use openpgp::Result;

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
    cmd.assert().success();

    // We can now partially authenticate the sender.
    let mut cmd = Command::cargo_bin("sq")?;
    cmd.arg("--cert-store").arg(certd.path())
        .arg("pki").arg("authenticate")
        .arg("--amount=40")
        .arg("A614C91D0392D83EE6B1C4A4DD4147FEF78AD630")
        .arg("--email").arg("pink@probier.email");
    cmd.assert().success();

    // Import the message with the decryption key.
    let mut cmd = Command::cargo_bin("sq")?;
    cmd.arg("--cert-store").arg(certd.path())
        .arg("autocrypt").arg("import")
        .arg("--session-key")
        .arg("9:770BFC3442DDE8DA263973474D6487DE8F6940FC0AED5EC632E9D53CAA28CC95")
        .arg(&eml);
    cmd.assert().success();

    // We can now weakly authenticate the peers.
    let mut cmd = Command::cargo_bin("sq")?;
    cmd.arg("--cert-store").arg(certd.path())
        .arg("pki").arg("authenticate")
        .arg("--amount=1")
        .arg("CBCD8F030588653EEDD7E2659B7DD433F254904A")
        .arg("--email").arg("justus@sequoia-pgp.org");
    cmd.assert().success();

    let mut cmd = Command::cargo_bin("sq")?;
    cmd.arg("--cert-store").arg(certd.path())
        .arg("pki").arg("authenticate")
        .arg("--amount=1")
        .arg("BB6B7E5F8343B2BE990EB7A7F3AF066F267892C1")
        .arg("--email").arg("hilal-maria@probier.email");
    cmd.assert().success();

    Ok(())
}
