use openpgp::parse::Parse;
use openpgp::Cert;
use openpgp::Result;
use sequoia_openpgp as openpgp;

mod common;
use common::sq_key_generate;
use common::Sq;

#[test]
fn sq_key_password() -> Result<()> {
    let (tmpdir, cert_path, time) = sq_key_generate(None)?;
    let cert_path = cert_path.display().to_string();
    let cert = Cert::from_file(&cert_path)?;

    let mut sq = Sq::at(time.into());

    let orig_password = sq.base().join("orig_password.txt");
    std::fs::write(&orig_password, "t00 ez").unwrap();
    let new_password = sq.base().join("new_password.txt");
    std::fs::write(&new_password, "crazy passw0rd").unwrap();

    let msg_txt = sq.base().join("msg.txt");
    std::fs::write(&msg_txt, "hello world").unwrap();

    let msg_sig = sq.base().join("msg.sig");

    // Two days go by.
    sq.tick(2 * 24 * 60 * 60);

    // Sign a message.
    let mut cmd = sq.command();
    cmd.args([
        "sign", &msg_txt.to_string_lossy(),
        "--signer-file", &cert_path,
        "--password-file", &orig_password.to_string_lossy(),
        "--output", &msg_sig.to_string_lossy(),
    ]);
    sq.run(cmd, true);

    // Change the key's password.
    let updated_path = &tmpdir.path().join("updated.pgp");
    let mut cmd = sq.command();
    cmd.args([
        "key", "password",
        "--cert-file", &cert_path,
        "--new-password-file", &new_password.to_string_lossy(),
        "--output", &updated_path.to_string_lossy(),
    ]);
    sq.run(cmd, true);

    // Sign a message.
    let mut cmd = sq.command();
    cmd.args([
        "--force",
        "sign", &msg_txt.to_string_lossy(),
        "--signer-file", &updated_path.to_string_lossy(),
        "--password-file", &new_password.to_string_lossy(),
        "--output", &msg_sig.to_string_lossy(),
    ]);
    sq.run(cmd, true);

    // Clear the key's password.
    let updated2_path = &tmpdir.path().join("updated2.pgp");
    let mut cmd = sq.command();
    cmd.args([
        "key", "password",
        "--cert-file", &updated_path.to_string_lossy(),
        "--old-password-file", &new_password.to_string_lossy(),
        "--clear",
        "--output", &updated2_path.to_string_lossy(),
    ]);
    sq.run(cmd, true);

    // Sign a message.
    let mut cmd = sq.command();
    cmd.args([
        "--force",
        "sign", &msg_txt.to_string_lossy(),
        "--signer-file", &updated2_path.to_string_lossy(),
        "--output", &msg_sig.to_string_lossy(),
    ]);
    sq.run(cmd, true);

    tmpdir.close()?;

    Ok(())
}
