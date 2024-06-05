use std::path::Path;
use std::process::ExitStatus;
use std::sync::{Mutex, OnceLock};

use tempfile::TempDir;
use assert_cmd::Command;


use sequoia_openpgp as openpgp;
use openpgp::Result;
use openpgp::Cert;
use openpgp::parse::Parse;

fn artifact(filename: &str) -> String {
    format!("tests/data/{}", filename)
}

// We are going to replace certifications, and we want to make sure
// that the newest one is the active one.  This means ensuring that
// the newer one has a newer timestamp.  To avoid sleeping for a
// second, the resolution of the time stamp, we pass an explicit time
// to each operation.
//
// This function drives the clock forward, and ensures that every
// operation "happens" at a different point in time.
static TIME: OnceLock<Mutex<chrono::DateTime<chrono::Utc>>> = OnceLock::new();

fn tick() -> String {
    let t = TIME.get_or_init(|| Mutex::new(chrono::Utc::now()));
    let mut t = t.lock().unwrap();
    *t = *t + chrono::Duration::seconds(10);
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

// Returns the "current" time.
fn now() -> chrono::DateTime<chrono::Utc> {
    *TIME.get_or_init(|| Mutex::new(chrono::Utc::now())).lock().unwrap()
}

// Imports a certificate.
fn sq_import(cert_store: &str, files: &[&str], stdin: Option<&str>)
{
    let mut cmd = Command::cargo_bin("sq").expect("have sq");
    cmd.args(["--cert-store", cert_store, "cert", "import"]);
    for file in files {
        cmd.arg(file);
    }
    eprintln!("{:?}", cmd);
    if let Some(stdin) = stdin {
        cmd.write_stdin(stdin);
    }
    cmd.assert().success();
}

// Generates a key.
//
// If cert_store is not `None`, then the resulting certificate is also
// imported.
fn sq_gen_key(cert_store: Option<&str>, userids: &[&str], file: &str) -> Cert
{
    let mut cmd = Command::cargo_bin("sq").expect("have sq");
    cmd.args(["--no-cert-store",
              "--no-key-store",
              "key", "generate",
              "--allow-non-canonical-userids",
              "--time", &tick(),
              "--expiry", "never",
              "--output", file]);
    for userid in userids.iter() {
        cmd.args(["--userid", userid]);
    }
    eprintln!("{:?}", cmd);
    cmd.assert().success();

    if let Some(cert_store) = cert_store {
        sq_import(cert_store, &[ file ], None);
    }

    Cert::from_file(file).expect("valid certificate")
}

// Verifies a signed message.
fn sq_verify(cert_store: Option<&str>,
             time: Option<chrono::DateTime<chrono::Utc>>,
             trust_roots: &[&str],
             signer_files: &[&str],
             msg_pgp: &str,
             good_sigs: usize, good_checksums: usize)
{
    let mut cmd = Command::cargo_bin("sq").expect("have sq");
    cmd.arg("--no-key-store");
    if let Some(cert_store) = cert_store {
        cmd.args(&["--cert-store", cert_store]);
    } else {
        cmd.arg("--no-cert-store");
    }
    for trust_root in trust_roots {
        cmd.args(&["--trust-root", trust_root]);
    }
    let time = if let Some(time) = time {
        time.format("%Y-%m-%dT%H:%M:%SZ").to_string()
    } else {
        tick()
    };
    cmd.args(["verify", "--time", &time]);
    for signer_file in signer_files {
        cmd.args(&["--signer-file", signer_file]);
    }
    cmd.arg(msg_pgp);
    eprintln!("{:?}", cmd);
    let output = cmd.output().expect("can run");

    let status = output.status;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if good_sigs > 0 {
        assert!(status.success(),
                "\nstdout:\n{}\nstderr:\n{}",
                stdout, stderr);
        assert!(stderr.contains(&format!("{} good signature",
                                         good_sigs)),
                "stdout:\n{}\nstderr:\n{}",
                stdout, stderr);
    } else {
        assert!(! status.success(),
                "\nstdout:\n{}\nstderr:\n{}",
                stdout, stderr);
    }

    if good_checksums > 0 {
        assert!(stderr.contains(&format!("{} unauthenticated checksum",
                                         good_checksums)),
                "stdout:\n{}\nstderr:\n{}", stdout, stderr);
    }
}

// Links a User ID and a certificate.
fn sq_link(cert_store: &str,
           cert: &str, userids: &[&str], more_args: &[&str],
           success: bool)
    -> (ExitStatus, String, String)
{
    let mut cmd = Command::cargo_bin("sq").expect("have sq");
    cmd.args(&["--cert-store", cert_store]);
    cmd.args(&["pki", "link", "add", "--time", &tick(), cert]);
    cmd.args(userids);
    cmd.args(more_args);
    eprintln!("{:?}", cmd);
    let output = cmd.output().expect("can run");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if success {
        assert!(output.status.success(),
                "'sq pki link add' failed unexpectedly\
                 \nstdout:\n{}\nstderr:\n{}",
                stdout, stderr);
    } else {
        assert!(! output.status.success(),
                "'sq pki link add' succeeded unexpectedly\
                 \nstdout:\n{}\nstderr:\n{}",
                stdout, stderr);
    }

    (output.status, stdout, stderr)
}

fn sq_retract(cert_store: &str, cert: &str, userids: &[&str])
    -> (ExitStatus, String, String)
{
    let mut cmd = Command::cargo_bin("sq").expect("have sq");
    cmd.args(&["--cert-store", cert_store]);
    cmd.args(&["pki", "link", "retract", "--time", &tick(), cert]);
    cmd.args(userids);
    eprintln!("{:?}", cmd);
    let output = cmd.output().expect("can run");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(output.status.success(),
            "sq pki link retract\nstdout:\n{}\nstderr:\n{}",
            stdout, stderr);

    (output.status, stdout, stderr)
}

// Certifies a binding.
//
// The certification is imported into the cert store.
fn sq_certify(cert_store: &str,
              key: &str, cert: &str, userid: &str,
              trust_amount: Option<usize>, depth: Option<usize>)
{
    let mut cmd = Command::cargo_bin("sq").expect("have sq");
    cmd.args(&["--cert-store", cert_store]);
    cmd.args(&["pki", "certify", "--time", &tick(),
               "--certifier-file", key, cert, userid]);
    if let Some(trust_amount) = trust_amount {
        cmd.args(&["--amount", &trust_amount.to_string()[..]]);
    }
    if let Some(depth) = depth {
        cmd.args(&["--depth", &depth.to_string()[..]]);
    }
    eprintln!("{:?}", cmd);
    let output = cmd.output().expect("can run");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(output.status.success(),
            "sq pki certify\nstdout:\n{}\nstderr:\n{}",
            stdout, stderr);

    // Import the certification.
    sq_import(cert_store, &[], Some(&stdout));
}

// Verify signatures using the acceptance machinery.
#[test]
fn sq_link_add_retract() -> Result<()> {
    let dir = TempDir::new()?;

    let certd = dir.path().join("cert.d").display().to_string();
    std::fs::create_dir(&certd).expect("mkdir works");

    struct Data {
        key_file: String,
        cert: Cert,
        sig_file: String,
    }

    // Four certificates.
    let alice_pgp = dir.path().join("alice.pgp").display().to_string();
    let alice_userid = "<alice@example.org>";
    let alice = Data {
        key_file: alice_pgp.clone(),
        cert: sq_gen_key(Some(&certd), &[ alice_userid ], &alice_pgp),
        sig_file: dir.path().join("alice.sig").display().to_string(),
    };
    let alice_fpr = alice.cert.fingerprint().to_string();

    let bob_pgp = dir.path().join("bob.pgp").display().to_string();
    let bob_userid = "<bob@example.org>";
    let bob = Data {
        key_file: bob_pgp.clone(),
        cert: sq_gen_key(Some(&certd), &[ bob_userid ], &bob_pgp),
        sig_file: dir.path().join("bob.sig").display().to_string(),
    };
    let bob_fpr = bob.cert.fingerprint().to_string();

    let carol_pgp = dir.path().join("carol.pgp").display().to_string();
    let carol_userid =  "<carol@example.org>";
    let carol = Data {
        key_file: carol_pgp.clone(),
        cert: sq_gen_key(Some(&certd), &[ carol_userid ], &carol_pgp),
        sig_file: dir.path().join("carol.sig").display().to_string(),
    };
    let carol_fpr = carol.cert.fingerprint().to_string();

    let dave_pgp = dir.path().join("dave.pgp").display().to_string();
    let dave_userid =  "<dave@other.org>";
    let dave = Data {
        key_file: dave_pgp.clone(),
        cert: sq_gen_key(Some(&certd), &[ dave_userid ], &dave_pgp),
        sig_file: dir.path().join("dave.sig").display().to_string(),
    };
    let dave_fpr = dave.cert.fingerprint().to_string();

    let data: &[&Data] = &[ &alice, &bob, &carol, &dave ][..];

    // Have each certificate sign a message.
    for data in data.iter() {
        Command::cargo_bin("sq")
            .unwrap()
            .arg("--no-cert-store")
            .arg("--no-key-store")
            .arg("sign")
            .args(["--signer-file", &data.key_file])
            .args(["--output", &data.sig_file])
            .args(["--time", &tick()])
            .arg(&artifact("messages/a-cypherpunks-manifesto.txt"))
            .assert()
            .success();
    }

    // None of the certificates can be authenticated so verifying the
    // messages should fail.
    for data in data.iter() {
        sq_verify(Some(&certd), None, &[], &[], &data.sig_file, 0, 1);
    }

    // Have Alice certify Bob as a trusted introducer and have Bob
    // certify Carol.
    sq_certify(&certd, &alice.key_file,
               &bob.cert.fingerprint().to_string(), bob_userid,
               None, Some(1));
    sq_certify(&certd, &bob.key_file,
               &carol.cert.fingerprint().to_string(), carol_userid,
               None, None);

    // We should be able to verify Alice's, Bob's and Carol's
    // signatures Alice as the trust root.  And Bob's and Carols' with
    // Bob as the trust root.

    sq_verify(Some(&certd), None, &[&alice_fpr], &[], &alice.sig_file, 1, 0);
    sq_verify(Some(&certd), None, &[&alice_fpr], &[], &bob.sig_file, 1, 0);
    sq_verify(Some(&certd), None, &[&alice_fpr], &[], &carol.sig_file, 1, 0);
    sq_verify(Some(&certd), None, &[&alice_fpr], &[], &dave.sig_file, 0, 1);

    sq_verify(Some(&certd), None, &[&bob_fpr], &[], &alice.sig_file, 0, 1);
    sq_verify(Some(&certd), None, &[&bob_fpr], &[], &bob.sig_file, 1, 0);
    sq_verify(Some(&certd), None, &[&bob_fpr], &[], &carol.sig_file, 1, 0);
    sq_verify(Some(&certd), None, &[&bob_fpr], &[], &dave.sig_file, 0, 1);

    sq_verify(Some(&certd), None, &[&carol_fpr], &[], &alice.sig_file, 0, 1);
    sq_verify(Some(&certd), None, &[&carol_fpr], &[], &bob.sig_file, 0, 1);
    sq_verify(Some(&certd), None, &[&carol_fpr], &[], &carol.sig_file, 1, 0);
    sq_verify(Some(&certd), None, &[&carol_fpr], &[], &dave.sig_file, 0, 1);

    sq_verify(Some(&certd), None, &[&dave_fpr], &[], &alice.sig_file, 0, 1);
    sq_verify(Some(&certd), None, &[&dave_fpr], &[], &bob.sig_file, 0, 1);
    sq_verify(Some(&certd), None, &[&dave_fpr], &[], &carol.sig_file, 0, 1);
    sq_verify(Some(&certd), None, &[&dave_fpr], &[], &dave.sig_file, 1, 0);

    // Let's accept Alice, but not (yet) as a trusted introducer.  We
    // should now be able to verify Alice's signature, but not Bob's.
    sq_link(&certd, &alice_fpr, &[ &alice_userid ], &[], true);

    sq_verify(Some(&certd), None, &[], &[], &alice.sig_file, 1, 0);
    sq_verify(Some(&certd), None, &[], &[], &bob.sig_file, 0, 1);

    // Accept Alice as a trusted introducer.  We should be able to
    // verify Alice, Bob, and Carol's signatures.
    sq_link(&certd, &alice_fpr, &[ &alice_userid ], &["--ca", "*"], true);

    sq_verify(Some(&certd), None, &[], &[], &alice.sig_file, 1, 0);
    sq_verify(Some(&certd), None, &[], &[], &bob.sig_file, 1, 0);
    sq_verify(Some(&certd), None, &[], &[], &carol.sig_file, 1, 0);
    sq_verify(Some(&certd), None, &[], &[], &dave.sig_file, 0, 1);

    // Retract the acceptance for Alice.  If we don't specify a trust
    // root, none of the signatures should verify.
    sq_retract(&certd, &alice_fpr, &[ &alice_userid ]);

    for data in data.iter() {
        sq_verify(Some(&certd), None, &[], &[], &data.sig_file, 0, 1);
    }

    // Accept Alice as a trusted introducer again.  We should be able
    // to verify Alice, Bob, and Carol's signatures.
    sq_link(&certd, &alice_fpr, &[ &alice_userid ], &["--ca", "*"], true);

    sq_verify(Some(&certd), None, &[], &[], &alice.sig_file, 1, 0);
    sq_verify(Some(&certd), None, &[], &[], &bob.sig_file, 1, 0);
    sq_verify(Some(&certd), None, &[], &[], &carol.sig_file, 1, 0);
    sq_verify(Some(&certd), None, &[], &[], &dave.sig_file, 0, 1);

    // Have Bob certify Dave.  Now Dave's signature should also
    // verify.
    sq_certify(&certd, &bob.key_file,
               &dave.cert.fingerprint().to_string(), dave_userid,
               None, None);

    sq_verify(Some(&certd), None, &[], &[], &alice.sig_file, 1, 0);
    sq_verify(Some(&certd), None, &[], &[], &bob.sig_file, 1, 0);
    sq_verify(Some(&certd), None, &[], &[], &carol.sig_file, 1, 0);
    sq_verify(Some(&certd), None, &[], &[], &dave.sig_file, 1, 0);

    // Change Alice's acceptance to just be a normal certification.
    // We should only be able to verify her signature.
    sq_link(&certd, &alice_fpr, &[ &alice_userid ], &[], true);

    sq_verify(Some(&certd), None, &[], &[], &alice.sig_file, 1, 0);
    sq_verify(Some(&certd), None, &[], &[], &bob.sig_file, 0, 1);
    sq_verify(Some(&certd), None, &[], &[], &carol.sig_file, 0, 1);
    sq_verify(Some(&certd), None, &[], &[], &dave.sig_file, 0, 1);

    // Change Alice's acceptance to be a ca, but only for example.org,
    // i.e., not for Dave.
    sq_link(&certd, &alice_fpr, &[ &alice_userid ], &["--ca", "example.org"],
            true);

    sq_verify(Some(&certd), None, &[], &[], &alice.sig_file, 1, 0);
    sq_verify(Some(&certd), None, &[], &[], &bob.sig_file, 1, 0);
    sq_verify(Some(&certd), None, &[], &[], &carol.sig_file, 1, 0);
    sq_verify(Some(&certd), None, &[], &[], &dave.sig_file, 0, 1);



    // Four certificates.
    let ed_pgp = dir.path().join("ed.pgp").display().to_string();
    let ed = sq_gen_key(
        Some(&certd),
        &[
            "Ed <ed@example.org>",
            "Eddie <ed@example.org>",
            // This is not considered to be an email address as
            // it is not wrapped in angle brackets.
            "ed@some.org",
            // But this is.
            "<ed@other.org>",
        ],
        &ed_pgp);
    let ed_fpr = ed.fingerprint().to_string();
    let ed_sig_file = dir.path().join("ed.sig").display().to_string();

    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("--no-key-store")
        .arg("sign")
        .args(["--signer-file", &ed_pgp])
        .args(["--output", &ed_sig_file])
        .args(["--time", &tick()])
        .arg(&artifact("messages/a-cypherpunks-manifesto.txt"))
        .assert()
        .success();

    // If we don't use --petname, than a self-signed User ID must
    // exist.
    sq_link(&certd, &ed_fpr, &[ "--userid", "bob@example.com" ], &[], false);
    sq_verify(Some(&certd), None, &[], &[], &ed_sig_file, 0, 1);

    sq_link(&certd, &ed_fpr, &[ "--email", "bob@example.com" ], &[], false);
    sq_verify(Some(&certd), None, &[], &[], &ed_sig_file, 0, 1);

    sq_link(&certd, &ed_fpr, &[ "bob@example.com" ], &[], false);
    sq_verify(Some(&certd), None, &[], &[], &ed_sig_file, 0, 1);

    // We should only create links if all the supplied User IDs are
    // valid.
    sq_link(&certd, &ed_fpr, &[
        "--userid", "ed@some.org", "--userid", "bob@example.com"
    ], &[], false);
    sq_verify(Some(&certd), None, &[], &[], &ed_sig_file, 0, 1);

    sq_link(&certd, &ed_fpr, &[
        "--userid", "ed@some.org", "--email", "bob@example.com"
    ], &[], false);
    sq_verify(Some(&certd), None, &[], &[], &ed_sig_file, 0, 1);

    sq_link(&certd, &ed_fpr, &[
        "--userid", "ed@some.org", "bob@example.com"
    ], &[], false);
    sq_verify(Some(&certd), None, &[], &[], &ed_sig_file, 0, 1);

    // Pass an email address to --userid.  This shouldn't match
    // either.
    sq_link(&certd, &ed_fpr, &[
        "--userid", "ed@other.org"
    ], &[], false);
    sq_verify(Some(&certd), None, &[], &[], &ed_sig_file, 0, 1);

    // Link all User IDs individually.
    sq_link(&certd, &ed_fpr, &[
        "--email", "ed@other.org",
        "--email", "ed@example.org",
        "--userid", "ed@some.org",
    ], &[], true);
    sq_verify(Some(&certd), None, &[], &[], &ed_sig_file, 1, 0);

    // Retract the links one at a time.
    sq_retract(&certd, &ed_fpr, &[ "ed@other.org" ]);
    sq_verify(Some(&certd), None, &[], &[], &ed_sig_file, 1, 0);

    sq_retract(&certd, &ed_fpr, &[ "Ed <ed@example.org>" ]);
    sq_verify(Some(&certd), None, &[], &[], &ed_sig_file, 1, 0);

    sq_retract(&certd, &ed_fpr, &[ "Eddie <ed@example.org>" ]);
    sq_verify(Some(&certd), None, &[], &[], &ed_sig_file, 1, 0);

    sq_retract(&certd, &ed_fpr, &[ "ed@some.org" ]);
    // Now the certificate should no longer be authenticated.
    sq_verify(Some(&certd), None, &[], &[], &ed_sig_file, 0, 1);

    Ok(())
}

// Set the different parameters.  When the parameters are the same,
// make sure no certifications are written; when they are different
// make sure the file changed.
#[test]
fn sq_link_update_detection() -> Result<()> {
    let dir = TempDir::new()?;

    let certd = dir.path().join("cert.d").display().to_string();
    std::fs::create_dir(&certd).expect("mkdir works");

    let alice_pgp = dir.path().join("alice.pgp").display().to_string();
    let alice_userid = "<alice@example.org>";
    let alice = sq_gen_key(Some(&certd), &[ alice_userid ], &alice_pgp);
    let alice_fpr = alice.fingerprint().to_string();
    let alice_cert_pgp = dir.path().join("cert.d")
        .join(&alice_fpr[0..2].to_ascii_lowercase())
        .join(&alice_fpr[2..].to_ascii_lowercase());

    // Reads and returns file.  Asserts that old and the new contexts
    // are the same (or not).
    let compare = |old: Vec<u8>, file: &Path, same: bool| -> Vec<u8> {
        let new = std::fs::read(file).unwrap();
        if same {
            assert_eq!(old, new, "file unexpectedly changed");
        } else {
            assert_ne!(old, new, "file unexpectedly stayed the same");
        }
        new
    };
    let bytes = std::fs::read(&alice_cert_pgp).unwrap();

    // Retract it.  There is nothing to retract (but this doesn't fail).
    let output = sq_retract(&certd, &alice_fpr, &[]);
    assert!(output.2.contains("You never linked"),
            "stdout:\n{}\nstderr:\n{}", output.1, output.2);
    let bytes = compare(bytes, &alice_cert_pgp, true);

    // Link it.
    sq_link(&certd, &alice_fpr, &[], &["--all"], true);
    let bytes = compare(bytes, &alice_cert_pgp, false);

    // As no parameters changed, this should succeeded, but no
    // certification should be written.
    let output = sq_link(&certd, &alice_fpr, &[], &["--all"], true);
    assert!(output.2.contains("Link parameters are unchanged, no update needed"),
            "stdout:\n{}\nstderr:\n{}", output.1, output.2);
    let bytes = compare(bytes, &alice_cert_pgp, true);

    // Make Alice a CA.
    let output = sq_link(&certd, &alice_fpr, &[],
                         &["--ca", "*", "--all"], true);
    assert!(output.2.contains("was already linked"),
            "stdout:\n{}\nstderr:\n{}", output.1, output.2);
    let bytes = compare(bytes, &alice_cert_pgp, false);

    let output = sq_link(&certd, &alice_fpr, &[],
                         &["--ca", "*", "--all"], true);
    assert!(output.2.contains("Link parameters are unchanged, no update needed"),
            "stdout:\n{}\nstderr:\n{}", output.1, output.2);
    let bytes = compare(bytes, &alice_cert_pgp, true);

    // Make her a partially trusted CA.
    let output = sq_link(&certd, &alice_fpr, &[],
                         &["--amount", "30", "--all"], true);
    assert!(output.2.contains("was already linked"),
            "stdout:\n{}\nstderr:\n{}", output.1, output.2);
    let bytes = compare(bytes, &alice_cert_pgp, false);

    let output = sq_link(&certd, &alice_fpr, &[],
                         &["--amount", "30", "--all"], true);
    assert!(output.2.contains("Link parameters are unchanged, no update needed"),
            "stdout:\n{}\nstderr:\n{}", output.1, output.2);
    let bytes = compare(bytes, &alice_cert_pgp, true);

    // Retract the link.
    let output = sq_retract(&certd, &alice_fpr, &[]);
    assert!(output.2.contains("was linked at"),
            "stdout:\n{}\nstderr:\n{}", output.1, output.2);
    let bytes = compare(bytes, &alice_cert_pgp, false);

    let output = sq_retract(&certd, &alice_fpr, &[]);
    assert!(output.2.contains("Link parameters are unchanged, no update needed"),
            "stdout:\n{}\nstderr:\n{}", output.1, output.2);
    let bytes = compare(bytes, &alice_cert_pgp, true);


    // Link it again.
    let output = sq_link(&certd, &alice_fpr, &[],
                         &["--depth", "10", "--amount", "10", "--all"], true);
    assert!(output.2.contains("was retracted"),
            "stdout:\n{}\nstderr:\n{}", output.1, output.2);
    let bytes = compare(bytes, &alice_cert_pgp, false);

    let output = sq_link(&certd, &alice_fpr, &[],
                         &["--depth", "10", "--amount", "10", "--all"], true);
    assert!(output.2.contains("Link parameters are unchanged, no update needed"),
            "stdout:\n{}\nstderr:\n{}", output.1, output.2);
    let bytes = compare(bytes, &alice_cert_pgp, true);

    // Use a notation.
    let output = sq_link(&certd, &alice_fpr, &[],
                         &["--notation", "foo", "10", "--all"], true);
    assert!(output.2.contains("was already linked"),
            "stdout:\n{}\nstderr:\n{}", output.1, output.2);
    let bytes = compare(bytes, &alice_cert_pgp, false);

    let output = sq_link(&certd, &alice_fpr, &[],
                         &["--notation", "foo", "10", "--all"], true);
    assert!(output.2.contains("Link parameters are unchanged, no update needed"),
            "stdout:\n{}\nstderr:\n{}", output.1, output.2);
    let bytes = compare(bytes, &alice_cert_pgp, true);

    // The default link again.
    let output = sq_link(&certd, &alice_fpr, &[], &["--all"], true);
    assert!(output.2.contains("was already linked"),
            "stdout:\n{}\nstderr:\n{}", output.1, output.2);
    let bytes = compare(bytes, &alice_cert_pgp, false);

    let output = sq_link(&certd, &alice_fpr, &[], &["--all"], true);
    assert!(output.2.contains("Link parameters are unchanged, no update needed"),
            "stdout:\n{}\nstderr:\n{}", output.1, output.2);
    let bytes = compare(bytes, &alice_cert_pgp, true);

    let _ = bytes;
    Ok(())
}

// Check that sq pki link add --temporary works.
#[test]
fn sq_link_add_temporary() -> Result<()> {
    let dir = TempDir::new()?;

    let certd = dir.path().join("cert.d").display().to_string();
    std::fs::create_dir(&certd).expect("mkdir works");

    let alice_pgp = dir.path().join("alice.pgp").display().to_string();
    let alice_userid = "<alice@example.org>";
    let alice = sq_gen_key(Some(&certd), &[ alice_userid ], &alice_pgp);
    let alice_fpr = alice.fingerprint().to_string();
    let alice_cert_pgp = dir.path().join("cert.d")
        .join(&alice_fpr[0..2].to_ascii_lowercase())
        .join(&alice_fpr[2..].to_ascii_lowercase());

    let alice_sig_file = dir.path().join("alice.sig").display().to_string();
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("--no-key-store")
        .arg("sign")
        .args(["--signer-file", &alice_pgp])
        .args(["--output", &alice_sig_file])
        .args(["--time", &tick()])
        .arg(&artifact("messages/a-cypherpunks-manifesto.txt"))
        .assert()
        .success();

    // Reads and returns file.  Asserts that old and the new contexts
    // are the same (or not).
    let compare = |old: Vec<u8>, file: &Path, same: bool| -> Vec<u8> {
        let new = std::fs::read(file).unwrap();
        if same {
            assert_eq!(old, new, "file unexpectedly changed");
        } else {
            assert_ne!(old, new, "file unexpectedly stayed the same");
        }
        new
    };
    let bytes = std::fs::read(&alice_cert_pgp).unwrap();

    sq_verify(Some(&certd), None, &[], &[], &alice_sig_file, 0, 1);

    let output = sq_link(&certd, &alice_fpr, &[], &["--temporary", "--all"], true);
    assert!(output.2.contains("Linking "),
            "stdout:\n{}\nstderr:\n{}", output.1, output.2);
    let bytes = compare(bytes, &alice_cert_pgp, false);

    // Now it is fully trusted.
    sq_verify(Some(&certd), None, &[], &[], &alice_sig_file, 1, 0);

    // In 6 days, too.
    sq_verify(Some(&certd),
              Some(now() + chrono::Duration::seconds(6 * 24 * 60 * 60)),
              &[], &[], &alice_sig_file, 1, 0);

    // But in 8 days it will only be partially trusted.
    sq_verify(Some(&certd),
              Some(now() + chrono::Duration::seconds(8 * 24 * 60 * 60)),
              &[], &[], &alice_sig_file, 0, 1);


    // Now mark it as fully trusted.  It should be trusted now, in 6
    // days and in 8 days.
    let output = sq_link(&certd, &alice_fpr, &[], &["--all"], true);
    assert!(output.2.contains("was already linked"),
            "stdout:\n{}\nstderr:\n{}", output.1, output.2);
    eprintln!("{:?}", output);
    let bytes = compare(bytes, &alice_cert_pgp, false);

    sq_verify(Some(&certd), None, &[], &[], &alice_sig_file, 1, 0);

    sq_verify(Some(&certd),
              Some(now() + chrono::Duration::seconds(6 * 24 * 60 * 60)),
              &[], &[], &alice_sig_file, 1, 0);

    sq_verify(Some(&certd),
              Some(now() + chrono::Duration::seconds(8 * 24 * 60 * 60)),
              &[], &[], &alice_sig_file, 1, 0);

    let _bytes = bytes;

    Ok(())
}
