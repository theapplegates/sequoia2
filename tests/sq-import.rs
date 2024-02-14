use tempfile::TempDir;
use assert_cmd::Command;

use sequoia_openpgp as openpgp;
use openpgp::Result;
use openpgp::cert::prelude::*;
use openpgp::parse::Parse;

#[test]
fn sq_import() -> Result<()>
{
    let dir = TempDir::new()?;

    let certd = dir.path().join("cert.d").display().to_string();
    std::fs::create_dir(&certd).expect("mkdir works");

    let alice_pgp = dir.path().join("alice.pgp").display().to_string();
    let alice_pgp = &alice_pgp[..];
    let bob_pgp = dir.path().join("bob.pgp").display().to_string();
    let bob_pgp = &bob_pgp[..];
    let carol_pgp = dir.path().join("carol.pgp").display().to_string();
    let carol_pgp = &carol_pgp[..];

    // Generate keys.
    let mut cmd = Command::cargo_bin("sq")?;
    cmd.args(["--cert-store", &certd,
              "key", "generate",
              "--expiry", "never",
              "--userid", "<alice@example.org>",
              "--output", &alice_pgp]);
    cmd.assert().success();

    let alice_bytes = std::fs::read(&alice_pgp)?;

    let mut cmd = Command::cargo_bin("sq")?;
    cmd.args(["--cert-store", &certd,
              "key", "generate",
              "--expiry", "never",
              "--userid", "<bob@example.org>",
              "--output", bob_pgp]);
    cmd.assert().success();

    let mut cmd = Command::cargo_bin("sq")?;
    cmd.args(["--cert-store", &certd,
              "key", "generate",
              "--expiry", "never",
              "--userid", "<carol@example.org>",
              "--output", carol_pgp]);
    cmd.assert().success();

    let files = &[ alice_pgp, bob_pgp, carol_pgp ];

    let check = |files: &[&str], stdin: Option<&[u8]>, expected: usize|
    {
        // Use a fresh certd.
        let dir = TempDir::new().unwrap();
        let certd = dir.path().join("cert.d").display().to_string();

        // Import.
        let mut cmd = Command::cargo_bin("sq").unwrap();
        cmd.args(["--cert-store", &certd, "cert", "import"]);
        cmd.args(files);
        if let Some(stdin) = stdin {
            cmd.write_stdin(stdin);
        }
        eprintln!("sq cert import {}{}",
                  files.join(" "),
                  if stdin.is_some() { "<BYTES" } else { "" });
        cmd.assert().success();


        // Export.
        let mut cmd = Command::cargo_bin("sq").unwrap();
        cmd.args(["--cert-store", &certd, "cert", "export", "--all"]);

        eprintln!("sq cert export...");

        let output = cmd.output().expect("success");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(output.status.success(),
                "sq cert export should succeed\n\
                 stdout:\n{}\nstderr:\n{}",
                stdout, stderr);

        let parser = CertParser::from_bytes(stdout.as_bytes())
            .expect("valid");
        let found = parser.collect::<Result<Vec<Cert>>>()
            .expect("valid");

        assert_eq!(expected, found.len(),
                   "expected: {}\nfound: {} ({})\n\
                    stdout:\n{}\nstderr:\n{}",
                   expected, found.len(),
                   found.iter().map(|c| c.fingerprint().to_string())
                   .collect::<Vec<_>>()
                   .join(", "),
                   stdout, stderr);
    };

    // Import from N files.
    for i in 1..=files.len() {
        check(&files[0..i], None, i);
    }

    // Import from stdin.
    check(&[], Some(&alice_bytes[..]), 1);

    // Specify "-".
    check(&["-"], Some(&alice_bytes[..]), 1);

    // Provide stdin and a file.  Only the file should be read.
    check(&[bob_pgp], Some(&alice_bytes[..]), 1);

    // Provide stdin explicitly and a file.  Both should be read.
    check(&[bob_pgp, "-"], Some(&alice_bytes[..]), 2);

    Ok(())
}
