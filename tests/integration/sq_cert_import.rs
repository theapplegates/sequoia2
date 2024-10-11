use sequoia_openpgp as openpgp;
use openpgp::Result;
use openpgp::cert::prelude::*;
use openpgp::parse::Parse;

use super::common::Sq;

#[test]
fn sq_cert_import() -> Result<()>
{
    let sq = Sq::new();

    // Generate keys.
    let (_cert, alice_pgp, _rev) =
        sq.key_generate(&["--expiration", "never"], &["<alice@example.org>"]);

    let alice_bytes = std::fs::read(&alice_pgp)?;

    let (_cert, bob_pgp, _rev) =
        sq.key_generate(&["--expiration", "never"], &["<bob@example.org>"]);

    let (_cert, carol_pgp, _rev) =
        sq.key_generate(&["--expiration", "never"], &["<carol@example.org>"]);

    let alice_pgp = alice_pgp.display().to_string();
    let alice_pgp = &alice_pgp[..];
    let bob_pgp = bob_pgp.display().to_string();
    let bob_pgp = &bob_pgp[..];
    let carol_pgp = carol_pgp.display().to_string();
    let carol_pgp = &carol_pgp[..];

    let files = &[ alice_pgp, bob_pgp, carol_pgp ];

    let check = |files: &[&str], stdin: Option<&[u8]>, expected: usize|
    {
        // Use a fresh certd.
        let sq = Sq::new();

        // Import.
        let mut cmd = sq.command();
        cmd.args(["cert", "import"]);
        cmd.args(files);
        if let Some(stdin) = stdin {
            cmd.write_stdin(stdin);
        }
        eprintln!("sq cert import {}{}",
                  files.join(" "),
                  if stdin.is_some() { "<BYTES" } else { "" });
        cmd.assert().success();


        // Export.
        let mut cmd = sq.command();
        cmd.args(["cert", "export", "--all"]);

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
