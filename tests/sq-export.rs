use std::borrow::Cow;
use std::ops::Deref;

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
    fn sq_export() -> Result<()>
    {
        let dir = TempDir::new()?;

        let certd = dir.path().join("cert.d").display().to_string();
        std::fs::create_dir(&certd).expect("mkdir works");

        struct Data {
            userids: &'static [&'static str],
            filename: String,
            cert: Option<Cert>,
        }

        impl Data {
            fn cert(&self) -> &Cert {
                self.cert.as_ref().expect("have the cert")
            }
        }

        let data: &mut [Data] = &mut [
            Data {
                userids: &[ "<alice@example.org>" ][..],
                filename: dir.path().join("alice.pgp").display().to_string(),
                cert: None,
            },
            Data {
                userids: &[ "<bob@example.org>" ][..],
                filename: dir.path().join("bob.pgp").display().to_string(),
                cert: None,
            },
            Data {
                userids: &[
                    "<carol@sub.example.org>",
                    "<carol@other.org>",
                ][..],
                filename: dir.path().join("carol.pgp").display().to_string(),
                cert: None,
            },
        ][..];

        // Generate and import the keys.
        for data in data.iter_mut() {
            eprintln!("Generating key for {}",
                      data.userids.join(", "));
            let mut cmd = Command::cargo_bin("sq")?;
            cmd.args(["--cert-store", &certd,
                      "key", "generate",
                      "--expiry", "never",
                      "--output", &data.filename]);
            for userid in data.userids.iter() {
                cmd.args(["--userid", userid]);
            }
            cmd.assert().success();

            let cert = Cert::from_file(&data.filename)?;
            eprintln!("Importing {}", cert.fingerprint());

            data.cert = Some(cert);

            let mut cmd = Command::cargo_bin("sq")?;
            cmd.args(["--cert-store", &certd,
                      "cert", "import",
                      &data.filename]);
            cmd.assert().success();
        }

        assert_eq!(data.len(), 3);
        let alice = &data[0];
        let bob = &data[1];
        let carol = &data[2];

        // Checks that the data contains exactly the listed
        // certificates.
        let check = |data: &[&Data], stdout: Cow<str>, stderr: Cow<str>| {
            let parser = CertParser::from_bytes(stdout.as_bytes())
                .expect("valid");
            let found = parser.collect::<Result<Vec<Cert>>>()
                .expect("valid");

            assert_eq!(found.len(), data.len(),
                       "found: {}\nexpected: {}\n\
                        stdout:\n{}\nstderr:\n{}",
                       found.iter().map(|c| c.fingerprint().to_string())
                           .collect::<Vec<_>>()
                           .join(", "),
                       data.iter().map(|d| d.cert().fingerprint().to_string())
                           .collect::<Vec<_>>()
                           .join(", "),
                       stdout, stderr);
            for cert in found.iter() {
                let fpr = cert.fingerprint();
                if let Some(_data) = data.iter().find(|data| {
                    data.cert().fingerprint() == fpr
                }) {
                    ()
                } else {
                    panic!("Didn't find {} (have: {})\n\
                            stdout:\n{}\nstderr:\n{}",
                           fpr,
                           data.iter()
                               .map(|d| d.cert().fingerprint().to_string())
                               .collect::<Vec<String>>()
                               .join(", "),
                           stdout, stderr);
                };
            }
        };

        // args: --cert|--key|--userid|... pattern
        let call = |args: &[&str], success: bool, data: &[&Data]| {
            let mut cmd = Command::cargo_bin("sq").unwrap();
            cmd.args(["--cert-store", &certd,
                      "cert", "export"]);
            cmd.args(args);

            let args = args.iter()
                .map(|s| format!("{:?}", s))
                .collect::<Vec<_>>()
                .join(" ");
            eprintln!("sq cert export {}...", args);

            let output = cmd.output().expect("success");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            if success {
                assert!(output.status.success(),
                        "sq cert export {} should succeed\n\
                         stdout:\n{}\nstderr:\n{}",
                        args, stdout, stderr);
                check(data, stdout, stderr);
            } else {
                assert!(! output.status.success(),
                        "sq cert export {} should fail\n\
                         stdout:\n{}\nstderr:\n{}",
                        args, stdout, stderr);
                check(&[], stdout, stderr);
            }
        };

        for data in data.iter() {
            let cert = data.cert.as_ref().unwrap();

            // Export them by the cert's fingerprint and keyid.
            for ka in cert.keys() {
                for kh in [ KeyHandle::from(ka.fingerprint()),
                            KeyHandle::from(ka.keyid()) ]
                {
                    call(&["--cert", &kh.to_string()], ka.primary(), &[data]);
                }
            }

            // Export them by fingerprint and keyid.
            for kh in cert.keys().map(|ka| KeyHandle::from(ka.fingerprint()))
                .chain(cert.keys().map(|ka| KeyHandle::from(ka.keyid())))
            {
                call(&["--key", &kh.to_string()], true, &[data]);
            }

            for ua in cert.userids() {
                // Export by user id.
                let userid = String::from_utf8_lossy(
                    ua.userid().value()).into_owned();
                let email = ua.userid().email2().unwrap().unwrap();

                call(&["--userid", &userid], true, &[data]);
                call(&["--userid", &email], false, &[]);
                // Should be case sensitive.
                call(&["--userid", &userid.deref().to_uppercase()], false, &[]);
                // Substring should fail.
                call(&["--userid", &userid[1..]], false, &[]);

                call(&["--email", &userid], false, &[]);
                call(&["--email", &email], true, &[data]);
                // Email is case insensitive.
                call(&["--email", &email.to_uppercase()], true, &[data]);
                // Substring should fail.
                call(&["--email", &email[1..]], false, &[]);

                call(&["--grep", &userid], true, &[data]);
                call(&["--grep", &email], true, &[data]);
                // Should be case insensitive.
                call(&["--grep", &userid.deref().to_uppercase()], true, &[data]);
                // Substring should succeed.
                call(&["--grep", &userid[1..]], true, &[data]);

            }
        }

        // By domain.
        call(&["--domain", "example.org"], true, &[alice, bob]);
        call(&["--domain", "EXAMPLE.ORG"], true, &[alice, bob]);
        call(&["--domain", "sub.example.org"], true, &[carol]);
        call(&["--domain", "SUB.EXAMPLE.ORG"], true, &[carol]);
        call(&["--domain", "other.org"], true, &[carol]);

        call(&["--domain", "hello.com"], false, &[]);
        call(&["--domain", "me@hello.com"], false, &[]);
        call(&["--domain", "alice@example.org"], false, &[]);
        call(&["--domain", "xample.org"], false, &[]);
        call(&["--domain", "example.or"], false, &[]);
        call(&["--domain", "@example.org"], false, &[]);

        // Match a cert in many ways.  It should only be exported
        // once.
        call(&["--cert", &carol.cert().fingerprint().to_string(),
               "--key",
               &carol.cert().keys().nth(1).unwrap().fingerprint().to_string(),
               "--userid", carol.userids[0],
               "--email", "carol@example.org",
               "--domain", "other.org"
        ], true, &[carol]);

        // Match multiple certs in different ways.
        call(&["--cert", &alice.cert().fingerprint().to_string(),
               "--key", &bob.cert().fingerprint().to_string(),
               "--email", "carol@sub.example.org",
        ], true, &[alice, bob, carol]);

        Ok(())
    }
}
