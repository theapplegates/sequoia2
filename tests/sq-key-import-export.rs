use assert_cmd::Command;

use tempfile::TempDir;

use sequoia_openpgp as openpgp;
use openpgp::KeyID;
use openpgp::Result;
use openpgp::cert::prelude::*;
use openpgp::packet::Key;
use openpgp::parse::Parse;

mod integration {
    use super::*;

    #[test]
    fn sq_key_import_export() -> Result<()>
    {
        let dir = TempDir::new()?;

        let rev_pgp = dir.path().join("rev.pgp");
        let rev_pgp_str = &*rev_pgp.to_string_lossy();

        let key_pgp = dir.path().join("key.pgp");
        let key_pgp_str = &*key_pgp.to_string_lossy();

        // Generate a few keys as red herrings.
        for _ in 0..10 {
            let mut cmd = Command::cargo_bin("sq")?;
            cmd.env("SEQUOIA_HOME", dir.path());
            cmd.args(["--force", "key", "generate",
                      "--no-userids",
                      "--rev-cert", &rev_pgp_str]);
            cmd.assert().success();
        }

        // Generate a key in a file.
        let mut cmd = Command::cargo_bin("sq")?;
        cmd.env("SEQUOIA_HOME", dir.path());
        cmd.args(["key", "generate",
                  "--no-userids",
                  "--output", &key_pgp_str]);
        cmd.assert().success();

        let cert = Cert::from_file(&key_pgp)?;
        assert!(cert.is_tsk());

        // Import it into the key store.
        let mut cmd = Command::cargo_bin("sq")?;
        cmd.env("SEQUOIA_HOME", dir.path());
        cmd.args(["key", "import",
                  &*key_pgp.to_string_lossy()]);
        cmd.assert().success();

        // Export the whole certificate.
        for by_fpr in [true, false] {
            let mut cmd = Command::cargo_bin("sq")?;
            cmd.env("SEQUOIA_HOME", dir.path());
            cmd.args(["key", "export", "--cert",
                      &if by_fpr {
                          cert.fingerprint().to_string()
                      } else {
                          cert.keyid().to_string()
                      }]);
            let result = cmd.assert().success();
            let stdout = &result.get_output().stdout;

            let got = Cert::from_bytes(stdout).expect("cert");
            assert_eq!(cert, got);
        }

        // Export each non-empty subset of keys.

        eprintln!("Certificate:");
        for k in cert.keys() {
            eprintln!("  {}", k.fingerprint());
        }

        // Returns the power set excluding the empty set.
        fn power_set<T: Clone>(set: &[T]) -> Vec<Vec<T>> {
            let mut power_set: Vec<Vec<T>> = Vec::new();
            for element in set.iter() {
                power_set.extend(
                    power_set.clone().into_iter().map(|mut v: Vec<T>| {
                        v.push(element.clone());
                        v
                    }));
                power_set.push(vec![ element.clone() ]);
            }
            power_set
        }

        let keys: Vec<Key<_, _>> = cert.keys()
            .map(|k| {
                k.key().clone()
            })
            .collect();

        let key_ids = keys.iter().map(|k| k.fingerprint()).collect::<Vec<_>>();

        for (i, selection) in power_set(&key_ids).into_iter().enumerate() {
            for by_fpr in [true, false] {
                eprintln!("Test #{}, by {}:",
                          i + 1,
                          if by_fpr { "fingerprint" } else { "key ID" });
                eprintln!("  Exporting:");
                for k in selection.iter() {
                    eprintln!("    {}", k);
                }

                // Export the selection.
                let mut cmd = Command::cargo_bin("sq")?;
                cmd.env("SEQUOIA_HOME", dir.path());
                cmd.args(["key", "export"]);
                for id in selection.iter() {
                    if by_fpr {
                        cmd.args(["--key", &id.to_string()]);
                    } else {
                        cmd.args(["--key", &KeyID::from(id).to_string()]);
                    }
                }
                eprintln!("  Running: {:?}", cmd);
                let result = cmd.assert().success();
                let stdout = &result.get_output().stdout;

                let got = Cert::from_bytes(stdout).expect("cert");

                // Make sure we got exactly what we asked for; no
                // more, no less.
                eprintln!("  Got:");

                let mut secrets = 0;
                for got in got.keys() {
                    let expected = keys.iter()
                        .find(|k| k.fingerprint() == got.fingerprint())
                        .expect("have key");

                    eprintln!("    {} {} secret key material",
                              got.fingerprint(),
                              if got.has_secret() {
                                  "has"
                              } else {
                                  "doesn't have"
                              });

                    if let Ok(got) = got.parts_as_secret() {
                        assert!(
                            selection.contains(&got.fingerprint()),
                            "got secret key material \
                             for a key we didn't ask for ({})",
                            got.fingerprint());

                        assert_eq!(expected.parts_as_secret().expect("have secrets"),
                                   got.key());

                        secrets += 1;
                    } else {
                        assert!(
                            ! selection.contains(&got.fingerprint()),
                            "didn't get secret key material \
                             for a key we asked for ({})",
                            got.fingerprint());

                        assert_eq!(expected, got.key());
                    }
                }
                assert_eq!(secrets, selection.len());
            }
        }

        Ok(())
    }
}
