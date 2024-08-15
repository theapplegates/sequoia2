use std::time::Duration;

use openpgp::parse::Parse;
use openpgp::Cert;
use openpgp::Result;
use sequoia_openpgp as openpgp;

use super::common::STANDARD_POLICY;
use super::common::Sq;
use super::common::time_as_string;

#[test]
fn sq_key_expire() -> Result<()> {
    for keystore in [false, true] {
        let mut sq = Sq::new();

        let (cert, cert_path, _rev_path)
            = sq.key_generate(&[], &["alice <alice@example.org>"]);
        let fpr = cert.fingerprint().to_string();

        // Two days go by.
        sq.tick(2 * 24 * 60 * 60);

        let updated_path = sq.scratch_file("updated.pgp");
        let updated2_path = sq.scratch_file("updated2.pgp");

        if keystore {
            sq.key_import(&cert_path);
        }

        // Change the key to expire in one day.
        let mut cmd = sq.command();
        cmd.args(["key", "expire", "1d"]);
        if keystore {
            cmd.args(["--cert", &fpr ]);
        } else {
            cmd
                .arg("--force")
                .arg("--cert-file").arg(&cert_path)
                .arg("--output").arg(&updated_path);
        }
        sq.run(cmd, true);

        let updated = if keystore {
            eprintln!("Updated certificate to expire in one day:\n{}",
                      sq.inspect(cert.key_handle()));

            sq.cert_export(cert.key_handle())
        } else {
            eprintln!("Updated certificate to expire in one day:\n{}",
                      sq.inspect(&updated_path));

            Cert::from_file(&updated_path).expect("valid cert")
        };

        // It should be alive now.
        let vc = updated.with_policy(STANDARD_POLICY, sq.now()).expect("valid");
        assert!(matches!(vc.alive(), Ok(())));

        // It should be alive in 1 day minus 1 second.
        let t = sq.now() + Duration::new(24 * 60 * 60 - 1, 0);
        eprintln!("Checking expiration status at {}", time_as_string(t.into()));
        let vc = updated.with_policy(STANDARD_POLICY, t).expect("valid");
        assert!(matches!(vc.alive(), Ok(())));

        // But in exactly one day, it should be expired.
        let t = sq.now() + Duration::new(24 * 60 * 60, 0);
        eprintln!("Checking expiration status at {}", time_as_string(t.into()));
        let vc = updated.with_policy(STANDARD_POLICY, t).expect("valid");
        assert!(matches!(vc.alive(), Err(_)));

        // 12 hours go by.  Clear the expiration time.
        sq.tick(12 * 60 * 60);

        let mut cmd = sq.command();
        cmd.args([ "key", "expire", "never" ]);
        if keystore {
            cmd.args([ "--cert", &fpr ]);
        } else {
            cmd.args([
                "--cert-file", &updated_path.to_string_lossy(),
                "--output", &updated2_path.to_string_lossy(),
            ]);
        }
        sq.run(cmd, true);

        let updated = if keystore {
            eprintln!("Updated certificate to expire in one day:\n{}",
                      sq.inspect(cert.key_handle()));

            sq.cert_export(cert.key_handle())
        } else {
            eprintln!("Updated certificate to expire in one day:\n{}",
                      sq.inspect(&updated2_path));

            Cert::from_file(&updated2_path).expect("valid cert")
        };

        // It should be alive now.
        let vc = updated.with_policy(STANDARD_POLICY, None)
            .expect("valid");
        assert!(matches!(vc.alive(), Ok(())));

        // It should be alive in 1 day minus 1 second.
        let vc = updated.with_policy(
            STANDARD_POLICY,
            sq.now() + Duration::new(24 * 60 * 60 - 1, 0))
            .expect("valid");
        assert!(matches!(vc.alive(), Ok(())));

        // And in exactly one day...
        let vc = updated.with_policy(
            STANDARD_POLICY,
            sq.now() + Duration::new(24 * 60 * 60, 0))
            .expect("valid");
        assert!(matches!(vc.alive(), Ok(())));
    }

    Ok(())
}
