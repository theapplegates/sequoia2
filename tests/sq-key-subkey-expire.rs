use std::time::Duration;

use openpgp::parse::Parse;
use openpgp::Cert;
use openpgp::Result;
use sequoia_openpgp as openpgp;

mod common;
use common::sq_key_generate;
use common::STANDARD_POLICY;
use common::Sq;
use common::power_set;
use common::time_as_string;

#[test]
fn sq_key_subkey_expire() -> Result<()> {
    let (tmpdir, cert_path, time) = sq_key_generate(None)?;
    let cert_path = cert_path.display().to_string();
    let cert = Cert::from_file(&cert_path)?;

    let updated_path = &tmpdir.path().join("updated.pgp");
    let updated2_path = &tmpdir.path().join("updated2.pgp");

    let keys = cert.keys().map(|k| k.fingerprint()).collect::<Vec<_>>();

    for expiring in power_set(&keys) {
        let mut sq = Sq::at(time.into());

        // Two days go by.
        sq.tick(2 * 24 * 60 * 60);

        let cert_expiring = expiring.contains(&cert.fingerprint());

        for (i, fpr) in keys.iter().enumerate() {
            eprintln!("  {}. {}: {}expiring",
                      i, fpr,
                      if expiring.contains(&fpr) {
                          ""
                      } else {
                          "NOT "
                      });
        }

        // Change the key to expire in one day.
        let mut cmd = sq.command();
        cmd.args([
            "--force",
            "key", "subkey", "expire", "1d",
            "--cert-file", &cert_path,
            "--output", &updated_path.to_string_lossy(),
        ]);
        for k in expiring.iter() {
            cmd.args(["--key", &k.to_string()]);
        }
        sq.run(cmd, true);

        eprintln!("Updated keys at {} to expire in one day:\n{}",
                  sq.now_as_string(),
                  sq.inspect(&updated_path));

        let updated = Cert::from_file(&updated_path).expect("valid cert");

        // It should be alive now.
        let vc = updated.with_policy(STANDARD_POLICY, sq.now()).expect("valid");
        for k in vc.keys() {
            assert!(k.alive().is_ok());
        }

        // It should be alive in 1 day minus 1 second.
        let t = sq.now() + Duration::new(24 * 60 * 60 - 1, 0);
        eprintln!("Checking expiration status at {}", time_as_string(t.into()));
        let vc = updated.with_policy(STANDARD_POLICY, t).expect("valid");
        for k in vc.keys() {
            assert!(k.alive().is_ok());
        }

        // But in exactly one day, it should be expired.
        let t = sq.now() + Duration::new(24 * 60 * 60, 0);
        eprintln!("Checking expiration status at {}", time_as_string(t.into()));
        let vc = updated.with_policy(STANDARD_POLICY, t).expect("valid");
        for k in vc.keys() {
            assert_eq!(
                cert_expiring || expiring.contains(&k.fingerprint()),
                k.alive().is_err(),
                "{} is {}alive",
                k.fingerprint(),
                if k.alive().is_ok() { "" } else { "NOT "});
        }

        // 12 hours go by.  Clear the expiration time.
        sq.tick(12 * 60 * 60);

        let mut cmd = sq.command();
        cmd.args([
            "--force",
            "key", "subkey", "expire", "never",
            "--cert-file", &updated_path.to_string_lossy(),
            "--output", &updated2_path.to_string_lossy(),
        ]);
        for k in expiring.iter() {
            cmd.args(["--key", &k.to_string()]);
        }
        sq.run(cmd, true);

        let updated = Cert::from_file(&updated2_path).expect("valid cert");

        eprintln!("Updated keys at {} to never expire:\n{}",
                  sq.now_as_string(),
                  sq.inspect(&updated_path));

        // It should be alive now.
        let vc = updated.with_policy(STANDARD_POLICY, sq.now())
            .expect("valid");
        for k in vc.keys() {
            assert!(k.alive().is_ok());
        }

        // It should be alive in 1 day minus 1 second.
        let t = sq.now() + Duration::new(24 * 60 * 60 - 1, 0);
        eprintln!("Checking expiration status at {}", time_as_string(t.into()));
        let vc = updated.with_policy(STANDARD_POLICY, t).expect("valid");
        for k in vc.keys() {
            assert!(k.alive().is_ok());
        }

        // And in exactly one day...
        let t = sq.now() + Duration::new(24 * 60 * 60, 0);
        eprintln!("Checking expiration status at {}", time_as_string(t.into()));
        let vc = updated.with_policy(STANDARD_POLICY, t).expect("valid");
        for k in vc.keys() {
            assert!(k.alive().is_ok());
        }
    }

    tmpdir.close()?;

    Ok(())
}
