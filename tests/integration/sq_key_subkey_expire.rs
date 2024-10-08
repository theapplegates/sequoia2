use std::time::Duration;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::KeyHandle;
use openpgp::Result;
use openpgp::parse::Parse;

use super::common::STANDARD_POLICY;
use super::common::Sq;
use super::common::power_set;
use super::common::time_as_string;

#[test]
fn sq_key_subkey_expire() -> Result<()> {
    let mut sq = Sq::new();

    let (cert, cert_path, _rev_path)
        = sq.key_generate(&[], &["alice <alice@example.org>"]);
    let fpr = cert.fingerprint().to_string();

    let updated_path = sq.scratch_file("updated.pgp");
    let updated2_path = sq.scratch_file("updated2.pgp");

    let keys = cert.keys().map(|k| k.fingerprint()).collect::<Vec<_>>();

    // Two days go by.
    sq.tick(2 * 24 * 60 * 60);

    for expiring in power_set(&keys) {
        for keystore in [false, true] {
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

            if keystore {
                sq.key_import(&cert_path);
            }

            // Change the key to expire in one day.
            let mut cmd = sq.command();
            cmd.args([
                "key", "subkey", "expire", "1d",
            ]);
            if keystore {
                cmd.args(["--cert", &fpr ]);
            } else {
                cmd
                    .arg("--overwrite")
                    .arg("--cert-file").arg(&cert_path)
                    .arg("--output").arg(&updated_path);
            }
            for k in expiring.iter() {
                cmd.args(["--key", &k.to_string()]);
            }
            sq.run(cmd, true);

            eprintln!("Updated keys at {} to expire in one day:\n{}",
                      sq.now_as_string(),
                      sq.inspect(&updated_path));

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
            cmd.args([ "key", "subkey", "expire", "never" ]);
            if keystore {
                cmd.args([ "--cert", &fpr ]);
            } else {
                cmd
                    .arg("--overwrite")
                    .arg("--cert-file").arg(&updated_path)
                    .arg("--output").arg(&updated2_path);
            }
            for k in expiring.iter() {
                cmd.args(["--key", &k.to_string()]);
            }
            sq.run(cmd, true);

            let updated = if keystore {
                eprintln!("Updated certificate at {} to never expire:\n{}",
                          sq.now_as_string(),
                          sq.inspect(cert.key_handle()));

                sq.cert_export(cert.key_handle())
            } else {
                eprintln!("Updated certificate at {} to never expire:\n{}",
                          sq.now_as_string(),
                          sq.inspect(&updated2_path));

                Cert::from_file(&updated2_path).expect("valid cert")
            };

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
                eprintln!("  {} expires at {}",
                          k.fingerprint(),
                          if let Some(t) = k.key_expiration_time() {
                              time_as_string(t.into())
                          } else {
                              "never".to_string()
                          });
                if let Err(err) = k.alive() {
                    panic!("{} should be alive, but it's not: {}",
                           k.fingerprint(), err);
                }
            }

            // And in exactly one day...
            let t = sq.now() + Duration::new(24 * 60 * 60, 0);
            eprintln!("Checking expiration status at {}", time_as_string(t.into()));
            let vc = updated.with_policy(STANDARD_POLICY, t).expect("valid");
            for k in vc.keys() {
                eprintln!("  {} expires at {}",
                          k.fingerprint(),
                          if let Some(t) = k.key_expiration_time() {
                              time_as_string(t.into())
                          } else {
                              "never".to_string()
                          });
                if let Err(err) = k.alive() {
                    panic!("{} should be alive, but it's not: {}",
                           k.fingerprint(), err);
                }
            }
        }
    }

    Ok(())
}

#[test]
fn unbound_subkey() {
    // Make sure we can't extend the expiration time of an unbound
    // subkey.

    let sq = Sq::new();

    let cert_path = sq.test_data()
        .join("keys")
        .join("unbound-subkey.pgp");

    let cert = Cert::from_file(&cert_path).expect("can read");
    let vc = cert.with_policy(STANDARD_POLICY, sq.now())
        .expect("valid cert");

    // One subkey should be considered invalid.
    assert!(vc.keys().count() < cert.keys().count());

    let unbound = "E992BF8BA7A27BB4FBB71D973857E47B14874045"
        .parse::<KeyHandle>().expect("valid");

    // Set it to expire in a day.
    let updated_path = sq.scratch_file("updated");
    let updated = sq.key_subkey_expire(cert_path,
                                       &[ unbound ],
                                       "1d",
                                       None,
                                       updated_path.as_path(),
                                       false);
    assert!(updated.is_err());
}
