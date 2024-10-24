use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;
use openpgp::KeyID;
use openpgp::Result;
use openpgp::packet::Key;

use super::common::power_set;
use super::common::Sq;

#[test]
fn sq_key_subkey_password_0() -> Result<()> {
    sq_key_subkey_password_mod(0)
}

#[test]
fn sq_key_subkey_password_1() -> Result<()> {
    sq_key_subkey_password_mod(1)
}

#[test]
fn sq_key_subkey_password_2() -> Result<()> {
    sq_key_subkey_password_mod(2)
}

#[test]
fn sq_key_subkey_password_3() -> Result<()> {
    sq_key_subkey_password_mod(3)
}

fn sq_key_subkey_password_mod(modulus: usize) -> Result<()>
{
    let sq = Sq::new();

    let password_txt = sq.scratch_file("password_txt");
    std::fs::write(&password_txt, "a new password 1234").expect("can write");

    // Generate a key in a file.
    let (cert, cert_file, _rev_file) = sq.key_generate(&[], &["alice"]);
    assert!(cert.is_tsk());

    // Change the password each non-empty subset of keys.

    eprintln!("Certificate:");
    for k in cert.keys() {
        eprintln!("  {}", k.fingerprint());
    }

    let keys: Vec<Key<_, _>> = cert.keys()
        .map(|k| {
            k.key().clone()
        })
        .collect();

    let key_ids = keys.iter().map(|k| k.fingerprint()).collect::<Vec<_>>();

    for (((i, to_change), keystore), by_fpr) in power_set(&key_ids).into_iter()
        .enumerate()
        .filter(|(i, _)| i % 4 == modulus)
        .flat_map(|x| [(x.clone(), false), (x.clone(), true)])
        .flat_map(|x| [(x.clone(), false), (x.clone(), true)])
    {
        eprintln!("Test #{}, by {}, from {}:",
                  i + 1,
                  if by_fpr { "fingerprint" } else { "key ID" },
                  if keystore {
                      "the key store".to_string()
                  } else {
                      cert_file.display().to_string()
                  });
        eprintln!("  Changing the password for:");
        for k in to_change.iter() {
            eprintln!("    {}", k);
        }

        let to_change_kh: Vec<KeyHandle> = if by_fpr {
            to_change.iter()
                .map(|fpr| KeyHandle::from(fpr))
                .collect()
        } else {
            to_change.iter()
                .map(|fpr| KeyHandle::from(KeyID::from(fpr)))
                .collect()
        };

        // Change the password for the selection.
        let got = if keystore {
            // Import it into the key store.
            sq.key_import(&cert_file);

            sq.key_subkey_password(
                cert.key_handle(), &to_change_kh,
                None, Some(&password_txt),
                None, true)
                .expect("can change password")
        } else {
            sq.key_subkey_password(
                &cert_file, &to_change_kh,
                None, Some(&password_txt),
                std::path::PathBuf::from("-").as_path(), true)
                .expect("can change password")
        };

        // Make sure we got exactly what we asked for; no
        // more, no less.
        eprintln!("  Got:");

        let mut changes = 0;
        for got in got.keys() {
            eprintln!("    {} {} encrypted secret key material",
                      got.fingerprint(),
                      if got.has_unencrypted_secret() {
                          "doesn't have"
                      } else {
                          "has"
                      });

            let should_have_changed
                = to_change.contains(&got.fingerprint());

            if should_have_changed {
                assert!(
                    ! got.has_unencrypted_secret(),
                    "got unencrypted secret key material \
                     for a key whose password we changed ({})",
                    got.fingerprint());

                changes += 1;
            } else {
                assert!(
                    got.has_unencrypted_secret(),
                    "didn't get encrypted secret key material \
                     for a key whose password we changed ({})",
                    got.fingerprint());
            }
        }
        assert_eq!(changes, to_change.len());
    }

    Ok(())
}
