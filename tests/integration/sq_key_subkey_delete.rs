use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;
use openpgp::KeyID;
use openpgp::Result;
use openpgp::packet::Key;

use super::common::power_set;
use super::common::Sq;

#[test]
fn sq_key_subkey_delete() -> Result<()>
{
    let sq = Sq::new();

    // Generate a key in a file.
    let (cert, cert_file, _rev_file) = sq.key_generate(&[], &["alice"]);
    assert!(cert.is_tsk());

    // Delete each non-empty subset of keys.

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

    for (((i, to_delete), keystore), by_fpr) in power_set(&key_ids).into_iter()
        .enumerate()
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
        eprintln!("  Deleting:");
        for k in to_delete.iter() {
            eprintln!("    {}", k);
        }

        let to_delete_kh: Vec<KeyHandle> = if by_fpr {
            to_delete.iter()
                .map(|fpr| KeyHandle::from(fpr))
                .collect()
        } else {
            to_delete.iter()
                .map(|fpr| KeyHandle::from(KeyID::from(fpr)))
                .collect()
        };

        // Delete the selection.
        let got = if keystore {
            // Import it into the key store.
            sq.key_import(&cert_file);

            sq.key_subkey_delete(
                cert.key_handle(), &to_delete_kh, None)
        } else {
            sq.key_subkey_delete(
                &cert_file, &to_delete_kh,
                std::path::PathBuf::from("-").as_path())
        };

        // Make sure we got exactly what we asked for; no
        // more, no less.
        eprintln!("  Got:");

        let mut deletions = 0;
        for got in got.keys() {
            eprintln!("    {} {} secret key material",
                      got.fingerprint(),
                      if got.has_secret() {
                          "has"
                      } else {
                          "doesn't have"
                      });

            let should_have_deleted
                = to_delete.contains(&got.fingerprint());

            if should_have_deleted {
                assert!(
                    ! got.has_secret(),
                    "got secret key material \
                     for a key we deleted ({})",
                    got.fingerprint());

                deletions += 1;
            } else {
                assert!(
                    got.has_secret(),
                    "didn't get secret key material \
                     for a key we didn't delete ({})",
                    got.fingerprint());
            }
        }
        assert_eq!(deletions, to_delete.len());
    }

    Ok(())
}
