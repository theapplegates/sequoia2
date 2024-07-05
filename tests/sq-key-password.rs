use openpgp::Result;
use sequoia_openpgp as openpgp;

mod common;
use common::FileOrKeyHandle;
use common::Sq;

#[test]
fn sq_key_password() -> Result<()> {
    let mut sq = Sq::new();

    let (cert, cert_path, _rev_path) = sq.key_generate(&[], &["alice"]);

    let orig_password = sq.scratch_file("orig-password.txt");
    std::fs::write(&orig_password, "t00 ez").unwrap();

    let new_password = sq.scratch_file("new-password.txt");
    std::fs::write(&new_password, "crazy passw0rd").unwrap();

    let msg_txt = sq.scratch_file("msg.txt");
    std::fs::write(&msg_txt, "hello world").unwrap();


    for keystore in [false, true] {
        eprintln!("Keystore: {}", keystore);

        // Two days go by.
        sq.tick(2 * 24 * 60 * 60);

        if keystore {
            sq.key_import(&cert_path);
        }

        let cert_handle = if keystore {
            FileOrKeyHandle::from(cert.fingerprint())
        } else {
            cert_path.as_path().into()
        };

        // Sign a message.  No password should be required.
        sq.sign(&cert_handle, None, msg_txt.as_path(), None);

        // Change the key's password.
        eprintln!("Change the key's password.");
        let cert_updated = sq.scratch_file("cert-updated");
        let cert = sq.key_password(
            &cert_handle,
            None, Some(&new_password),
            if keystore { None } else { Some(cert_updated.as_path()) },
            true)
            .expect("can set password");
        assert!(cert.keys().all(|ka| {
            ka.has_secret()
                && ! ka.has_unencrypted_secret()
        }));

        let cert_handle = if keystore {
            FileOrKeyHandle::from(cert.fingerprint())
        } else {
            cert_updated.as_path().into()
        };

        // Sign a message.
        sq.sign(&cert_handle,
                Some(new_password.as_path()),
                msg_txt.as_path(), None);

        // Clear the key's password.
        eprintln!("Clear the key's password.");
        let cert_updated2 = sq.scratch_file("cert-updated2");

        let cert = sq.key_password(
            &cert_handle,
            Some(&new_password), None,
            if keystore { None } else { Some(cert_updated2.as_path()) },
            true)
            .expect("can set password");
        assert!(cert.keys().all(|ka| ka.has_unencrypted_secret()));

        let cert_handle = if keystore {
            FileOrKeyHandle::from(cert.fingerprint())
        } else {
            cert_updated2.as_path().into()
        };

        // Sign a message.
        sq.sign(&cert_handle, None, msg_txt.as_path(), None);
    }

    Ok(())
}
