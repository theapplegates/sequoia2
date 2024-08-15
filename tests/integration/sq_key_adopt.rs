use super::common::FileOrKeyHandle;
use super::common::Sq;

#[cfg(test)]
mod integration {
    use super::*;

    use std::path;

    use sequoia_openpgp as openpgp;

    use openpgp::Fingerprint;
    use openpgp::KeyHandle;
    use openpgp::Result;
    use openpgp::cert::prelude::*;
    use openpgp::policy::StandardPolicy;
    use openpgp::types::KeyFlags;

    fn dir() -> path::PathBuf {
        path::Path::new("tests").join("data").join("keys")
    }
    fn alice() -> path::PathBuf {
        //     Fingerprint: 5CCB BA06 74EA 5162 615E  36E9 80E5 ADE9 43CA 0DC3
        // Public-key algo: EdDSA Edwards-curve Digital Signature Algorithm
        // Public-key size: 256 bits
        //      Secret key: Unencrypted
        //   Creation time: 2020-12-21 23:00:49 UTC
        //       Key flags: certification
        //
        //          Subkey: 6A3B 1EC7 6233 62BC 066E  75AB DC42 7976 95D6 24E5
        // Public-key algo: EdDSA Edwards-curve Digital Signature Algorithm
        // Public-key size: 256 bits
        //      Secret key: Unencrypted
        //   Creation time: 2020-12-21 23:00:49 UTC
        //       Key flags: signing
        //
        //          Subkey: 827E 4397 F330 7EDA 6ABD  2A6E AD9C 461D 6D2F 0982
        // Public-key algo: ECDH public key algorithm
        // Public-key size: 256 bits
        //      Secret key: Unencrypted
        //   Creation time: 2020-12-21 23:00:49 UTC
        //       Key flags: transport encryption, data-at-rest encryption
        //
        //          UserID: Alice Lovelace <alice@example.org>
        dir().join("alice-lovelace-encryption-subkey-signing-subkey-priv.pgp")
    }
    fn alice_primary() -> (Fingerprint, KeyFlags) {
        ("5CCB BA06 74EA 5162 615E  36E9 80E5 ADE9 43CA 0DC3".parse().unwrap(),
         KeyFlags::empty().set_certification())
    }
    fn alice_signing() -> (Fingerprint, KeyFlags) {
        ("6A3B 1EC7 6233 62BC 066E  75AB DC42 7976 95D6 24E5".parse().unwrap(),
         KeyFlags::empty().set_signing())
    }
    fn alice_encryption() -> (Fingerprint, KeyFlags) {
        ("827E 4397 F330 7EDA 6ABD  2A6E AD9C 461D 6D2F 0982".parse().unwrap(),
         KeyFlags::empty().set_transport_encryption().set_storage_encryption())
    }
    fn bob() -> path::PathBuf {
        //     Fingerprint: C1CF 22F6 C838 07CE 3901  6CDE 8463 B196 87EE 13BB
        // Public-key algo: EdDSA Edwards-curve Digital Signature Algorithm
        // Public-key size: 256 bits
        //      Secret key: Unencrypted
        //   Creation time: 2020-12-21 23:02:23 UTC
        //       Key flags: certification
        //
        //          UserID: Bob Babbage <bob@example.org>
        dir().join("bob-babbage-cert-only-priv.pgp")
    }
    fn bob_primary() -> (Fingerprint, KeyFlags) {
        ("C1CF 22F6 C838 07CE 3901  6CDE 8463 B196 87EE 13BB".parse().unwrap(),
         KeyFlags::empty().set_certification())
    }

    fn carol() -> path::PathBuf {
        //     Fingerprint: 0B17 34A8 2726 A5D1 D5AC  1568 1EC1 4781 FD88 09B4
        // Public-key algo: EdDSA Edwards-curve Digital Signature Algorithm
        // Public-key size: 256 bits
        //      Secret key: Unencrypted
        //   Creation time: 2020-12-22 00:02:24 UTC
        //       Key flags: certification
        //
        //          Subkey: 3D56 A424 3D5C C345 638D  FB19 05D8 B9EA DB92 A8C1
        // Public-key algo: EdDSA Edwards-curve Digital Signature Algorithm
        // Public-key size: 256 bits
        //      Secret key: Unencrypted
        //   Creation time: 2020-12-22 00:02:24 UTC
        //       Key flags: signing
        //
        //          Subkey: 1F47 6866 1260 CFFA D3DE  B630 5652 476A 8B74 5CE5
        // Public-key algo: ECDH public key algorithm
        // Public-key size: 256 bits
        //      Secret key: Unencrypted
        //   Creation time: 2020-12-22 00:02:24 UTC
        //       Key flags: transport encryption, data-at-rest encryption
        //
        //          UserID: Carol <carol@example.org>
        dir().join("carol-encryption-subkey-signing-subkey-priv.pgp")
    }
    fn carol_primary() -> (Fingerprint, KeyFlags) {
        ("0B17 34A8 2726 A5D1 D5AC  1568 1EC1 4781 FD88 09B4".parse().unwrap(),
         KeyFlags::empty().set_certification())
    }
    fn carol_signing() -> (Fingerprint, KeyFlags) {
        ("3D56 A424 3D5C C345 638D  FB19 05D8 B9EA DB92 A8C1".parse().unwrap(),
         KeyFlags::empty().set_signing())
    }
    fn carol_encryption() -> (Fingerprint, KeyFlags) {
        ("1F47 6866 1260 CFFA D3DE  B630 5652 476A 8B74 5CE5".parse().unwrap(),
         KeyFlags::empty().set_transport_encryption().set_storage_encryption())
    }

    fn check(cert: &Cert,
             key_count: usize,
             keys: ((Fingerprint, KeyFlags), &[(Fingerprint, KeyFlags)]))
        -> Result<()>
    {
        let p = &StandardPolicy::new();

        let vc = cert.with_policy(p, None).unwrap();

        assert_eq!(key_count, vc.keys().count());

        assert_eq!(vc.primary_key().fingerprint(), keys.0.0);
        assert_eq!(vc.primary_key().key_flags(), Some(keys.0.1));

        for (subkey, keyflags) in keys.1 {
            let mut found = false;
            for k in vc.keys().subkeys() {
                if k.fingerprint() == *subkey {
                    assert_eq!(k.key_flags().as_ref(), Some(keyflags));
                    found = true;
                    break;
                }
            }
            assert!(found);
        }

        Ok(())
    }

    #[test]
    fn adopt_encryption() -> Result<()> {
        for (keyrings, key_imports, handle) in [
            (
                // Keyrings
                &[ alice() ][..],
                // Key store imports.
                &[][..],
                // Handle
                FileOrKeyHandle::from(bob()),
            ),
            (
                // Keyrings
                &[][..],
                // Key store imports.
                &[ alice() ],
                // Handle
                bob().into()
            ),
            (
                // Keyrings
                &[][..],
                // Key store imports.
                &[ alice(), bob() ],
                // Handle
                bob_primary().0.into()
            ),
        ] {
            let sq = Sq::new();

            for file in key_imports {
                sq.key_import(file);
            }

            // Have Bob adopt alice's encryption subkey.
            let cert = sq.key_adopt(
                keyrings.to_vec(),
                handle,
                [ alice_encryption().0.clone() ].to_vec(),
                None,
                false,
                "-",
                true)
                .unwrap();

            assert!(
                check(&cert, 2, (bob_primary(), &[alice_encryption()])).is_ok());
        }

        Ok(())
    }

    #[test]
    fn adopt_signing() -> Result<()> {
        for (keyrings, key_imports, handle) in [
            (
                // Keyrings
                &[ alice() ][..],
                // Key store imports.
                &[][..],
                // Handle
                FileOrKeyHandle::from(bob()),
            ),
            (
                // Keyrings
                &[][..],
                // Key store imports.
                &[ alice() ],
                // Handle
                bob().into()
            ),
            (
                // Keyrings
                &[][..],
                // Key store imports.
                &[ alice(), bob() ],
                // Handle
                bob_primary().0.into()
            ),
        ] {
            let sq = Sq::new();

            for file in key_imports {
                sq.key_import(file);
            }

            // Adopt a signing subkey (subkey has secret key material).
            let cert = sq.key_adopt(
                keyrings.to_vec(),
                handle,
                [ alice_signing().0.clone() ].to_vec(),
                None,
                false,
                "-",
                true)
                .unwrap();

            assert!(
                check(&cert, 2, (bob_primary(), &[alice_signing()])).is_ok());
        }

        Ok(())
    }

    #[test]
    fn adopt_certification() -> Result<()> {
        for (keyrings, key_imports, handle) in [
            (
                // Keyrings
                &[ alice() ][..],
                // Key store imports.
                &[][..],
                // Handle
                FileOrKeyHandle::from(carol()),
            ),
            (
                // Keyrings
                &[][..],
                // Key store imports.
                &[ alice() ],
                // Handle
                carol().into()
            ),
            (
                // Keyrings
                &[][..],
                // Key store imports.
                &[ alice(), carol() ],
                // Handle
                carol_primary().0.into()
            ),
        ] {
            let sq = Sq::new();

            for file in key_imports {
                sq.key_import(file);
            }

            // Adopt a certification subkey (subkey has secret key
            // material).
            let cert = sq.key_adopt(
                keyrings.to_vec(),
                handle,
                [ alice_primary().0.clone() ].to_vec(),
                None,
                false,
                "-",
                true)
                .unwrap();

            assert!(check(&cert, 4, (carol_primary(), &[alice_primary()])).is_ok());
        }

        Ok(())
    }

    #[test]
    fn adopt_encryption_and_signing() -> Result<()> {
        for (keyrings, key_imports, handle) in [
            (
                // Keyrings
                &[ alice() ][..],
                // Key store imports.
                &[][..],
                // Handle
                FileOrKeyHandle::from(bob()),
            ),
            (
                // Keyrings
                &[][..],
                // Key store imports.
                &[ alice() ],
                // Handle
                bob().into()
            ),
            (
                // Keyrings
                &[][..],
                // Key store imports.
                &[ alice(), bob() ],
                // Handle
                bob_primary().0.into()
            ),
        ] {
            let sq = Sq::new();

            for file in key_imports {
                sq.key_import(file);
            }

            let cert = sq.key_adopt(
                keyrings.to_vec(),
                handle,
                [
                    alice_signing().0.clone(),
                    alice_encryption().0.clone(),
                ].to_vec(),
                None,
                false,
                "-",
                true)
                .unwrap();

            assert!(
                check(&cert, 3,
                      (bob_primary(),
                       &[alice_signing(), alice_encryption()]))
                    .is_ok());
        }

        Ok(())
    }

    #[test]
    fn adopt_twice() -> Result<()> {
        for (keyrings, key_imports, handle) in [
            (
                // Keyrings
                &[ alice() ][..],
                // Key store imports.
                &[][..],
                // Handle
                FileOrKeyHandle::from(bob()),
            ),
            (
                // Keyrings
                &[][..],
                // Key store imports.
                &[ alice() ],
                // Handle
                bob().into()
            ),
            (
                // Keyrings
                &[][..],
                // Key store imports.
                &[ alice(), bob() ],
                // Handle
                bob_primary().0.into()
            ),
        ] {
            let sq = Sq::new();

            for file in key_imports {
                sq.key_import(file);
            }

            // Adopt the same an encryption subkey twice.
            let cert = sq.key_adopt(
                keyrings.to_vec(),
                handle,
                [
                    alice_encryption().0.clone(),
                    alice_encryption().0.clone(),
                ].to_vec(),
                None,
                false,
                "-",
                true)
                .unwrap();

            assert!(
                check(&cert, 2, (bob_primary(), &[alice_encryption()])).is_ok());
        }

        Ok(())
    }

    #[test]
    fn adopt_key_appears_twice() -> Result<()> {
        let sq = Sq::new();

        // Adopt an encryption subkey that appears twice.
        let cert = sq.key_adopt(
            [ alice(), alice(), ].to_vec(),
            bob(),
            [
                alice_encryption().0.clone(),
            ].to_vec(),
            None,
            false,
            "-",
            true)
            .unwrap();

        assert!(
            check(&cert, 2, (bob_primary(), &[alice_encryption()])).is_ok());

        Ok(())
    }

    #[test]
    fn adopt_own_encryption() -> Result<()> {
        for (keyrings, key_imports, handle) in [
            (
                // Keyrings
                &[ alice() ][..],
                // Key store imports.
                &[][..],
                // Handle
                FileOrKeyHandle::from(alice()),
            ),
            (
                // Keyrings
                &[][..],
                // Key store imports.
                &[ alice() ],
                // Handle
                alice().into()
            ),
            (
                // Keyrings
                &[][..],
                // Key store imports.
                &[ alice(), bob() ],
                // Handle
                alice_primary().0.into()
            ),
        ] {
            let sq = Sq::new();

            for file in key_imports {
                sq.key_import(file);
            }

            // Adopt its own encryption subkey.  This should be a noop.
            let cert = sq.key_adopt(
                keyrings.to_vec(),
                handle,
                [
                    alice_encryption().0.clone(),
                ].to_vec(),
                None,
                false,
                "-",
                true)
                .unwrap();

            assert!(
                check(&cert, 3, (alice_primary(), &[alice_encryption()])).is_ok());
        }

        Ok(())
    }

    #[test]
    fn adopt_own_primary() -> Result<()> {
        for (keyrings, key_imports, handle) in [
            (
                // Keyrings
                &[ bob() ][..],
                // Key store imports.
                &[][..],
                // Handle
                FileOrKeyHandle::from(bob()),
            ),
            (
                // Keyrings
                &[][..],
                // Key store imports.
                &[ bob() ],
                // Handle
                bob().into()
            ),
            (
                // Keyrings
                &[][..],
                // Key store imports.
                &[ bob() ],
                // Handle
                bob_primary().0.into()
            ),
        ] {
            let sq = Sq::new();

            for file in key_imports {
                sq.key_import(file);
            }

            // Adopt own primary key.
            let cert = sq.key_adopt(
                keyrings.to_vec(),
                handle,
                [
                    bob_primary().0.clone(),
                ].to_vec(),
                None,
                false,
                "-",
                true)
                .unwrap();

            assert!(
                check(&cert, 2, (bob_primary(), &[bob_primary()])).is_ok());
        }

        Ok(())
    }

    #[test]
    fn adopt_missing() -> Result<()> {
        for (keyrings, key_imports, handle) in [
            (
                // Keyrings
                &[ alice(), bob() ][..],
                // Key store imports.
                &[][..],
                // Handle
                FileOrKeyHandle::from(bob()),
            ),
            (
                // Keyrings
                &[][..],
                // Key store imports.
                &[][..],
                // Handle
                FileOrKeyHandle::from(bob()),
            ),
            (
                // Keyrings
                &[][..],
                // Key store imports.
                &[ bob() ],
                // Handle
                bob().into()
            ),
            (
                // Keyrings
                &[][..],
                // Key store imports.
                &[ bob() ],
                // Handle
                bob_primary().0.into()
            ),
        ] {
            let sq = Sq::new();

            for file in key_imports {
                sq.key_import(file);
            }

            // Adopt a key that is not present.
            let r = sq.key_adopt(
                keyrings.to_vec(),
                handle,
                [
                    "1234 5678 90AB CDEF  1234 5678 90AB CDEF"
                        .parse::<KeyHandle>()
                        .expect("valid fingerprint")
                ].to_vec(),
                None,
                false,
                "-",
                false);

            assert!(r.is_err());
        }

        Ok(())
    }

    #[test]
    fn adopt_from_multiple() -> Result<()> {
        for (keyrings, key_imports, handle) in [
            (
                // Keyrings
                &[ alice(), carol() ][..],
                // Key store imports.
                &[][..],
                // Handle
                FileOrKeyHandle::from(bob()),
            ),
            (
                // Keyrings
                &[][..],
                // Key store imports.
                &[ alice(), carol() ],
                // Handle
                bob().into()
            ),
            (
                // Keyrings
                &[][..],
                // Key store imports.
                &[ alice(), bob(), carol(), ],
                // Handle
                bob_primary().0.into()
            ),
        ] {
            let sq = Sq::new();

            for file in key_imports {
                sq.key_import(file);
            }

            // Adopt own primary key.
            let cert = sq.key_adopt(
                keyrings.to_vec(),
                handle,
                [
                    alice_signing().0.clone(),
                    alice_encryption().0.clone(),
                    carol_signing().0.clone(),
                    carol_encryption().0.clone(),
                ].to_vec(),
                None,
                false,
                "-",
                true)
                .unwrap();

            assert!(
                check(&cert, 5,
                      (bob_primary(),
                       &[
                           alice_signing(), alice_encryption(),
                           carol_signing(), carol_encryption()
                       ]))
                    .is_ok());
        }

        Ok(())
    }
}
