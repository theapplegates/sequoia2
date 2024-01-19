use std::fs::{self, File};
use std::io;

use tempfile::TempDir;
use assert_cmd::Command;

use sequoia_openpgp as openpgp;
use openpgp::Fingerprint;
use openpgp::KeyHandle;
use openpgp::Result;
use openpgp::{Packet, PacketPile, Cert};
use openpgp::cert::CertBuilder;
use openpgp::crypto::KeyPair;
use openpgp::packet::key::SecretKeyMaterial;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::packet::signature::subpacket::NotationDataFlags;
use openpgp::types::{CompressionAlgorithm, SignatureType};
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Message, Signer, Compressor, LiteralWriter};
use openpgp::serialize::Serialize;

const P: &StandardPolicy = &StandardPolicy::new();

fn artifact(filename: &str) -> String {
    format!("tests/data/{}", filename)
}

#[test]
fn sq_sign() {
    let tmp_dir = TempDir::new().unwrap();
    let sig = tmp_dir.path().join("sig0");

    // Sign message.
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("sign")
        .args(["--signer-file", &artifact("keys/dennis-simon-anton-private.pgp")])
        .args(["--output", &sig.to_string_lossy()])
        .arg(&artifact("messages/a-cypherpunks-manifesto.txt"))
        .assert()
        .success();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig).unwrap().into_children().collect();
    assert_eq!(packets.len(), 3);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::Literal(_) = packets[1] {
        // Do nothing.
    } else {
        panic!("expected literal");
    }
    if let Packet::Signature(ref sig) = packets[2] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify signed message.
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("verify")
        .args(["--signer-file", &artifact("keys/dennis-simon-anton.pgp")])
        .arg(&*sig.to_string_lossy())
        .assert()
        .success();
}

#[test]
fn sq_sign_with_notations() {
    let tmp_dir = TempDir::new().unwrap();
    let sig = tmp_dir.path().join("sig0");

    // Sign message.
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("sign")
        .args(["--signer-file", &artifact("keys/dennis-simon-anton-private.pgp")])
        .args(["--output", &sig.to_string_lossy()])
        .args(["--notation", "foo", "bar"])
        .args(["--notation", "!foo", "xyzzy"])
        .args(["--notation", "hello@example.org", "1234567890"])
        .arg(&artifact("messages/a-cypherpunks-manifesto.txt"))
        .assert()
        .success();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig).unwrap().into_children().collect();
    assert_eq!(packets.len(), 3);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::Literal(_) = packets[1] {
        // Do nothing.
    } else {
        panic!("expected literal");
    }
    if let Packet::Signature(ref sig) = packets[2] {
        assert_eq!(sig.typ(), SignatureType::Binary);

        eprintln!("{:?}", sig);

        let hr = NotationDataFlags::empty().set_human_readable();
        let notations = &mut [
            (NotationData::new("foo", "bar", hr.clone()), false),
            (NotationData::new("foo", "xyzzy", hr.clone()), false),
            (NotationData::new("hello@example.org", "1234567890", hr), false)
        ];

        for n in sig.notation_data() {
            if n.name() == "salt@notations.sequoia-pgp.org" {
                continue;
            }

            for (m, found) in notations.iter_mut() {
                if n == m {
                    assert!(!*found);
                    *found = true;
                }
            }
        }
        for (n, found) in notations.iter() {
            assert!(found, "Missing: {:?}", n);
        }
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify signed message.
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .args(["--known-notation", "foo"])
        .arg("verify")
        .args(["--signer-file", &artifact("keys/dennis-simon-anton.pgp")])
        .arg(&*sig.to_string_lossy())
        .assert()
        .success();
}

#[test]
fn sq_sign_append() {
    let tmp_dir = TempDir::new().unwrap();
    let sig0 = tmp_dir.path().join("sig0");

    // Sign message.
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("sign")
        .args(["--signer-file", &artifact("keys/dennis-simon-anton-private.pgp")])
        .args(["--output", &sig0.to_string_lossy()])
        .arg(&artifact("messages/a-cypherpunks-manifesto.txt"))
        .assert()
        .success();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig0).unwrap().into_children().collect();
    assert_eq!(packets.len(), 3);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::Literal(_) = packets[1] {
        // Do nothing.
    } else {
        panic!("expected literal");
    }
    if let Packet::Signature(ref sig) = packets[2] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig0).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify signed message.
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("verify")
        .args(["--signer-file", &artifact("keys/dennis-simon-anton.pgp")])
        .arg(&*sig0.to_string_lossy())
        .assert()
        .success();

    // Now add a second signature with --append.
    let sig1 = tmp_dir.path().join("sig1");
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("sign")
        .arg("--append")
        .args(["--signer-file", &artifact("keys/erika-corinna-daniela-simone-antonia-nistp256-private.pgp")])
        .arg("--output")
        .arg(&*sig1.to_string_lossy())
        .arg(&*sig0.to_string_lossy())
        .assert()
        .success();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig1).unwrap().into_children().collect();
    assert_eq!(packets.len(), 5);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(! ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::OnePassSig(ref ops) = packets[1] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::Literal(_) = packets[2] {
        // Do nothing.
    } else {
        panic!("expected literal");
    }
    if let Packet::Signature(ref sig) = packets[3] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 0);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[4] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 0);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig1).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify both signatures of the signed message.
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("verify")
        .args(["--signer-file", &artifact("keys/dennis-simon-anton.pgp")])
        .arg(&*sig1.to_string_lossy())
        .assert()
        .success();
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("verify")
        .args(["--signer-file", &artifact("keys/erika-corinna-daniela-simone-antonia-nistp256.pgp")])
        .arg(&*sig1.to_string_lossy())
        .assert()
        .success();
}

#[test]
#[allow(unreachable_code)]
fn sq_sign_append_on_compress_then_sign() {
    let tmp_dir = TempDir::new().unwrap();
    let sig0 = tmp_dir.path().join("sig0");

    // This is quite an odd scheme, so we need to create such a
    // message by foot.
    let tsk = Cert::from_file(&artifact("keys/dennis-simon-anton-private.pgp"))
        .unwrap();
    let key = tsk.keys().with_policy(P, None).for_signing().next().unwrap().key();
    let sec = match key.optional_secret() {
        Some(SecretKeyMaterial::Unencrypted(ref u)) => u.clone(),
        _ => unreachable!(),
    };
    let keypair = KeyPair::new(key.clone(), sec).unwrap();
    let signer = Signer::new(Message::new(File::create(&sig0).unwrap()),
                             keypair).build().unwrap();
    let compressor = Compressor::new(signer)
        .algo(CompressionAlgorithm::Uncompressed)
        .build().unwrap();
    let mut literal = LiteralWriter::new(compressor).build()
        .unwrap();
    io::copy(
        &mut File::open(&artifact("messages/a-cypherpunks-manifesto.txt")).unwrap(),
        &mut literal)
        .unwrap();
    literal.finalize()
        .unwrap();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig0).unwrap().into_children().collect();
    assert_eq!(packets.len(), 3);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::CompressedData(_) = packets[1] {
        // Do nothing.
    } else {
        panic!("expected compressed data");
    }
    if let Packet::Signature(ref sig) = packets[2] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }

    // Verify signed message.
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("verify")
        .args(["--signer-file", &artifact("keys/dennis-simon-anton.pgp")])
        .arg(&*sig0.to_string_lossy())
        .assert()
        .success();

    // Now add a second signature with --append.
    let sig1 = tmp_dir.path().join("sig1");
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("sign")
        .arg("--append")
        .args(["--signer-file", &artifact("keys/erika-corinna-daniela-simone-antonia-nistp256-private.pgp")])
        .arg("--output")
        .arg(&*sig1.to_string_lossy())
        .arg(&*sig0.to_string_lossy())
        .assert()
        .failure(); // XXX: Currently, this is not implemented.

    // XXX: Currently, this is not implemented in sq.
    return;

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig1).unwrap().into_children().collect();
    assert_eq!(packets.len(), 5);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(! ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::OnePassSig(ref ops) = packets[1] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::CompressedData(_) = packets[2] {
        // Do nothing.
    } else {
        panic!("expected compressed data");
    }
    if let Packet::Signature(ref sig) = packets[3] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 0);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[4] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 0);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig1).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify both signatures of the signed message.
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("verify")
        .args(["--signer-file", &artifact("keys/dennis-simon-anton.pgp")])
        .arg(&*sig0.to_string_lossy())
        .assert()
        .success();

    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("verify")
        .args(["--signer-file", &artifact("keys/erika-corinna-daniela-simone-antonia-nistp256.pgp")])
        .arg(&*sig0.to_string_lossy())
        .assert()
        .success();
}

#[test]
fn sq_sign_detached() {
    let tmp_dir = TempDir::new().unwrap();
    let sig = tmp_dir.path().join("sig0");

    // Sign detached.
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("sign")
        .arg("--detached")
        .args(["--signer-file", &artifact("keys/dennis-simon-anton-private.pgp")])
        .args(["--output", &sig.to_string_lossy()])
        .arg(&artifact("messages/a-cypherpunks-manifesto.txt"))
        .assert()
        .success();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig).unwrap().into_children().collect();
    assert_eq!(packets.len(), 1);
    if let Packet::Signature(ref sig) = packets[0] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP SIGNATURE-----\n\n"));

    // Verify detached.
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("verify")
        .args(["--signer-file", &artifact("keys/dennis-simon-anton.pgp")])
        .args(["--detached", &sig.to_string_lossy()])
        .arg(&artifact("messages/a-cypherpunks-manifesto.txt"))
        .assert()
        .success();
}

#[test]
fn sq_sign_detached_append() {
    let tmp_dir = TempDir::new().unwrap();
    let sig = tmp_dir.path().join("sig0");

    // Sign detached.
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("sign")
        .arg("--detached")
        .args(["--signer-file", &artifact("keys/dennis-simon-anton-private.pgp")])
        .args(["--output", &sig.to_string_lossy()])
        .arg(&artifact("messages/a-cypherpunks-manifesto.txt"))
        .assert()
        .success();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig).unwrap().into_children().collect();
    assert_eq!(packets.len(), 1);
    if let Packet::Signature(ref sig) = packets[0] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP SIGNATURE-----\n\n"));

    // Verify detached.
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("verify")
        .args(["--signer-file", &artifact("keys/dennis-simon-anton.pgp")])
        .args(["--detached", &sig.to_string_lossy()])
        .arg(&artifact("messages/a-cypherpunks-manifesto.txt"))
        .assert()
        .success();

    // Check that we don't blindly overwrite signatures.
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("sign")
        .arg("--detached")
        .args(["--signer-file", &artifact("keys/erika-corinna-daniela-simone-antonia-nistp256-private.pgp")])
        .args(["--output", &sig.to_string_lossy()])
        .arg(&artifact("messages/a-cypherpunks-manifesto.txt"))
        .assert()
        .failure();

    // Now add a second signature with --append.
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("sign")
        .arg("--detached")
        .arg("--append")
        .args(["--signer-file", &artifact("keys/erika-corinna-daniela-simone-antonia-nistp256-private.pgp")])
        .args(["--output", &sig.to_string_lossy()])
        .arg(&artifact("messages/a-cypherpunks-manifesto.txt"))
        .assert()
        .success();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig).unwrap().into_children().collect();
    assert_eq!(packets.len(), 2);
    if let Packet::Signature(ref sig) = packets[0] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[1] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP SIGNATURE-----\n\n"));

    // Verify both detached signatures.
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("verify")
        .args(["--signer-file", &artifact("keys/dennis-simon-anton.pgp")])
        .args(["--detached", &sig.to_string_lossy()])
        .arg(&artifact("messages/a-cypherpunks-manifesto.txt"))
        .assert()
        .success();

    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("verify")
        .args(["--signer-file", &artifact("keys/erika-corinna-daniela-simone-antonia-nistp256.pgp")])
        .args(["--detached", &sig.to_string_lossy()])
        .arg(&artifact("messages/a-cypherpunks-manifesto.txt"))
        .assert()
        .success();

    // Finally, check that we don't truncate the file if something
    // goes wrong.
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("sign")
        .arg("--detached")
        .arg("--append")
        .arg("--signer-file") // Not a private key => signing will fail.
        .arg(&artifact("keys/erika-corinna-daniela-simone-antonia-nistp521.pgp"))
        .args(["--output", &sig.to_string_lossy()])
        .arg(&artifact("messages/a-cypherpunks-manifesto.txt"))
        .assert()
        .failure();

    // Check that the content is still sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig).unwrap().into_children().collect();
    assert_eq!(packets.len(), 2);
    if let Packet::Signature(ref sig) = packets[0] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[1] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }
}

// Notarizations ahead.

#[ignore]
#[test]
fn sq_sign_append_a_notarization() {
    let tmp_dir = TempDir::new().unwrap();
    let sig0 = tmp_dir.path().join("sig0");

    // Now add a third signature with --append to a notarized message.
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("sign")
        .arg("--append")
        .args(["--signer-file", &artifact("keys/erika-corinna-daniela-simone-antonia-nistp256-private.pgp")])
        .args(["--output", &sig0.to_string_lossy()])
        .arg(&artifact("messages/signed-1-notarized-by-ed25519.pgp"))
        .assert()
        .success();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig0).unwrap().into_children().collect();
    assert_eq!(packets.len(), 7);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(! ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::OnePassSig(ref ops) = packets[1] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::OnePassSig(ref ops) = packets[2] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::Literal(_) = packets[3] {
        // Do nothing.
    } else {
        panic!("expected literal");
    }
    if let Packet::Signature(ref sig) = packets[4] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 0);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[5] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 1);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[6] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 1);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig0).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify both notarizations and the signature.
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("verify")
        .args(["--signer-file", &artifact("keys/neal.pgp")])
        .arg(&*sig0.to_string_lossy())
        .assert()
        .success();
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("verify")
        .args(["--signer-file", &artifact("keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp")])
        .arg(&*sig0.to_string_lossy())
        .assert()
        .success();
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("verify")
        .args(["--signer-file", &artifact("keys/erika-corinna-daniela-simone-antonia-nistp256.pgp")])
        .arg(&*sig0.to_string_lossy())
        .assert()
        .success();
}

#[ignore]
#[test]
fn sq_sign_notarize() {
    let tmp_dir = TempDir::new().unwrap();
    let sig0 = tmp_dir.path().join("sig0");

    // Now add a third signature with --append to a notarized message.
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("sign")
        .arg("--notarize")
        .args(["--signer-file", &artifact("keys/erika-corinna-daniela-simone-antonia-nistp256-private.pgp")])
        .args(["--output", &sig0.to_string_lossy()])
        .arg(&artifact("messages/signed-1.gpg"))
        .assert()
        .success();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig0).unwrap().into_children().collect();
    assert_eq!(packets.len(), 5);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::OnePassSig(ref ops) = packets[1] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::Literal(_) = packets[2] {
        // Do nothing.
    } else {
        panic!("expected literal");
    }
    if let Packet::Signature(ref sig) = packets[3] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 0);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[4] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 1);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig0).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify both notarizations and the signature.
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("verify")
        .args(["--signer-file", &artifact("keys/neal.pgp")])
        .arg(&*sig0.to_string_lossy())
        .assert()
        .success();
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("verify")
        .args(["--signer-file", &artifact("keys/erika-corinna-daniela-simone-antonia-nistp256.pgp")])
        .arg(&*sig0.to_string_lossy())
        .assert()
        .success();
}

#[ignore]
#[test]
fn sq_sign_notarize_a_notarization() {
    let tmp_dir = TempDir::new().unwrap();
    let sig0 = tmp_dir.path().join("sig0");

    // Now add a third signature with --append to a notarized message.
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("sign")
        .arg("--notarize")
        .args(["--signer-file", &artifact("keys/erika-corinna-daniela-simone-antonia-nistp256-private.pgp")])
        .args(["--output", &sig0.to_string_lossy()])
        .arg(&artifact("messages/signed-1-notarized-by-ed25519.pgp"))
        .assert()
        .success();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig0).unwrap().into_children().collect();
    assert_eq!(packets.len(), 7);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::OnePassSig(ref ops) = packets[1] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::OnePassSig(ref ops) = packets[2] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::Literal(_) = packets[3] {
        // Do nothing.
    } else {
        panic!("expected literal");
    }
    if let Packet::Signature(ref sig) = packets[4] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 0);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[5] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 1);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[6] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 2);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig0).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify both notarizations and the signature.
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("verify")
        .args(["--signer-file", &artifact("keys/neal.pgp")])
        .arg(&*sig0.to_string_lossy())
        .assert()
        .success();
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("verify")
        .args(["--signer-file", &artifact("keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp")])
        .arg(&*sig0.to_string_lossy())
        .assert()
        .success();
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("verify")
        .args(["--signer-file", &artifact("keys/erika-corinna-daniela-simone-antonia-nistp256.pgp")])
        .arg(&*sig0.to_string_lossy())
        .assert()
        .success();
}

#[test]
fn sq_multiple_signers() -> Result<()> {
    let tmp = TempDir::new()?;

    let gen = |userid: &str| {
        CertBuilder::new()
            .add_signing_subkey()
            .add_userid(userid)
            .generate().map(|(key, _rev)| key)
    };

    let alice = gen("<alice@some.org>")?;
    let alice_pgp = tmp.path().join("alice.pgp");
    let mut file = File::create(&alice_pgp)?;
    alice.as_tsk().serialize(&mut file)?;

    let bob = gen("<bob@some.org>")?;
    let bob_pgp = tmp.path().join("bob.pgp");
    let mut file = File::create(&bob_pgp)?;
    bob.as_tsk().serialize(&mut file)?;

    // Sign message.
    let assertion = Command::cargo_bin("sq")?
        .args([
            "--no-cert-store",
            "sign",
            "--signer-file", alice_pgp.to_str().unwrap(),
            "--signer-file", &bob_pgp.to_str().unwrap(),
            "--detached",
        ])
        .write_stdin(&b"foo"[..])
        .assert().try_success()?;

    let stdout = String::from_utf8_lossy(&assertion.get_output().stdout);

    let pp = PacketPile::from_bytes(&*stdout)?;

    assert_eq!(pp.children().count(), 2,
               "expected two packets");

    let mut sigs: Vec<Fingerprint> = pp.children().map(|p| {
        if let &Packet::Signature(ref sig) = p {
            if let Some(KeyHandle::Fingerprint(fpr))
                = sig.get_issuers().into_iter().next()
            {
                fpr
            } else {
                panic!("No issuer fingerprint subpacket!");
            }
        } else {
            panic!("Expected a signature, got: {:?}", pp);
        }
    }).collect();
    sigs.sort();

    let alice_sig_fpr = alice.with_policy(P, None)?
        .keys().for_signing().next().unwrap().fingerprint();
    let bob_sig_fpr = bob.with_policy(P, None)?
        .keys().for_signing().next().unwrap().fingerprint();

    let mut expected = vec![
        alice_sig_fpr,
        bob_sig_fpr,
    ];
    expected.sort();

    assert_eq!(sigs, expected);

    Ok(())
}

#[test]
fn sq_sign_using_cert_store() -> Result<()> {
    let dir = TempDir::new()?;

    let certd = dir.path().join("cert.d").display().to_string();
    std::fs::create_dir(&certd).expect("mkdir works");

    let alice_pgp = dir.path().join("alice.pgp").display().to_string();
    let msg_pgp = dir.path().join("msg.pgp").display().to_string();

    // Generate a key.
    let mut cmd = Command::cargo_bin("sq")?;
    cmd.args(["--cert-store", &certd,
              "key", "generate",
              "--expiry", "never",
              "--userid", "<alice@example.org>",
              "--output", &alice_pgp]);
    cmd.assert().success();

    let alice = Cert::from_file(&alice_pgp)?;

    // Import it.
    let mut cmd = Command::cargo_bin("sq")?;
    cmd.args(["--cert-store", &certd,
              "cert", "import", &alice_pgp]);
    cmd.assert().success();


    // Sign a message.
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("sign")
        .args(["--signer-file", &alice_pgp])
        .args(["--output", &msg_pgp])
        .arg(&artifact("messages/a-cypherpunks-manifesto.txt"))
        .assert()
        .success();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&msg_pgp).unwrap().into_children().collect();
    assert_eq!(packets.len(), 3);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::Literal(_) = packets[1] {
        // Do nothing.
    } else {
        panic!("expected literal");
    }
    if let Packet::Signature(ref sig) = packets[2] {
        assert_eq!(sig.typ(), SignatureType::Binary);

        let alice_signer = alice.with_policy(P, None)?
            .keys().for_signing().next().expect("have one");
        assert_eq!(sig.get_issuers().into_iter().next(),
                   Some(KeyHandle::from(alice_signer.fingerprint())));
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&msg_pgp).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify the signed message.  First, we specify the certificate
    // explicitly.
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("verify")
        .args(["--signer-file", &alice_pgp])
        .arg(&msg_pgp)
        .assert()
        .success();

    // Verify the signed message.  Now, we don't specify the
    // certificate or use a certificate store.
    let mut cmd = Command::cargo_bin("sq").unwrap();
    cmd.arg("--no-cert-store")
        .arg("verify")
        .arg(&msg_pgp);
    let output = cmd.output().expect("success");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(! output.status.success(),
            "stdout:\n{}\nstderr: {}", stdout, stderr);

    assert!(stderr.contains("No key to check checksum from "),
            "stdout:\n{}\nstderr: {}", stdout, stderr);
    assert!(stderr.contains("Error: Verification failed"),
            "stdout:\n{}\nstderr: {}", stdout, stderr);

    // Now we use the certificate store.
    let mut cmd = Command::cargo_bin("sq").unwrap();
    cmd.arg("--cert-store").arg(&certd)
        .arg("verify")
        .arg(&msg_pgp);
    let output = cmd.output().expect("success");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(! output.status.success(),
            "stdout:\n{}\nstderr: {}", stdout, stderr);

    // The default trust model says that certificates from the
    // certificate store are not authenticated.
    assert!(stderr.contains("Unauthenticated checksum from "),
            "stdout:\n{}\nstderr: {}", stdout, stderr);
    assert!(stderr.contains("Error: Verification failed"),
            "stdout:\n{}\nstderr: {}", stdout, stderr);

    // Now we use the certificate store *and* specify the certificate.
    let mut cmd = Command::cargo_bin("sq").unwrap();
    cmd.arg("--cert-store").arg(&certd)
        .arg("verify")
        .arg("--signer-cert").arg(&alice.fingerprint().to_string())
        .arg(&msg_pgp);
    let output = cmd.output().expect("success");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(),
            "stdout:\n{}\nstderr: {}", stdout, stderr);

    // The default trust model says that certificates from the
    // certificate store are not authenticated.
    assert!(stderr.contains("Good signature from "),
            "stdout:\n{}\nstderr: {}", stdout, stderr);
    assert!(stderr.contains("1 good signature."),
            "stdout:\n{}\nstderr: {}", stdout, stderr);

    Ok(())
}

// Verify signatures using the web of trust to authenticate the
// signers.
#[test]
fn sq_verify_wot() -> Result<()> {
    let dir = TempDir::new()?;

    let certd = dir.path().join("cert.d").display().to_string();
    std::fs::create_dir(&certd).expect("mkdir works");

    let alice_pgp = dir.path().join("alice.pgp").display().to_string();
    let bob_pgp = dir.path().join("bob.pgp").display().to_string();
    let carol_pgp = dir.path().join("carol.pgp").display().to_string();
    let dave_pgp = dir.path().join("dave.pgp").display().to_string();
    let msg_pgp = dir.path().join("msg.pgp").display().to_string();

    // Imports a certificate.
    let sq_import = |cert_store: &str, files: &[&str], stdin: Option<&str>| {
        let mut cmd = Command::cargo_bin("sq").expect("have sq");
        cmd.args(["--cert-store", cert_store, "cert", "import"]);
        for file in files {
            cmd.arg(file);
        }
        if let Some(stdin) = stdin {
            cmd.write_stdin(stdin);
        }
        cmd.assert().success();
    };

    // Generates a key.
    //
    // If cert_store is not `None`, then the resulting certificate is also
    // imported.
    let sq_gen_key = |cert_store: Option<&str>, userids: &[&str], file: &str|
        -> Cert
    {
        let mut cmd = Command::cargo_bin("sq").expect("have sq");
        cmd.args(["--no-cert-store",
                  "key", "generate",
                  "--expiry", "never",
                  "--output", file]);
        for userid in userids.iter() {
            cmd.args(["--userid", userid]);
        }
        cmd.assert().success();

        if let Some(cert_store) = cert_store {
            sq_import(cert_store, &[ file ], None);
        }

        Cert::from_file(file).expect("valid certificate")
    };

    // Verifies a signed message.
    let sq_verify = |cert_store: Option<&str>,
                     trust_roots: &[&str],
                     signer_files: &[&str],
                     msg_pgp: &str|
    {
        let mut cmd = Command::cargo_bin("sq").expect("have sq");
        if let Some(cert_store) = cert_store {
            cmd.args(&["--cert-store", cert_store]);
        } else {
            cmd.arg("--no-cert-store");
        }
        for trust_root in trust_roots {
            cmd.args(&["--trust-root", trust_root]);
        }
        cmd.arg("verify");
        for signer_file in signer_files {
            cmd.args(&["--signer-file", signer_file]);
        }
        cmd.arg(msg_pgp);
        let output = cmd.output().expect("can run");

        (output.status.clone(),
         String::from_utf8_lossy(&output.stdout).to_string(),
         String::from_utf8_lossy(&output.stderr).to_string())
    };

    // Certifies a binding.
    //
    // The certification is imported into the cert store.
    let sq_certify = |cert_store: &str,
                      key: &str, cert: &str, userid: &str,
                      trust_amount: Option<usize>|
    {
        let mut cmd = Command::cargo_bin("sq").expect("have sq");
        cmd.args(&["--cert-store", cert_store]);
        cmd.args(&["pki", "certify", key, cert, userid]);
        if let Some(trust_amount) = trust_amount {
            cmd.args(&["--amount", &trust_amount.to_string()[..]]);
        }
        let output = cmd.output().expect("can run");

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        assert!(output.status.success(),
                "sq pki certify\nstdout:\n{}\nstderr:\n{}",
                stdout, stderr);

        // Import the certification.
        sq_import(cert_store, &[], Some(&stdout));
        let output = cmd.output().expect("can run");

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        assert!(output.status.success(),
                "sq pki certify | sq import\nstdout:\n{}\nstderr:\n{}",
                stdout, stderr);
    };

    let alice = sq_gen_key(Some(&certd), &[ "<alice@example.org>" ], &alice_pgp);
    let bob = sq_gen_key(Some(&certd), &[ "<bob@example.org>" ], &bob_pgp);
    let carol = sq_gen_key(Some(&certd), &[ "<carol@example.org>" ], &carol_pgp);
    let dave = sq_gen_key(Some(&certd), &[ "<dave@example.org>" ], &dave_pgp);

    let alice_fpr = alice.fingerprint().to_string();
    let bob_fpr = bob.fingerprint().to_string();
    let carol_fpr = carol.fingerprint().to_string();
    let dave_fpr = dave.fingerprint().to_string();

    // Sign a message.
    Command::cargo_bin("sq")
        .unwrap()
        .arg("--no-cert-store")
        .arg("sign")
        .args(["--signer-file", &bob_pgp])
        .args(["--signer-file", &carol_pgp])
        .args(["--signer-file", &dave_pgp])
        .args(["--output", &msg_pgp])
        .arg(&artifact("messages/a-cypherpunks-manifesto.txt"))
        .assert()
        .success();

    // When designating the signers using a file, the signers are
    // fully trusted.
    {
        let output = sq_verify(Some(&certd), &[], &[&bob_pgp], &msg_pgp);
        assert!(output.0.success());
        let output = sq_verify(Some(&certd), &[], &[&carol_pgp], &msg_pgp);
        assert!(output.0.success());
        let output = sq_verify(Some(&certd), &[], &[&dave_pgp], &msg_pgp);
        assert!(output.0.success());

        // Alice did not sign it so this should fail.
        let output = sq_verify(Some(&certd), &[], &[&alice_pgp], &msg_pgp);
        assert!(! output.0.success());

        // But, one good signature is enough.
        let output = sq_verify(Some(&certd), &[], &[&alice_pgp, &bob_pgp], &msg_pgp);
        assert!(output.0.success());
    }

    // When the signers' certificates are found in the cert store, and
    // they can't be authenticated with the web of trust, the
    // verification will fail.
    {
        let output = sq_verify(Some(&certd), &[], &[], &msg_pgp);
        assert!(! output.0.success(),
                "stdout:\n{}\nstderr:\n{}", output.1, output.2);
        assert!(output.2.contains("Unauthenticated checksum from "),
                "stdout:\n{}\nstderr:\n{}",
                output.1, output.2);

        // Specifying a trust root won't help if there is no path to a
        // signer.
        let output = sq_verify(Some(&certd), &[&alice_fpr], &[], &msg_pgp);
        assert!(! output.0.success(),
                "stdout:\n{}\nstderr:\n{}", output.1, output.2);
        assert!(output.2.contains("Unauthenticated checksum from "),
                "stdout:\n{}\nstderr:\n{}",
                output.1, output.2);
    }

    // A trust root can certify itself
    {
        let output = sq_verify(Some(&certd), &[&bob_fpr], &[], &msg_pgp);
        assert!(output.0.success(),
                "stdout:\n{}\nstderr:\n{}", output.1, output.2);
        assert!(output.2.contains("Good signature from "),
                "stdout:\n{}\nstderr:\n{}",
                output.1, output.2);

        let output = sq_verify(
            Some(&certd), &[&alice_fpr, &bob_fpr], &[], &msg_pgp);
        assert!(output.0.success(),
                "stdout:\n{}\nstderr:\n{}", output.1, output.2);
        assert!(output.2.contains("Good signature from "),
                "stdout:\n{}\nstderr:\n{}",
                output.1, output.2);
    }

    // Have Alice partially certify Bob, and make Alice the trust
    // root.  The signature should still be bad.
    {
        sq_certify(&certd, &alice_pgp,
                   &bob.fingerprint().to_string(), "<bob@example.org>",
                   Some(90));
        let output = sq_verify(Some(&certd), &[&alice_fpr], &[], &msg_pgp);
        assert!(! output.0.success(),
                "stdout:\n{}\nstderr:\n{}", output.1, output.2);
        assert!(output.2.contains("Unauthenticated checksum from "),
                "stdout:\n{}\nstderr:\n{}",
                output.1, output.2);
    }

    // Have Alice also partially certify Carol, and make Alice the
    // trust root.  Bob and Carol combined don't (currently) make the
    // signature good.
    {
        sq_certify(&certd, &alice_pgp,
                   &carol_fpr, "<carol@example.org>",
                   Some(60));
        let output = sq_verify(Some(&certd), &[&alice_fpr], &[], &msg_pgp);
        assert!(! output.0.success(),
                "stdout:\n{}\nstderr:\n{}", output.1, output.2);
        assert!(output.2.contains("Unauthenticated checksum from "),
                "stdout:\n{}\nstderr:\n{}",
                output.1, output.2);
        assert!(output.2.contains("3 unauthenticated checksums"),
                "stdout:\n{}\nstderr:\n{}",
                output.1, output.2);
    }

    // Have Alice fully certify Dave, and make Alice the trust root.
    // Now the signature will be considered verified.
    {
        sq_certify(&certd, &alice_pgp,
                   &dave_fpr, "<dave@example.org>",
                   None);
        let output = sq_verify(Some(&certd), &[&alice_fpr], &[], &msg_pgp);
        assert!(output.0.success(),
                "stdout:\n{}\nstderr:\n{}", output.1, output.2);
        assert!(output.2.contains("Good signature from "),
                "stdout:\n{}\nstderr:\n{}",
                output.1, output.2);
        assert!(output.2.contains("1 good signature, 2 unauthenticated checksums"),
                "stdout:\n{}\nstderr:\n{}",
                output.1, output.2);
    }

    Ok(())
}
