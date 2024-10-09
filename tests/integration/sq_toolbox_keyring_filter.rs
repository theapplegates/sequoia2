use std::{
    fs::File,
    io::{Cursor, Read},
};

use sequoia_openpgp::{
    Result,
    cert::{Cert, CertParser},
    parse::Parse,
};

use super::common::{Sq, artifact};

/// Creates a keyring.
fn build_keyring(sq: &Sq) {
    let mut cmd = sq.command();
    cmd.arg("toolbox")
        .arg("keyring")
        .arg("merge")
        .arg("--output=keys.pgp")
        .arg(artifact("examples").join("alice-secret.pgp"))
        .arg(artifact("examples").join("bob.pgp"))
        .arg(artifact("keys").join("neal.pgp"));
    sq.run(cmd, true);
}

/// Reads all certs in.
fn read_certs(source: &mut (dyn Read + Sync + Send)) -> Vec<Cert> {
    CertParser::from_reader(source).unwrap()
        .collect::<Result<Vec<_>>>().unwrap()
}

/// Filters the keyring, then reads all certs in.
fn filter(sq: &Sq, args: &[&str]) -> Vec<Cert> {
    let mut cmd = sq.command();
    cmd.arg("toolbox")
        .arg("keyring")
        .arg("filter")
        .arg("--output=-")
        .args(args)
        .arg("keys.pgp");
    let output = sq.run(cmd, true);

    read_certs(&mut Cursor::new(output.stdout))
}

#[test]
fn to_cert() -> Result<()> {
    let sq = Sq::new();
    build_keyring(&sq);

    let keys = read_certs(&mut File::open(sq.working_dir().join("keys.pgp"))?);
    assert!(keys.iter().any(|cert| cert.is_tsk()));

    let certs = filter(&sq, &["--to-cert"]);
    assert!(! certs.iter().any(|cert| cert.is_tsk()));

    Ok(())
}

#[test]
fn userid() -> Result<()> {
    let sq = Sq::new();
    build_keyring(&sq);

    let certs = filter(&sq, &["--userid", "Alice <alice@example.org>"]);
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].fingerprint(),
               "EB28F26E2739A4870ECC47726F0073F60FD0CBF0".parse()?);

    Ok(())
}

#[test]
fn userid_prune() -> Result<()> {
    let sq = Sq::new();
    build_keyring(&sq);

    let neals_uid = "Neal H. Walfield <neal@sequoia-pgp.org>";
    let certs = filter(&sq, &["--prune-certs", "--userid", neals_uid]);
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].fingerprint(),
               "8F17777118A33DDA9BA48E62AACB3243630052D9".parse()?);
    assert_eq!(certs[0].userids().count(), 1);
    assert_eq!(certs[0].userids().next().unwrap().value(),
               neals_uid.as_bytes());

    Ok(())
}

#[test]
fn domain() -> Result<()> {
    let sq = Sq::new();
    build_keyring(&sq);

    let certs = filter(&sq, &["--domain", "example.org"]);
    assert_eq!(certs.len(), 2);
    let mut fiprs = certs.iter().map(Cert::fingerprint).collect::<Vec<_>>();
    fiprs.sort();
    assert_eq!(&fiprs[..],
               &[
                   "511257EBBF077B7AEDAE5D093F68CB84CE537C9A".parse()?,
                   "EB28F26E2739A4870ECC47726F0073F60FD0CBF0".parse()?,
               ]);

    Ok(())
}

#[test]
fn domain_prune() -> Result<()> {
    let sq = Sq::new();
    build_keyring(&sq);

    let certs = filter(&sq, &["--prune-certs", "--domain", "sequoia-pgp.org"]);
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].fingerprint(),
               "8F17777118A33DDA9BA48E62AACB3243630052D9".parse()?);
    assert_eq!(certs[0].userids().count(), 1);
    assert_eq!(certs[0].userids().next().unwrap().value(),
               b"Neal H. Walfield <neal@sequoia-pgp.org>");

    Ok(())
}
