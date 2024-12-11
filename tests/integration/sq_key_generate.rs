use std::time;

use sequoia_openpgp as openpgp;
use openpgp::Result;

use super::common;
use super::common::UserIDArg;
use super::common::NO_USERIDS;

#[test]
fn sq_key_generate_no_userid() -> Result<()> {
    let sq = common::Sq::new();

    // Stateless key generation.
    let (cert, _, _) = sq.key_generate::<&str>(&[], &[]);
    assert_eq!(cert.userids().count(), 0);

    // Stateful key generation.
    let mut cmd = sq.command();
    cmd.args(["key", "generate", "--own-key", "--no-userids",
              "--without-password"]);
    sq.run(cmd, true);

    Ok(())
}

#[test]
fn sq_key_generate_creation_time() -> Result<()>
{
    let sq = common::Sq::new();

    // $ date +'%Y%m%dT%H%M%S%z'; date +'%s'
    let iso8601 = "20220120T163236+0100";
    let t = 1642692756;

    let (result, _, _) = sq.key_generate(&[
        "--time", iso8601,
        "--expiration", "never",
    ], NO_USERIDS);
    let vc = result.with_policy(common::STANDARD_POLICY, None)?;

    assert_eq!(vc.primary_key().creation_time(),
               time::UNIX_EPOCH + time::Duration::new(t, 0));
    assert!(vc.primary_key().key_expiration_time().is_none());

    Ok(())
}

#[test]
fn sq_key_generate_name_email() -> Result<()> {
    let sq = common::Sq::new();
    let (cert, _, _) = sq.key_generate(
        &[],
        &[
            UserIDArg::Name("Joan Clarke"),
            UserIDArg::Name("Joan Clarke Murray"),
            UserIDArg::Email("joan@hut8.bletchley.park"),
        ]);

    assert_eq!(cert.userids().count(), 3);
    assert!(cert.userids().any(|u| u.value() == b"Joan Clarke"));
    assert!(cert.userids().any(|u| u.value() == b"Joan Clarke Murray"));
    assert!(
        cert.userids().any(|u| u.value() == b"<joan@hut8.bletchley.park>"));

    Ok(())
}

#[test]
fn sq_key_generate_with_password() -> Result<()> {
    let sq = common::Sq::new();

    let password = "hunter2";
    let path = sq.base().join("password");
    std::fs::write(&path, password)?;

    let (cert, _, _) = sq.key_generate(&[
        "--new-password-file", &path.display().to_string(),
    ], NO_USERIDS);

    assert!(cert.is_tsk());

    let password = password.into();
    for key in cert.keys() {
        let secret = key.optional_secret().unwrap();
        assert!(secret.is_encrypted());
        assert!(secret.clone().decrypt(key.pk_algo(), &password).is_ok());
    }

    Ok(())
}
