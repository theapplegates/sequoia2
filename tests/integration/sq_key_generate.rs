use std::time;

use sequoia_openpgp as openpgp;
use openpgp::Result;

use super::common;

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
    ], &[]);
    let vc = result.with_policy(common::STANDARD_POLICY, None)?;

    assert_eq!(vc.primary_key().creation_time(),
               time::UNIX_EPOCH + time::Duration::new(t, 0));
    assert!(vc.primary_key().key_expiration_time().is_none());

    Ok(())
}

#[test]
fn sq_key_generate_name_email() -> Result<()> {
    let sq = common::Sq::new();
    let (cert, _, _) = sq.key_generate(&[
        "--name", "Joan Clarke",
        "--name", "Joan Clarke Murray",
        "--email", "joan@hut8.bletchley.park",
    ], &[]);

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
    ], &[]);

    assert!(cert.is_tsk());

    let password = password.into();
    for key in cert.keys() {
        let secret = key.optional_secret().unwrap();
        assert!(secret.is_encrypted());
        assert!(secret.clone().decrypt(key.pk_algo(), &password).is_ok());
    }

    Ok(())
}
