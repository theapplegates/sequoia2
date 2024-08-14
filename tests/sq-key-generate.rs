use std::time;

use sequoia_openpgp as openpgp;
use openpgp::Result;

mod common;

mod integration {
    use super::*;

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
}
