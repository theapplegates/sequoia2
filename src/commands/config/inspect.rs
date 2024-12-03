//! Dispatches and implements `sq config inspect`.

use anyhow::Result;

use sequoia_policy_config::{
    ConfiguredStandardPolicy,
    DumpDefault,
};

use crate::{
    Sq,
    cli::config::inspect,
};

pub fn dispatch(sq: Sq, cmd: inspect::Command)
                -> Result<()>
{
    match cmd.subcommand {
        inspect::Subcommands::Policy(c) => policy(sq, c),
    }
}

/// Implements `sq config inspect policy`.
fn policy(sq: Sq, _: inspect::policy::Command) -> Result<()> {
    let p = ConfiguredStandardPolicy::from_policy(sq.policy.clone());

    p.dump(&mut std::io::stdout(), DumpDefault::Explicit)?;

    Ok(())
}
