//! Dispatches and implements `sq config inspect`.

use std::path::{Path, PathBuf};

use anyhow::Result;

use sequoia_policy_config::{
    ConfiguredStandardPolicy,
    DumpDefault,
};

use crate::{
    Sq,
    cli::config::inspect,
    config::ConfigFile,
};

pub fn dispatch(sq: Sq, cmd: inspect::Command)
                -> Result<()>
{
    match cmd.subcommand {
        inspect::Subcommands::Paths(c) => paths(sq, c),
        inspect::Subcommands::Policy(c) => policy(sq, c),
    }
}

/// Implements `sq config inspect paths`.
fn paths(sq: Sq, _: inspect::paths::Command) -> Result<()> {
    // Whether we have emitted anything.
    let mut dirty = false;

    // Formats a path.
    let mut p = |path: &Path, name: &str, description: &str| -> Result<()> {
        if dirty {
            wprintln!();
        }
        dirty = true;

        wprintln!(initial_indent = " - ", "{}", name);
        wprintln!(initial_indent = "   - ", "{}", path.display());

        if ! path.exists() {
            wprintln!(initial_indent = "   - ", "does not exist");
        }

        wprintln!(initial_indent = "   - ", "{}", description);

        Ok(())
    };

    if let Some(home) = &sq.home {
        p(home.location(), "home directory",
          "This holds the configuration file, and, unless overridden, \
           the certificate store and key store.",
        )?;

        p(&ConfigFile::file_name(&home), "config file",
          "sq's configuration file.",
        )?;
    }

    p(&PathBuf::from(ConfigFile::global_crypto_policy_file()),
      "global cryptographic policy",
      "This is the global cryptographic policy file.  If it exists, it \
       is read before reading in the policy in sq's configuration file, \
       which will refine the global one.",
    )?;

    if let Some(policy_path) = sq.config.policy_path() {
        p(policy_path,
          "referenced cryptographic policy",
          "This is the cryptographic policy file referenced in sq's \
           configuration file.  It is read after the global policy, \
           and before the policy embedded in sq's configuration file, \
           which will refine the global and referenced one.",
        )?;
    }

    if let Some(cert_store) = sq.cert_store_base() {
        p(&cert_store, "certificate store",
          "This holds all the certificates, indices for faster lookup, \
           and some additional certificates like the trust root.",
        )?;
    }

    if let Ok(Some(key_store)) = sq.key_store_path() {
        p(&key_store, "key store",
          "This holds all the keys, either directly for those in the \
           `softkeys` backend, or indirectly, using some configuration \
           and metadata.",
        )?;
    }

    Ok(())
}

/// Implements `sq config inspect policy`.
fn policy(sq: Sq, _: inspect::policy::Command) -> Result<()> {
    let p = ConfiguredStandardPolicy::from_policy(sq.policy.clone());

    p.dump(&mut std::io::stdout(), DumpDefault::Explicit)?;

    Ok(())
}
