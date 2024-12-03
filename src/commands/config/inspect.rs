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
    cli::network,
    config::ConfigFile,
};

pub fn dispatch(sq: Sq, cmd: inspect::Command)
                -> Result<()>
{
    match cmd.subcommand {
        inspect::Subcommands::Network(c) => network(sq, c),
        inspect::Subcommands::Paths(c) => paths(sq, c),
        inspect::Subcommands::Policy(c) => policy(sq, c),
    }
}

/// Implements `sq config inspect network`.
fn network(sq: Sq, _: inspect::network::Command) -> Result<()> {
    fn may_use(what: &str, enabled: bool) -> String {
        format!("will {}use {}",
                if enabled { "" } else { "not " },
                what)
    }

    // First, sq network search, the most general interface.
    wprintln!(initial_indent = " - ", "sq network search");
    wprintln!(initial_indent = "   - ", "{}",
              may_use("WKD", sq.config.network_search_wkd()));
    wprintln!(initial_indent = "     - ",
              "relevant setting: network.search.use-wkd");
    if sq.config.network_search_wkd() {
        wprintln!(initial_indent = "     - ", "see below for impact");
    }

    wprintln!(initial_indent = "   - ", "{}",
              may_use("DANE", sq.config.network_search_dane()));
    wprintln!(initial_indent = "     - ",
              "relevant setting: network.search.use-dane");
    if sq.config.network_search_dane() {
        wprintln!(initial_indent = "     - ", "see below for impact");
    }

    let key_servers = sq.config.key_servers(
        &network::keyserver::DEFAULT_KEYSERVERS,
        Some(clap::parser::ValueSource::DefaultValue))
        .collect::<Vec<_>>();

    if key_servers.is_empty() {
        wprintln!(initial_indent = "   - ",
                  "will use no key servers by default");
    } else {
        wprintln!(initial_indent = "   - ",
                  "will use the following key servers");
        for s in &key_servers {
            wprintln!(initial_indent = "     - ", "{}", s);
        }
    }
    wprintln!(initial_indent = "       - ",
              "relevant setting: network.keyservers");
    if ! key_servers.is_empty() {
        wprintln!(initial_indent = "       - ", "see below for impact");
    }

    if sq.config.network_search_iterations() > 1 {
        wprintln!(initial_indent = "   - ",
                  "will iteratively search up to {} steps from \
                   your original query to discover related \
                   certificates",
                  sq.config.network_search_iterations().saturating_sub(1));
        wprintln!(initial_indent = "     - ",
                  "this will query certificates that you did not \
                   request, hopefully finding relevant related \
                   certificates, but increases the metadata \
                   leakage and may query \"suspicious\" \
                   certificates");
    }

    // Then, sq network keyserver search.
    wprintln!();
    wprintln!(initial_indent = " - ", "sq network keyserver search");
    if key_servers.is_empty() {
        wprintln!(initial_indent = "   - ",
                  "will use no key servers by default");
    } else {
        wprintln!(initial_indent = "   - ",
                  "will use the following key servers");
        for s in &key_servers {
            wprintln!(initial_indent = "     - ", "{}", s);
        }
    }
    wprintln!(initial_indent = "   - ",
              "relevant setting: network.keyservers");
    wprintln!(initial_indent = "   - ", "impact:");
    wprintln!(initial_indent = "     - ",
              "key servers and their operators can see all requests, \
               and learn about your contacts, and track you");
    wprintln!(initial_indent = "     - ",
              "although the traffic is encrypted, network observers \
               can use traffic analysis and observe the size of requests \
               and responses, and infer information about you and \
               your contacts, and track you");

    // Then, sq network wkd search.
    wprintln!();
    wprintln!(initial_indent = " - ", "sq network wkd search");
    wprintln!(initial_indent = "   - ", "impact:");
    wprintln!(initial_indent = "     - ",
              "WKD servers and their operators can see all requests, \
               and learn about your contacts, and track you");
    wprintln!(initial_indent = "     - ",
              "although the traffic is encrypted, network observers \
               can use traffic analysis, and observe the size of requests \
               and responses, and infer information about you and \
               your contacts, and possibly track you");

    // Then, sq network dane search.
    wprintln!();
    wprintln!(initial_indent = " - ", "sq network dane search");
    wprintln!(initial_indent = "   - ", "impact:");
    wprintln!(initial_indent = "     - ",
              "DNS servers and their operators can see all requests, \
               and learn about your contacts, and track you");
    wprintln!(initial_indent = "     - ",
              "the traffic is not encrypted, network observers \
               can see all requests, and learn about your contacts, \
               and track you");
    Ok(())
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
