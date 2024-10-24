#![doc(html_favicon_url = "https://docs.sequoia-pgp.org/favicon.png")]
#![doc(html_logo_url = "https://docs.sequoia-pgp.org/logo.svg")]

#![allow(rustdoc::invalid_rust_codeblocks)]
#![allow(rustdoc::broken_intra_doc_links)]
#![allow(rustdoc::bare_urls)]
#![doc = include_str!("../README.md")]

use anyhow::Context as _;

use std::borrow::Borrow;
use std::path::Path;
use std::time::SystemTime;

use once_cell::sync::OnceCell;

use sequoia_openpgp as openpgp;

use openpgp::Result;
use openpgp::Cert;
use openpgp::parse::Parse;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::packet::signature::subpacket::NotationDataFlags;
use openpgp::cert::prelude::*;

use clap::FromArgMatches;

#[macro_use] mod macros;
#[macro_use] mod log;

mod sq;
use sq::Sq;

mod common;
use common::PreferredUserID;
pub mod utils;

mod cli;
use cli::SECONDS_IN_DAY;
use cli::SECONDS_IN_YEAR;
use cli::types::Time;

mod commands;
pub mod output;
pub use output::Model;

/// Converts sequoia_openpgp types for rendering.
pub trait Convert<T> {
    /// Performs the conversion.
    fn convert(self) -> T;
}

impl Convert<humantime::FormattedDuration> for std::time::Duration {
    fn convert(self) -> humantime::FormattedDuration {
        humantime::format_duration(self)
    }
}

impl Convert<humantime::FormattedDuration> for openpgp::types::Duration {
    fn convert(self) -> humantime::FormattedDuration {
        humantime::format_duration(self.into())
    }
}

impl Convert<chrono::DateTime<chrono::offset::Utc>> for std::time::SystemTime {
    fn convert(self) -> chrono::DateTime<chrono::offset::Utc> {
        chrono::DateTime::<chrono::offset::Utc>::from(self)
    }
}

impl Convert<chrono::DateTime<chrono::offset::Utc>> for openpgp::types::Timestamp {
    fn convert(self) -> chrono::DateTime<chrono::offset::Utc> {
        std::time::SystemTime::from(self).convert()
    }
}

/// Loads one TSK from every given file.
fn load_keys<I, II>(files: I) -> openpgp::Result<Vec<Cert>>
where
    I: Iterator<Item=II>,
    II: AsRef<Path>,
{
    let mut certs = vec![];
    for f in files {
        let f = f.as_ref();
        let cert = Cert::from_file(f)
            .context(format!("Failed to load key from file {}", f.display()))?;
        if ! cert.is_tsk() {
            return Err(anyhow::anyhow!(
                "Cert in file {} does not contain secret keys", f.display()));
        }
        certs.push(cert);
    }
    Ok(certs)
}

/// Loads one or more certs from every given file.
fn load_certs<I, II>(files: I) -> openpgp::Result<Vec<Cert>>
where
    I: Iterator<Item=II>,
    II: AsRef<Path>,
{
    let mut certs = vec![];
    for f in files {
        let f = f.as_ref();
        for maybe_cert in CertParser::from_file(f)
            .context(format!("Failed to load certs from file {}", f.display()))?
        {
            certs.push(maybe_cert.context(
                format!("A cert from file {} is bad", f.display())
            )?);
        }
    }
    Ok(certs)
}

/// Prints a warning if the user supplied "help" or "-help" to an
/// positional argument.
///
/// This should be used wherever a positional argument is followed by
/// an optional positional argument.
#[allow(dead_code)]
fn help_warning(arg: &str) {
    if arg == "help" {
        wprintln!("Warning: \"help\" is not a subcommand here.  \
                   Did you mean --help?");
    }
}

fn main() {
    if let Err(e) = real_main() {
        print_error_chain(&e);
        std::process::exit(1);
    }
}

fn real_main() -> Result<()> {
    let mut cli = cli::build(true);
    let matches = cli.clone().try_get_matches();
    let c = match matches {
        Ok(matches) => {
            cli::SqCommand::from_arg_matches(&matches)?
        }
        Err(err) => {
            // Warning: hack ahead!
            //
            // If we are showing the help output, we only want to
            // display the global options at the top-level; for
            // subcommands we hide the global options to not overwhelm
            // the user.
            //
            // Ideally, clap would provide a mechanism to only show
            // the help output for global options at the level they
            // are defined at.  That's not the case.
            //
            // We can use `err` to figure out if we are showing the
            // help output, but it doesn't tell us what subcommand we
            // are showing the help for.  Instead (and here's the
            // hack!), we compare the output.  If it is the output for
            // the top-level `--help` or `-h`, then we are showing the
            // help for the top-level.  If not, then we are showing
            // the help for a subcommand.  In the former case, we
            // unhide the global options.
            use clap::error::ErrorKind;
            if err.kind() == ErrorKind::DisplayHelp
                || err.kind() == ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
            {
                let output = err.render();
                let output = if output == cli.render_long_help() {
                    Some(cli::build(false).render_long_help())
                } else if output == cli.render_help() {
                    Some(cli::build(false).render_help())
                } else {
                    None
                };

                if let Some(output) = output {
                    if err.use_stderr() {
                        eprint!("{}", output);
                    } else {
                        print!("{}", output);
                    }
                    std::process::exit(err.exit_code());
                }
            }

            // Print the error message.
            err.print()?;

            // Then, figure out if this is a usage message, and
            // extract the usage string.
            if let Some(usage) = err.context()
                .find_map(|(kind, value)|
                          (kind == clap::error::ContextKind::Usage)
                          .then_some(value))
            {
                print_examples(&cli, usage)?;
            }

            // Finally, exit with an error code.
            std::process::exit(err.exit_code());
        }
    };

    let time_is_now = c.time.is_none();
    let time: SystemTime =
        c.time.clone().unwrap_or_else(|| Time::now()).into();

    let mut policy = sequoia_policy_config::ConfiguredStandardPolicy::new();
    policy.parse_default_config()?;
    let mut policy = policy.build();

    let known_notations_store = c.known_notation.clone();
    let known_notations = known_notations_store
        .iter()
        .map(|n| n.as_str())
        .collect::<Vec<&str>>();
    policy.good_critical_notations(&known_notations);

    let mut password_cache = Vec::new();
    for password_file in &c.password_file {
        let password = std::fs::read(&password_file)
            .with_context(|| {
                format!("Reading {}", password_file.display())
            })?;
        password_cache.push(password.into());
    };

    let sq = Sq {
        verbose: c.verbose,
        quiet: c.quiet,
        overwrite: c.overwrite,
        batch: c.batch,
        policy: &policy,
        time,
        time_is_now,
        home: if let Some(p) = c.home.as_ref().and_then(|a| a.path()) {
            sequoia_directories::Home::new(p)?
        } else {
            sequoia_directories::Home::default()
                .ok_or(anyhow::anyhow!("no default SEQUOIA_HOME \
                                        on this platform"))?
                .clone()
        },
        no_rw_cert_store: c.no_cert_store,
        cert_store_path: c.cert_store.as_ref().and_then(|a| a.path()),
        keyrings: c.keyring.clone(),
        keyring_tsks: Default::default(),
        cert_store: OnceCell::new(),
        trust_roots: c.trust_roots.clone(),
        trust_root_local: Default::default(),
        no_key_store: c.no_key_store,
        key_store_path: c.key_store.as_ref().and_then(|a| a.path()),
        key_store: OnceCell::new(),
        password_cache: password_cache.into(),
    };

    commands::dispatch(sq, c)
}

fn parse_notations<N>(n: N) -> Result<Vec<(bool, NotationData)>>
where
    N: AsRef<[String]>,
{
    let n = n.as_ref();
    assert_eq!(n.len() % 2, 0, "notations must be pairs of key and value");

    // Each --notation takes two values.  Iterate over them in chunks of 2.
    let notations: Vec<(bool, NotationData)> = n
        .chunks(2)
        .map(|arg_pair| {
            let name = &arg_pair[0];
            let value = &arg_pair[1];

            let (critical, name) = match name.strip_prefix('!') {
                Some(name) => (true, name),
                None => (false, name.as_str()),
            };

            let notation_data = NotationData::new(
                name,
                value,
                NotationDataFlags::empty().set_human_readable(),
            );
            (critical, notation_data)
        })
        .collect();

    Ok(notations)
}

// Sometimes the same error cascades, e.g.:
//
// ```
// $ sq-wot --time 20230110T0406   --keyring sha1.pgp path B5FA089BA76FE3E17DC11660960E53286738F94C 231BC4AB9D8CAB86D1622CE02C0CE554998EECDB FABA8485B2D4D5BF1582AA963A8115E774FA9852 "<carol@example.org>"
// [ ] FABA8485B2D4D5BF1582AA963A8115E774FA9852 <carol@example.org>: not authenticated (0%)
//   ◯ B5FA089BA76FE3E17DC11660960E53286738F94C ("<alice@example.org>")
//   │   No adequate certification found.
//   │   No binding signature at time 2023-01-10T04:06:00Z
//   │     No binding signature at time 2023-01-10T04:06:00Z
//   │     No binding signature at time 2023-01-10T04:06:00Z
// ...
// ```
//
// Compress these.
fn error_chain(err: &anyhow::Error) -> Vec<String> {
    let mut errs = std::iter::once(err.to_string())
        .chain(err.chain().map(|source| source.to_string()))
        .collect::<Vec<String>>();
    errs.dedup();
    errs
}

/// Prints the error and causes, if any.
pub fn print_error_chain(err: &anyhow::Error) {
    wprintln!();
    wprintln!(initial_indent="  Error: ", "{}", err);
    err.chain().skip(1).for_each(
        |cause| wprintln!(initial_indent="because: ", "{}", cause));
}

/// Returns the error chain as a string.
///
/// The error and causes are separated by `error_separator`.  The
/// causes are separated by `cause_separator`, or, if that is `None`,
/// `error_separator`.
pub fn display_error_chain<'a, E, C>(err: E,
                                     error_separator: &str,
                                     cause_separator: C)
    -> String
where E: Borrow<anyhow::Error>,
      C: Into<Option<&'a str>>
{
    let err = err.borrow();
    let cause_separator = cause_separator.into();

    let error_chain = error_chain(err);
    match error_chain.len() {
        0 => unreachable!(),
        1 => {
            error_chain.into_iter().next().expect("have one")
        }
        2 => {
            format!("{}{}{}",
                    error_chain[0],
                    error_separator,
                    error_chain[1])
        }
        _ => {
            if let Some(cause_separator) = cause_separator {
                format!("{}{}{}",
                        error_chain[0],
                        error_separator,
                        error_chain[1..].join(cause_separator))
            } else {
                error_chain.join(error_separator)
            }
        }
    }

}

pub fn one_line_error_chain<E>(err: E) -> String
where E: Borrow<anyhow::Error>,
{
    display_error_chain(err, ": ", ", because ")
}

/// Given a `clap::Command` and a usage string, try to augment the
/// usage message with relevant examples.
fn print_examples(cli: &clap::Command, usage: impl ToString) -> Result<()> {
    // First, find the invoked subcommand.
    let usage = usage.to_string();
    let prefix = usage.find("sq ");
    let subcommands = if let Some(i) = prefix {
        usage[i + 3..].split(" ")
        // Split, but only take the parts that do not denote options
        // or flags.
            .take_while(|p| p.chars().all(|c| c.is_alphabetic()))
    } else {
        // Odd...
        return Ok(());
    };

    // Now traverse the CLI tree to find the subcommand.
    let mut cmd = cli;
    for sub in subcommands {
        cmd = if let Some(c) = cmd.get_subcommands()
            .find(|c| c.get_name() == sub)
        {
            c
        } else {
            // Very odd...
            return Ok(());
        };
    }

    // And print the examples, if any.
    if let Some(examples) = cmd.get_after_help() {
        wprintln!("\n{}", examples);
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    // Run some clap tests.
    #[test]
    fn verify_app() {
        let cli = cli::build(true);
        cli.debug_assert();
    }
}
