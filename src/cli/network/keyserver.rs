use clap::{Args, Parser, Subcommand};

use crate::cli::types::ClapData;
use crate::cli::types::FileOrCertStore;
use crate::cli::types::FileOrStdin;
use crate::cli::types::FileOrStdout;

/// The default keyservers to query.
pub const DEFAULT_KEYSERVERS: &[&'static str] = &[
    "hkps://keys.openpgp.org",
    "hkps://mail-api.proton.me",
    "hkps://keys.mailvelope.com",
    "hkps://keyserver.ubuntu.com",
];

#[derive(Parser, Debug)]
#[clap(
    name = "keyserver",
    about = "Interacts with keyservers",
    subcommand_required = true,
    arg_required_else_help = true,
)]
pub struct Command {
    #[clap(
        short,
        long = "server",
        default_values_t = DEFAULT_KEYSERVERS.iter().map(ToString::to_string),
        global = true,
        // All global options should have a high display_order, so
        // that they are sorted to the bottom.
        display_order = 800,
        value_name = "URI",
        help = "Sets the keyserver to use.  Can be given multiple times.",
    )]
    pub servers: Vec<String>,
    #[clap(subcommand)]
    pub subcommand: Subcommands,
}

#[derive(Debug, Subcommand)]
pub enum Subcommands {
    Fetch(FetchCommand),
    Publish(PublishCommand),
}

#[derive(Debug, Args)]
#[clap(
    about = "Retrieves certificates from key servers",
    long_about =
"Retrieves certificates from key servers

By default, any returned certificates are stored in the local
certificate store.  This can be overridden by using `--output`
option.

When a certificate is retrieved from a verifying keyserver (currently,
this is limited to a list of known servers: `hkps://keys.openpgp.org`,
`hkps://keys.mailvelope.com`, and `hkps://mail-api.proton.me`), and
imported into the local certificate store, the User IDs are also
certificated with a local server-specific key.  That proxy certificate
is in turn certified as a minimally trusted CA (trust amount: 1 of
120) by the local trust root.  How much a proxy key server CA is
trusted can be tuned using `sq link add` or `sq link retract` in
the usual way.
"
)]
pub struct FetchCommand {
    #[clap(
        help = FileOrCertStore::HELP_OPTIONAL,
        long,
        short,
        value_name = FileOrCertStore::VALUE_NAME,
    )]
    pub output: Option<FileOrStdout>,
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,
    #[clap(
        value_name = "QUERY",
        required = true,
        help = "Retrieve certificate(s) using QUERY. \
            This may be a fingerprint, a KeyID, \
            or an email address.",
    )]
    pub query: Vec<String>,
}

#[derive(Debug, Args)]
#[clap(
    about = "Publishes certificates on key servers",
    long_about = format!(
"Publishes certificates on key servers

Sends certificates to the configured key servers for publication.  By
default, the certificates are sent to {}.  This can be tweaked using
`--servers`.",
        join(DEFAULT_KEYSERVERS.iter().cloned())),
)]
pub struct PublishCommand {
    #[clap(
        long,
        help = "Requires that all publish operations succeed \
                and return an error otherwise.  \
                By default we only require that one publish \
                operation succeeds.",
    )]
    pub require_all: bool,
    #[clap(
        default_value_t = FileOrStdin::default(),
        help = FileOrStdin::HELP_OPTIONAL,
        value_name = FileOrStdin::VALUE_NAME,
    )]
    pub input: FileOrStdin,
}

/// Joins the given key server URLs into a list.
fn join<'a>(i: impl Iterator<Item = &'a str>) -> String {
    let mut i = i.map(|u| format!("`{}`", u)).collect::<Vec<_>>();
    match i.len() {
        0 => panic!("empty list"),
        1 => i.pop().unwrap(),
        2 => format!("{} and {}", i[0], i[1]),
        n => format!("{}, and {}", i[..n-1].join(", "), i[n-1]),
    }
}
