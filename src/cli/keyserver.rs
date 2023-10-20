use clap::{Args, Parser, Subcommand};

use crate::cli::types::NetworkPolicy;

use super::types::ClapData;
use super::types::FileOrCertStore;
use super::types::FileOrStdin;
use super::types::FileOrStdout;

#[derive(Parser, Debug)]
#[clap(
    name = "keyserver",
    about = "Interacts with keyservers",
    subcommand_required = true,
    arg_required_else_help = true,
)]
pub struct Command {
    #[clap(
        short = 'p',
        long = "policy",
        value_name = "NETWORK-POLICY",
        default_value_t = NetworkPolicy::Encrypted,
        help = "Sets the network policy to use",
        value_enum,
    )]
    pub network_policy: NetworkPolicy,
    #[clap(
        short,
        long,
        default_value = "hkps://keys.openpgp.org",
        value_name = "URI",
        help = "Sets the keyserver to use",
    )]
    pub server: String,
    #[clap(subcommand)]
    pub subcommand: Subcommands,
}

#[derive(Debug, Subcommand)]
pub enum Subcommands {
    Get(GetCommand),
    Send(SendCommand),
}

#[derive(Debug, Args)]
#[clap(
    about = "Retrieves a certificate",
    long_about =
"Retrieves a certificate from a keyserver.

By default, any returned certificates are stored in the local
certificate store.  This can be overridden by using \"--output\"
option.

When a certificate is downloaded from a verifying keyserver
(currently, this is limited to a list of known servers:
keys.openpgp.org, keys.mailvelope.com, and mail-api.proton.me), and
imported into the local certificate store, the User IDs are also
certificated with a local server-specific key.  That proxy certificate
is in turn certified as a minimally trusted CA (trust amount: 1 of
120) by the local trust root.  How much a proxy key server CA is
trusted can be tuned using \"sq link add\" or \"sq link retract\" in
the usual way.
"
)]
pub struct GetCommand {
    #[clap(
        help = FileOrCertStore::HELP,
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
        help = "Retrieve certificate(s) using QUERY. \
            This may be a fingerprint, a KeyID, \
            or an email address.",
    )]
    pub query: String,
}

#[derive(Debug, Args)]
#[clap(
    about = "Sends a key",
)]
pub struct SendCommand {
    #[clap(
        default_value_t = FileOrStdin::default(),
        help = FileOrStdin::HELP,
        value_name = FileOrStdin::VALUE_NAME,
    )]
    pub input: FileOrStdin,
}
