use clap::Parser;

use crate::cli::types::ClapData;
use crate::cli::types::FileOrCertStore;
use crate::cli::types::FileOrStdout;
use super::keyserver::DEFAULT_KEYSERVERS;

#[derive(Parser, Debug)]
#[clap(
    name = "fetch",
    about = "Retrieves certificates using all supported network services",
    long_about =
"Retrieves certificates using all supported network services

By default, any returned certificates are stored in the local
certificate store.  This can be overridden by using `--output`
option.

When a certificate is retrieved from a verifying key server (currently,
this is limited to a list of known servers: `hkps://keys.openpgp.org`,
`hkps://keys.mailvelope.com`, and `hkps://mail-api.proton.me`), and
imported into the local certificate store, the User IDs are also
certificated with a local server-specific key.  That proxy certificate
is in turn certified as a minimally trusted CA (trust amount: 1 of
120) by the local trust root.  How much a proxy key server CA is
trusted can be tuned using `sq pki link add` or `sq pki link retract` in
the usual way.
",
    arg_required_else_help = true,
)]
pub struct Command {
    #[clap(
        short,
        long = "server",
        default_values_t = DEFAULT_KEYSERVERS.iter().map(ToString::to_string),
        value_name = "URI",
        help = "Sets the key server to use.  Can be given multiple times.",
    )]
    pub servers: Vec<String>,

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
