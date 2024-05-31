//! Command-line parser for `sq key expire`.

use clap::Args;
use clap::ArgGroup;

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;

use crate::cli::types::ClapData;
use crate::cli::types::Expiry;
use crate::cli::types::FileOrStdin;
use crate::cli::types::FileOrStdout;

use crate::cli::examples::*;

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::Example(Example {
            comment: "Make Alice's key expire in a year.",
            command: &[
                "sq", "key", "expire", "1y",
                "--cert-file", "alice-secret.pgp",
            ],
        }),

        Action::Example(Example {
            comment: "Make Alice's key never expire.",
            command: &[
                "sq", "key", "expire", "never",
                "--cert-file", "alice-secret.pgp",
            ],
        }),
    ],
};

test_examples!(sq_key_expire, EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    name = "expire",
    about = "Change expiration times",
    long_about =
"Change expiration times

Change or clear a certificate's expiration time.

This subcommand changes the certificate's expiration time.  To change
the expiration time of an individual subkey, use the `sq key subkey
expire` subcommand.",
    after_help = EXAMPLES,
)]
#[clap(group(ArgGroup::new("cert_input").args(&["cert_file", "cert"]).required(true)))]
pub struct Command {
    #[clap(
        help = FileOrStdout::HELP_OPTIONAL,
        long,
        short,
        value_name = FileOrStdout::VALUE_NAME,
    )]
    pub output: Option<FileOrStdout>,

    #[clap(
        short = 'B',
        long,
        help = "Emit binary data",
    )]
    pub binary: bool,

    #[clap(
        value_name = "EXPIRY",
        help =
            "Define EXPIRY for the key as ISO 8601 formatted string or \
            custom duration.",
        long_help =
            "Define EXPIRY for the key as ISO 8601 formatted string or \
            custom duration. \
            If an ISO 8601 formatted string is provided, the validity period \
            reaches from the reference time (may be set using `--time`) to \
            the provided time. \
            Custom durations starting from the reference time may be set using \
            `N[ymwds]`, for N years, months, weeks, days, or seconds. \
            The special keyword `never` sets an unlimited expiry.",
    )]
    pub expiry: Expiry,

    #[clap(
        long,
        value_name = "FINGERPRINT|KEYID",
        help = "Change the certificate's expiration time",
    )]
    pub cert: Option<KeyHandle>,
    #[clap(
        long,
        value_name = "CERT_FILE",
        help = "Change the certificate's expiration time",
    )]
    pub cert_file: Option<FileOrStdin>,
}
