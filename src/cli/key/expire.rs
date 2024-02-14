//! Command-line parser for `sq key expire`.

use clap::Args;

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
                "sq", "key", "expire", "1y", "alice-secret.pgp",
            ],
        }),

        Action::Example(Example {
            comment: "Make Alice's key never expire.",
            command: &[
                "sq", "key", "expire", "never", "alice-secret.pgp",
            ],
        }),

        Action::Example(Example {
            comment: "Make Bob's authentication subkey expire in six months.",
            command: &[
                "sq", "key", "expire", "6m",
                "--subkey", "6AEACDD24F896624", "bob-secret.pgp",
            ],
        }),
    ],
};

test_examples!(sq_key_expire, EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    name = "expire",
    about = "Changes expiration times",
    long_about =
"Changes expiration times

Keys and their individual subkeys can expire.  This subcommand changes
or clears the expiration times.

By default, the expiration time of the entire key is changed.  To
change the expiration of only some of the subkeys, use the `--subkey`
option.
",
    after_help = EXAMPLES,
)]
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
        help = "Emits binary data",
    )]
    pub binary: bool,

    #[clap(
        long,
        help = "Change expiration of this subkey, not the entire key",
    )]
    pub subkey: Vec<KeyHandle>,

    #[clap(
        value_name = "EXPIRY",
        help =
            "Defines EXPIRY for the key as ISO 8601 formatted string or \
            custom duration.",
        long_help =
            "Defines EXPIRY for the key as ISO 8601 formatted string or \
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
        default_value_t = FileOrStdin::default(),
        help = FileOrStdin::HELP_OPTIONAL,
        value_name = FileOrStdin::VALUE_NAME,
    )]
    pub input: FileOrStdin,
}
