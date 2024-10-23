//! Command-line parser for `sq key expire`.

use clap::Args;

use crate::cli::types::ClapData;
use crate::cli::types::Expiration;
use crate::cli::types::FileOrStdout;

use crate::cli::examples::*;
use crate::cli::types::cert_designator::*;

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::Setup(Setup {
            command: &[
                "sq", "key", "import",
                "alice-secret.pgp",
            ],
        }),
        Action::Example(Example {
            comment: "Change Alice's certificate to expire in a year.",
            command: &[
                "sq", "key", "expire", "1y",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            ],
        }),

        Action::Example(Example {
            comment: "Change Alice's certificate to never expire.",
            command: &[
                "sq", "key", "expire", "never",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            ],
        }),
    ],
};

test_examples!(sq_key_expire, EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    name = "expire",
    about = "Change a certificate's expiration time",
    long_about =
"Change a certificate's expiration time.

This subcommand changes a certificate's expiration time.  To change \
the expiration time of an individual subkey, use the `sq key subkey \
expire` subcommand.
",
    after_help = EXAMPLES,
)]
pub struct Command {
    #[command(flatten)]
    pub cert: CertDesignators<CertUserIDEmailFileArgs,
                              NoPrefix,
                              OneValueAndFileRequiresOutput,
                              KeyExpireDoc>,

    #[clap(
        help = FileOrStdout::HELP_OPTIONAL,
        long,
        value_name = FileOrStdout::VALUE_NAME,
    )]
    pub output: Option<FileOrStdout>,

    #[clap(
        long,
        help = "Emit binary data",
    )]
    pub binary: bool,

    #[clap(
        value_name = "EXPIRATION",
        help =
            "Define EXPIRATION for the key as ISO 8601 formatted string or \
            custom duration.",
        long_help =
            "Define EXPIRATION for the key as ISO 8601 formatted string or \
            custom duration. \
            If an ISO 8601 formatted string is provided, the validity period \
            reaches from the reference time (may be set using `--time`) to \
            the provided time. \
            Custom durations starting from the reference time may be set using \
            `N[ymwds]`, for N years, months, weeks, days, or seconds. \
            The special keyword `never` sets an unlimited expiry.",
    )]
    pub expiration: Expiration,
}

/// Documentation for the cert designators for the key expire.
pub struct KeyExpireDoc {}

impl AdditionalDocs for KeyExpireDoc {
    fn help(arg: &'static str, help: &'static str) -> clap::builder::StyledStr {
        match arg {
            "file" =>
                "Change the expiration of the key \
                 read from PATH"
                .into(),
            _ => {
                debug_assert!(help.starts_with("Use certificates"));
                help.replace("Use certificates",
                             "Change the expiration of the key")
            },
        }.into()
    }
}
