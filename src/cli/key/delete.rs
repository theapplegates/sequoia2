//! Command-line parser for `sq key delete`.

use clap::{ArgGroup, Args};

use sequoia_openpgp::KeyHandle;

use crate::cli::types::*;
use crate::cli::examples::*;

#[derive(Debug, Args)]
#[clap(
    name = "delete",
    about = "Delete a certificate's secret key material",
    after_help = EXAMPLES,
)]
#[clap(group(ArgGroup::new("cert_input").args(&["cert_file", "cert"]).required(true)))]
pub struct Command {
    #[clap(
        long,
        help = "Delete the secret key material from the specified certificate",
        value_name = FileOrStdin::VALUE_NAME,
    )]
    pub cert: Option<KeyHandle>,
    #[clap(
        long,
        value_name = "CERT_FILE",
        help = "Delete the secret key material from the specified certificate",
        long_help = "\
Delete the secret key material from the specified certificate.

Read the certificate from FILE or stdin, if `-`.  It is an error \
for the file to contain more than one certificate.",
    )]
    pub cert_file: Option<FileOrStdin>,

    #[clap(
        long,
        value_name = FileOrStdout::VALUE_NAME,
        conflicts_with = "cert",
        help = "Write the stripped certificate to the specified file",
    )]
    pub output: Option<FileOrStdout>,

    #[clap(
        long,
        requires = "output",
        help = "Emit binary data",
    )]
    pub binary: bool,
}

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::Setup(Setup {
            command: &[
                "sq", "key", "import", "alice-secret.pgp",
            ],
        }),

        Action::Example(Example {
            comment: "\
Delete any secret key associated with Alice's certificate.",
            command: &[
                "sq", "key", "delete",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            ],
        }),
    ]
};
test_examples!(sq_key_delete, EXAMPLES);
