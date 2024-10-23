//! Command-line parser for `sq key password`.

use std::path::PathBuf;

use clap::{ArgGroup, Args};

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;

use crate::cli::types::*;
use crate::cli::examples::*;

#[derive(Debug, Args)]
#[clap(
    name = "password",
    about = "Change the password protecting secret key material",
    long_about = "
Change the password protecting secret key material.

Secret key material can be protected by a password.  This subcommand \
changes or clears the password.

To strip the password either use `--clear` or supply a zero-length \
password when prompted for the new password.

If a key is password protected, and the correct password was not \
supplied using the `--password-file` argument, the user is \
prompted for the password.  Likewise, if the new password isn't \
provided, the user is prompted.
",
    after_help = EXAMPLES,
)]
#[clap(group(ArgGroup::new("cert_input").args(&["cert_file", "cert"]).required(true)))]
pub struct Command {
    #[clap(
        long,
        help = "Change the password of the specified certificate's keys",
        value_name = FileOrStdin::VALUE_NAME,
    )]
    pub cert: Option<KeyHandle>,
    #[clap(
        long,
        value_name = "CERT_FILE",
        help = "Change the password of the specified certificate's keys",
        long_help = "\
Change the password of the specified certificate's keys.

Read the certificate from FILE or stdin, if `-`.  It is an error \
for the file to contain more than one certificate.",
    )]
    pub cert_file: Option<FileOrStdin>,

    #[clap(
        long,
        value_name = "PASSWORD_FILE",
        help = "\
File containing password to encrypt the secret key material",
        long_help = "\
File containing password to encrypt the secret key material.

Note that the entire key file will be used as the password including \
any surrounding whitespace like a trailing newline."
    )]
    pub new_password_file: Option<PathBuf>,
    #[clap(
        long,
        help = "Clear the password protecting the secret key material",
    )]
    pub clear_password: bool,

    #[clap(
        help = FileOrStdout::HELP_OPTIONAL,
        long,
        value_name = FileOrStdout::VALUE_NAME,
        conflicts_with = "cert",
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
                "sq", "key", "import", "alice-secret.pgp"
            ],
        }),
        Action::Example(Example {
            comment: "\
Change the password for all of Alice's keys to the password in the \
specified file.",
            command: &[
                "sq", "key", "password",
                "--new-password-file", "password-file.txt",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0"
            ],
        }),
        Action::Example(Example {
            comment: "\
Clear the password protection for all of Alice's keys.",
            command: &[
                "sq", "key", "password",
                "--password-file", "password-file.txt",
                "--clear-password",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0"
            ],
        }),
    ]
};
test_examples!(sq_key_password, EXAMPLES);
