//! Command-line parser for `sq key expire`.

use clap::{
    Args,
    ArgGroup,
    Subcommand,
};

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;

use crate::cli::types::ClapData;
use crate::cli::types::FileOrStdin;
use crate::cli::types::FileOrStdout;

use crate::cli::examples::*;

#[derive(Debug, Subcommand)]
#[clap(
    name = "approvals",
    about = "Manages certification approvals",
    long_about = "\
Manages certification approvals.

Key holders may approve of third-party certifications associated with
their certificate.  This subcommand manages the approvals.",
    subcommand_required = true,
    arg_required_else_help = true,
)]
#[non_exhaustive]
pub enum Command {
    Update(UpdateCommand),
}


const UPDATE_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Example(Example {
            comment: "\
Import Alice's key.",
            command: &[
                "sq", "key", "import",
                "alice-secret.pgp",
            ],
        }),
        Action::Example(Example {
            comment: "\
Attest to all of the certifications on all the user IDs.",
            command: &[
                "sq", "key", "approvals", "update",
                "--all",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            ],
        }),
    ]
};
test_examples!(sq_key_approvals_update, UPDATE_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    name = "update",
    about = "Approves of third-party certifications",
    long_about = "\
Approves of third-party certifications allowing for their distribution.

To prevent certificate flooding attacks, modern key servers prevent
uncontrolled distribution of third-party certifications on
certificates.  To allow the key holder to control what information is
distributed with their certificate, these key servers only distribute
third-party certifications that the key holder has explicitly
approved.

After the attestation has been created, the certificate has to be
distributed, e.g. by uploading it to a key server.
",
    after_help = UPDATE_EXAMPLES,
)]
#[clap(group(ArgGroup::new("certifications_input").args(&["all", "none"]).required(true)))]
#[clap(group(ArgGroup::new("cert_input").args(&["cert_file", "cert"]).required(true)))]
pub struct UpdateCommand {
    #[clap(
        long,
        conflicts_with = "all",
        help = "Remove all prior attestations",
    )]
    pub none: bool,
    #[clap(
        long,
        conflicts_with = "none",
        help = "Attest to all certifications",
    )]
    pub all: bool,
    #[clap(
        long,
        value_name = "CERT",
        help = "Change attestations on the specified certificate",
    )]
    pub cert: Option<KeyHandle>,
    #[clap(
        long,
        value_name = "CERT_FILE",
        help = "Change attestations on the specified certificate",
    )]
    pub cert_file: Option<FileOrStdin>,
    #[clap(
        long,
        short,
        value_name = FileOrStdout::VALUE_NAME,
        help = "Write to the specified FILE",
        long_help = "\
Write to the specified FILE.

If not specified, and the certificate was read from the certificate \
store, imports the modified certificate into the cert store.  If not \
specified, and the certificate was read from a file, writes the \
modified certificate to stdout.",
    )]
    pub output: Option<FileOrStdout>,
    #[clap(
        short = 'B',
        long,
        help = "Emit binary data",
    )]
    pub binary: bool,
}
