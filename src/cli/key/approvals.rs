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

Key holders may approve of third-party certifications associated with \
their certificate.  This subcommand manages the approvals.

To prevent certificate flooding attacks, modern key servers prevent \
uncontrolled distribution of third-party certifications on \
certificates.  To allow the key holder to control what information is \
distributed with their certificate, these key servers only distribute \
third-party certifications that the key holder has explicitly \
approved.
",
    subcommand_required = true,
    arg_required_else_help = true,
)]
#[non_exhaustive]
pub enum Command {
    List(ListCommand),
    Update(UpdateCommand),
}

const LIST_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Example(Example {
            comment: "\
Lists the approved certifications on all the user IDs.",
            command: &[
                "sq", "key", "approvals", "list",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            ],
        }),

        Action::Example(Example {
            comment: "\
Lists the unapproved certifications on all the user IDs.",
            command: &[
                "sq", "key", "approvals", "list",
                "--pending",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            ],
        }),

        Action::Example(Example {
            comment: "\
Lists all unapproved certifications on a given user ID.",
            command: &[
                "sq", "key", "approvals", "list",
                "--pending",
                "--email", "alice@example.org",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            ],
        }),
    ]
};
test_examples!(sq_key_approvals_list, LIST_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    name = "list",
    about = "Lists third-party certifications",
    long_about = "\
Lists third-party certifications and their approval status.

To prevent certificate flooding attacks, modern key servers prevent \
uncontrolled distribution of third-party certifications on \
certificates.  To allow the key holder to control what information is \
distributed with their certificate, these key servers only distribute \
third-party certifications that the key holder has explicitly \
approved.
",
    after_help = LIST_EXAMPLES,
)]
pub struct ListCommand {
    #[clap(
        long = "pending",
        help = "List unapproved certifications",
    )]
    pub pending: bool,

    #[clap(
        long = "name",
        help = "List certifications on this name user ID",
    )]
    pub names: Vec<String>,

    #[clap(
        long = "email",
        help = "List certifications on this email address user ID",
    )]
    pub emails: Vec<String>,

    #[clap(
        long = "userid",
        help = "List certifications on this user ID",
    )]
    pub userids: Vec<String>,

    #[clap(
        long,
        value_name = "CERT",
        help = "Lists attestations on the specified certificate",
    )]
    pub cert: KeyHandle,
}

const UPDATE_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Setup(Setup {
            command: &[
                "sq", "key", "import", "alice-secret.pgp",
            ],
        }),
        Action::Setup(Setup {
            command: &[
                "sq", "key", "import", "bob-secret.pgp",
            ],
        }),
        Action::Setup(Setup {
            command: &[
                "sq", "pki", "certify",
                "--certifier", "511257EBBF077B7AEDAE5D093F68CB84CE537C9A",
                "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--email", "alice@example.org",
            ],
        }),
        Action::Setup(Setup {
            command: &[
                "sq", "pki", "link", "add",
                "511257EBBF077B7AEDAE5D093F68CB84CE537C9A",
                "--email", "bob@example.org",
            ],
        }),

        Action::Example(Example {
            comment: "\
Approve of all of the certifications on all of Alice's user IDs.",
            command: &[
                "sq", "key", "approvals", "update",
                "--add-all",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            ],
        }),

        Action::Example(Example {
            comment: "\
Approve of all of the certifications on all of Alice's user IDs made by Bob, \
discarding all prior approvals first.",
            command: &[
                "sq", "key", "approvals", "update",
                "--remove-all",
                "--add-by", "511257EBBF077B7AEDAE5D093F68CB84CE537C9A",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            ],
        }),

        Action::Example(Example {
            comment: "\
Approve of all of the certifications on a specific user ID by certifiers that \
can be authenticated, discarding all prior approvals first.",
            command: &[
                "sq", "key", "approvals", "update",
                "--remove-all",
                "--add-authenticated",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--userid", "Alice <alice@example.org>",
            ],
        }),

        Action::Example(Example {
            comment: "\
Remove the approval of Bob's certification on all of Alice's user IDs.",
            command: &[
                "sq", "key", "approvals", "update",
                "--remove-by", "511257EBBF077B7AEDAE5D093F68CB84CE537C9A",
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

To prevent certificate flooding attacks, modern key servers prevent \
uncontrolled distribution of third-party certifications on \
certificates.  To allow the key holder to control what information is \
distributed with their certificate, these key servers only distribute \
third-party certifications that the key holder has explicitly \
approved.

By default, all user IDs are considered, but if at least one `--name`, \
`--email`, or `--userid` argument is given, only the matching user IDs \
are considered.

After the approvals have been changed, the certificate has to be \
distributed, e.g. by uploading it to a key server.
",
    after_help = UPDATE_EXAMPLES,
)]
#[clap(group(ArgGroup::new("cert_input").args(&["cert_file", "cert"]).required(true)))]
pub struct UpdateCommand {
    #[clap(
        long = "name",
        help = "Change approvals on this name user ID",
    )]
    pub names: Vec<String>,

    #[clap(
        long = "email",
        help = "Change approvals on this email address user ID",
    )]
    pub emails: Vec<String>,

    #[clap(
        long = "userid",
        help = "Change approvals on this user ID",
    )]
    pub userids: Vec<String>,

    #[clap(
        long = "remove-all",
        help = "Remove all prior approvals",
        conflicts_with = "add_all",
        long_help = "\
Remove all prior approvals.

By default, this command adds to the set of already approved
certifications.  If this flag is given, the existing approvals are
disregarded, and only the newly selected certifications are approved,
if any.
",
    )]
    pub remove_all: bool,

    #[clap(
        long = "remove-by",
        value_name = "FINGERPRINT|KEYID",
        help = "Remove all prior approvals of certifications by this certifier",
        conflicts_with = "remove_all",
    )]
    pub remove_by: Vec<KeyHandle>,

    #[clap(
        long = "add-all",
        help = "Approve of all pending certifications",
        conflicts_with_all = ["remove_all", "remove_by"],
    )]
    pub add_all: bool,

    #[clap(
        long = "add-by",
        value_name = "FINGERPRINT|KEYID",
        help = "Approve of all certifications by this certifier",
        conflicts_with = "add_all",
    )]
    pub add_by: Vec<KeyHandle>,

    #[clap(
        long = "add-authenticated",
        value_name = "AMOUNT",
        default_missing_value = "40",
        num_args = 0..=1,
        help = "Approve of all certifications by authenticated certifiers",
        long_help = "\
Approve of all certifications by authenticated certifiers.

For all pending approvals, try to authenticate any user ID on the
certifier, and if any can be authenticated to at least the given
amount, approve of the certification.",
        conflicts_with = "add_all",
    )]
    pub add_authenticated: Option<u8>,

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
        long,
        help = "Emit binary data",
    )]
    pub binary: bool,
}
