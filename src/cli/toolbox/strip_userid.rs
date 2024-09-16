use clap::{ArgGroup, Args};

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;
use openpgp::packet::UserID;

use crate::cli::types::ClapData;
use crate::cli::types::FileOrCertStore;
use crate::cli::types::FileOrStdin;
use crate::cli::types::FileOrStdout;

use crate::cli::examples::*;

#[derive(Debug, Args)]
#[clap(
    about = "Strip a user ID",
    long_about =
"Strip a user ID.

Note that this operation does not reliably remove User IDs from a \
certificate that has already been disseminated! (OpenPGP software \
typically appends new information it receives about a certificate to \
its local copy of that certificate.  Systems that have obtained a copy \
of your certificate with the User ID that you are trying to strip will \
not drop that User ID from their copy.)

In most cases, you will want to use the 'sq key userid revoke' operation \
instead.  That issues a revocation for a User ID, which can be used to mark \
the User ID as invalidated.

However, this operation can be useful in very specific cases, in particular: \
to remove a mistakenly added User ID before it has been uploaded to key \
servers or otherwise shared.

Stripping a User ID may change how a certificate is interpreted.  This \
is because information about the certificate like algorithm preferences, \
the primary key's key flags, etc. is stored in the User ID's binding \
signature.
",
    after_help = USERID_STRIP_EXAMPLES,
)]
#[clap(group(ArgGroup::new("cert_input").args(&["cert_file", "cert"]).required(true)))]
#[clap(group(ArgGroup::new("cert-userid").args(&["names", "emails", "userid"]).required(true).multiple(true)))]
pub struct Command {
    #[clap(
        long,
        value_name = "FINGERPRINT|KEYID",
        help = "Strip the user ID on the specified certificate",
    )]
    pub cert: Option<KeyHandle>,
    #[clap(
        long,
        help = FileOrStdin::HELP_OPTIONAL,
        value_name = "CERT_FILE",
        conflicts_with = "cert",
        help = "Strip the user ID on the specified certificate",
        long_help = "\
Strip the user ID on the specified certificate.

Read the certificate whose user ID should be stripped from FILE or \
stdin, if `-`.  It is an error for the file to contain more than one \
certificate.",
    )]
    pub cert_file: Option<FileOrStdin>,

    #[clap(
        long,
        value_name = FileOrCertStore::VALUE_NAME,
        help = "Write to the specified FILE",
        long_help = "\
Write to the specified FILE.

If not specified, and the certificate was read from the certificate
store, imports the modified certificate into the cert store.  If not
specified, and the certificate was read from a file, writes the
modified certificate to stdout.",
    )]
    pub output: Option<FileOrStdout>,

    #[clap(
        long = "name",
        value_name = "NAME",
        help = "Strip the given name user ID",
        long_help = "\
Strip the given name user ID.  Must match a user ID exactly.  To strip
a user ID that contains more than just a name, use `--userid`.",
    )]
    pub names: Vec<String>,

    #[clap(
        long = "email",
        value_name = "ADDRESS",
        help = "Strip the given email address user ID",
        long_help = "\
Strip the given email address user ID.  Must match a user ID exactly.
To strip a user ID that contains more than just an email address name,
use `--userid`.",
    )]
    pub emails: Vec<String>,

    #[clap(
        value_name = "USERID",
        long,
        help = "Strip the given user IDs",
        long_help = "\
Strip the given user IDs from the key.  Must match a user ID exactly.",
    )]
    pub userid: Vec<UserID>,

    #[clap(
        long,
        help = "Emit binary data",
    )]
    pub binary: bool,
}

const USERID_STRIP_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Example(Example {
            comment: "Strip a User ID from a cert in the cert store.",
            command: &[
                "sq", "toolbox", "strip-userid",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--userid", "Alice <alice@example.org>",
            ],
        }),
    ]
};
test_examples!(sq_key_userid_strip, USERID_STRIP_EXAMPLES);
