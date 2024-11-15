use clap::Args;

use crate::cli::types::ClapData;
use crate::cli::types::FileOrCertStore;
use crate::cli::types::FileOrStdout;

use crate::cli::examples::*;
use crate::cli::types::CertDesignators;
use crate::cli::types::UserIDDesignators;
use crate::cli::types::cert_designator;
use crate::cli::types::userid_designator;

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
pub struct Command {
    #[command(flatten)]
    pub cert: CertDesignators<
        cert_designator::CertUserIDEmailFileArgs,
        cert_designator::CertPrefix,
        cert_designator::OneValue,
        StripUserIDDoc>,

    #[command(flatten)]
    pub userids: UserIDDesignators<
        userid_designator::ExistingUserIDEmailNameArgs>,

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

/// Documentation for the cert designators for the toolbox
/// strip-userid command.
pub struct StripUserIDDoc {}

impl cert_designator::AdditionalDocs for StripUserIDDoc {
    fn help(arg: &'static str, help: &'static str) -> clap::builder::StyledStr {
        match arg {
            "file" =>
                "Strip the user ID from the cert read from PATH"
                .into(),
            _ => {
                debug_assert!(help.starts_with("Use certificates"));
                help.replace("Use certificates",
                             "Strip the user ID of the certificate")
                    .into()
            },
        }
    }
}
