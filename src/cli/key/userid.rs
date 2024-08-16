use clap::{ValueEnum, ArgGroup, Args, Subcommand};

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;
use openpgp::packet::UserID;
use openpgp::types::ReasonForRevocation;

use crate::cli::types::ClapData;
use crate::cli::types::FileOrCertStore;
use crate::cli::types::FileOrStdin;
use crate::cli::types::FileOrStdout;

use crate::cli::examples;
use examples::Action;
use examples::Actions;
use examples::Example;
use examples::Setup;

#[derive(Debug, Subcommand)]
#[clap(
    name = "userid",
    about = "Manage User IDs",
    long_about =
"Manage User IDs

Add User IDs to a key, or revoke them.
",
    subcommand_required = true,
    arg_required_else_help = true,
)]
pub enum Command {
    Add(AddCommand),
    Revoke(RevokeCommand),
    Strip(StripCommand),
}

const USERID_ADD_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Setup(Setup {
            command: &[
                "sq", "key", "import", "alice-secret.pgp"
            ],
        }),
        Action::Example(Example {
            comment: "\
Add a new user ID to Alice's key.",
            command: &[
                "sq", "key", "userid", "add",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--name", "Alice",
                "--email", "alice@work.example.com",
            ],
        }),
    ]
};
test_examples!(sq_key_userid_add, USERID_ADD_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    about = "Add a user ID",
    long_about =
"Add a user ID.

A user ID can contain a name, like `Juliet`, or an email address, like \
`<juliet@example.org>`.  Historically, a name and an email address were \
usually combined as a single user ID, like `Juliet <juliet@example.org>`.
However, user IDs that include different information such as name and
email address are more difficult to reason about, so using distinct
user IDs for name and email address is preferred nowadays.

`sq userid add` respects the reference time set by the top-level \
`--time` argument.  It sets the creation time of the user ID's \
binding signature to the specified time.
",
    after_help = USERID_ADD_EXAMPLES,
)]
#[clap(group(ArgGroup::new("cert_input").args(&["cert_file", "cert"]).required(true)))]
#[clap(group(ArgGroup::new("cert-userid").args(&["names", "emails", "userid"]).required(true).multiple(true)))]
pub struct AddCommand {
    #[clap(
        long,
        value_name = "FINGERPRINT|KEYID",
        help = "Add the user ID to the specified certificate",
    )]
    pub cert: Option<KeyHandle>,
    #[clap(
        long,
        value_name = "CERT_FILE",
        conflicts_with = "cert",
        help = "Add the user ID to the specified certificate",
    )]
    pub cert_file: Option<FileOrStdin>,

    #[clap(
        long = "name",
        value_name = "NAME",
        help = "Add a name as user ID to the key"
    )]
    pub names: Vec<String>,

    #[clap(
        long = "email",
        value_name = "ADDRESS",
        help = "Add an email address as user ID to the key"
    )]
    pub emails: Vec<String>,

    #[clap(
        long,
        value_name = "USERID",
        help = "Add a user ID to the key",
        long_help = "
Add a user ID to the key.

This user ID can combine name and email address, can optionally
contain a comment, or even be free-form if
`--allow-non-canonical-userids` is given.  However, user IDs that
include different information such as name and email address are more
difficult to reason about, so using distinct user IDs for name and
email address is preferred nowadays.

In doubt, prefer `--name` and `--email`.
",
    )]
    pub userid: Vec<UserID>,

    #[clap(
        long,
        help = "Don't reject user IDs that are not in canonical form",
        long_help = "\
Don't reject user IDs that are not in canonical form.

Canonical user IDs are of the form `Name (Comment) \
<localpart@example.org>`.",
    )]
    pub allow_non_canonical_userids: bool,
    #[clap(
        long,
        value_name = FileOrCertStore::VALUE_NAME,
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

const USERID_REVOKE_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Setup(Setup {
            command: &[
                "sq", "key", "import", "alice-secret.pgp"
            ],
        }),
        Action::Example(Example {
            comment: "\
Retire a user ID on Alice's key.",
            command: &[
                "sq", "key", "userid", "revoke",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--userid", "Alice <alice@example.org>",
                "retired", "No longer at example.org.",
            ],
        }),
    ]
};
test_examples!(sq_key_userid_revoke, USERID_REVOKE_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    about = "Revoke a user ID",
    long_about = "\
Revoke a user ID.

Creates a revocation certificate for a user ID.

If `--revoker` or `--revoker-file` is provided, then that key is used \
to create the revocation certificate.  If that key is different from \
the certificate that is being revoked, this results in a third-party \
revocation.  This is normally only useful if the owner of the \
certificate designated the key to be a designated revoker.

`sq key userid revoke` respects the reference time set by the top-level \
`--time` argument.  When set, it uses the specified time instead of \
the current time when determining what keys are valid, and it sets \
the revocation certificate's creation time to the reference time \
instead of the current time.",
    after_help = USERID_REVOKE_EXAMPLES,
)]
#[clap(group(ArgGroup::new("cert_input").args(&["cert_file", "cert"]).required(true)))]
#[clap(group(ArgGroup::new("revoker_input").args(&["revoker_file", "revoker"])))]
pub struct RevokeCommand {
    #[clap(
        long,
        value_name = "FINGERPRINT|KEYID",
        help = "Revoke the user ID on the specified certificate",
    )]
    pub cert: Option<KeyHandle>,
    #[clap(
        long,
        help = FileOrStdin::HELP_OPTIONAL,
        value_name = "CERT_FILE",
        conflicts_with = "cert",
        help = "Revoke the user ID on the specified certificate",
        long_help = "\
Revoke the user ID on the specified certificate.

Read the certificate whose user ID should be revoked from FILE or \
stdin, if `-`.  It is an error for the file to contain more than one \
certificate.",
    )]
    pub cert_file: Option<FileOrStdin>,

    #[clap(
        long,
        value_name = "FINGERPRINT|KEYID",
        help = "The certificate that issues the revocation",
        long_help = "\
The certificate that issues the revocation.

Sign the revocation certificate using the specified key.  By default, \
the certificate being revoked is used.  Using this option, it is \
possible to create a third-party revocation.",
    )]
    pub revoker: Option<KeyHandle>,
    #[clap(
        long,
        value_name = "KEY_FILE",
        conflicts_with = "revoker",
        help = "The certificate that issues the revocation",
        long_help = "\
The certificate that issues the revocation.

Sign the revocation certificate using the specified key.  By default, \
the certificate being revoked is used.  Using this option, it is \
possible to create a third-party revocation.

Read the certificate from KEY_FILE or stdin, if `-`.  It is an error \
for the file to contain more than one certificate.",
    )]
    pub revoker_file: Option<FileOrStdin>,

    #[clap(
        long,
        value_name = "USERID",
        help = "The user ID to revoke",
        long_help = "\
The user ID to revoke.

By default, this must exactly match a self-signed User ID.  Use \
`--force` to generate a revocation certificate for a User ID that is \
not self signed."
    )]
    pub userid: String,

    #[clap(
        value_enum,
        value_name = "REASON",
        help = "The reason for the revocation",
        long_help = "\
The reason for the revocation.

If the reason happened in the past, you should specify that using the \
`--time` argument.  This allows OpenPGP implementations to more \
accurately reason about artifacts whose validity depends on the validity \
of the user ID."
    )]
    pub reason: UserIDReasonForRevocation,

    #[clap(
        value_name = "MESSAGE",
        help = "A short, explanatory text",
        long_help = "\
A short, explanatory text.

The text is shown to a viewer of the revocation certificate, and \
explains why the certificate has been revoked.  For instance, if Alice \
has left the organization, it might say who to contact instead.",
    )]
    pub message: String,

    #[clap(
        long,
        value_names = &["NAME", "VALUE"],
        number_of_values = 2,
        help = "Add a notation to the certification.",
        long_help = "\
Add a notation to the certification.

A user-defined notation's name must be of the form \
`name@a.domain.you.control.org`.  If the notation's name starts with a \
`!`, then the notation is marked as being critical.  If a consumer of \
a signature doesn't understand a critical notation, then it will \
ignore the signature.  The notation is marked as being human \
readable."
    )]
    pub notation: Vec<String>,

    #[clap(
        long,
        value_name = FileOrCertStore::VALUE_NAME,
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

/// The revocation reason for a user ID
#[derive(ValueEnum, Clone, Debug)]
pub enum UserIDReasonForRevocation {
    /// The user ID is no longer valid.  This is appropriate when
    /// someone leaves an organisation, and the organisation does not
    /// have their secret key material.  For instance, if someone was
    /// part of Debian and retires, they would use this to indicate
    /// that a Debian-specific User ID is no longer valid.
    Retired,

    /// None of the other reasons apply.  OpenPGP implementations
    /// conservatively treat this type of revocation similar to a
    /// compromised key.
    Unspecified
}

impl From<UserIDReasonForRevocation> for ReasonForRevocation {
    fn from(rr: UserIDReasonForRevocation) -> Self {
        match rr {
            UserIDReasonForRevocation::Retired => ReasonForRevocation::UIDRetired,
            UserIDReasonForRevocation::Unspecified => ReasonForRevocation::Unspecified,
        }
    }
}

const USERID_STRIP_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Example(Example {
            comment: "Strip a User ID from a cert in the cert store.",
            command: &[
                "sq", "key", "userid", "strip",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--userid", "Alice <alice@example.org>",
            ],
        }),
    ]
};
test_examples!(sq_key_userid_strip, USERID_STRIP_EXAMPLES);

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
pub struct StripCommand {
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
        value_name = "USERID",
        long,
        help = "User IDs to strip",
        long_help = "The User IDs to strip.  Values must exactly match a \
User ID."
    )]
    pub userid: Vec<UserID>,
    #[clap(
        long,
        help = "Emit binary data",
    )]
    pub binary: bool,
}
