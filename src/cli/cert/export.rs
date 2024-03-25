use clap::Parser;

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;

use crate::cli::examples;
use examples::Action;
use examples::Actions;
use examples::Example;

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::Example(Example {
            comment: "Export all certificates.",
            command: &[
                "sq", "cert", "export", "--all",
            ],
        }),
        Action::Example(Example {
            comment: "\
Export certificates with a matching User ID packet.  The binding \
signatures are checked, but the User IDs are not authenticated. \
Note: this check is case sensitive.",
            command: &[
                "sq", "cert", "export",
                "--userid", "Alice <alice@example.org>",
            ],
        }),
        Action::Example(Example {
            comment: "\
Export certificates with a User ID containing the email address. \
The binding signatures are checked, but the User IDs are not \
authenticated.  Note: this check is case insensitive.",
            command: &[
                "sq", "cert", "export", "--email", "alice@example.org",
            ],
        }),
        Action::Example(Example {
            comment: "\
Export certificates where the certificate (i.e., the primary key) \
has the specified Key ID.",
            command: &[
                "sq", "cert", "export", "--cert", "6F0073F60FD0CBF0",
            ],
        }),
        Action::Example(Example {
            comment: "\
Export certificates where the primary key or a subkey matches the \
specified Key ID.",
            command: &[
                "sq", "cert", "export", "--key", "24F3955B0B8DECC8",
            ],
        }),
        Action::Example(Example {
            comment: "\
Export certificates that contain a User ID with *either* (not both!) \
email address.  Note: this check is case insensitive.",
            command: &[
                "sq", "cert", "export",
                "--email", "alice@example.org",
                "--email", "bob@example.org",
            ],
        }),
    ],
};

test_examples!(sq_cert_export, EXAMPLES);


#[derive(Parser, Debug)]
#[clap(
    name = "export",
    about = "Export certificates from the local certificate store",
    long_about =
"Export certificates from the local certificate store

If multiple predicates are specified a certificate is returned if
at least one of them matches.

This does not check the authenticity of the certificates in anyway.
Before using the certificates, be sure to validate and authenticate
them.

When matching on subkeys or User IDs, the component must have a valid
self signature according to the policy.  This is not the case when
matching the certificate's key handle using `--cert` or when exporting
all certificates.

Fails if search criteria are specified and none of them matches any
certificates.  Note: this means if the certificate store is empty and
no search criteria are specified, then this will return success.",
    after_help = EXAMPLES,
)]
pub struct Command {
    #[clap(
        short = 'B',
        long,
        help = "Emit binary data",
    )]
    pub binary: bool,

    #[clap(
        long,
        conflicts_with_all = [
            "cert", "key", "userid", "grep", "email", "domain", "query",
        ],
        help = "Export all certificates",
    )]
    pub all: bool,

    #[clap(
        long = "cert",
        value_name = "FINGERPRINT|KEYID",
        help = "Return certificates that \
                have the specified fingerprint or key ID",
    )]
    pub cert: Vec<KeyHandle>,

    #[clap(
        long = "key",
        value_name = "FINGERPRINT|KEYID",
        help = "Return certificates where the primary key or \
                a subkey has the specified fingerprint or key ID",
    )]
    pub key: Vec<KeyHandle>,

    #[clap(
        long = "userid",
        value_name = "USERID",
        help = "Return certificates that have a User ID that \
                matches exactly, including case",
    )]
    pub userid: Vec<String>,

    #[clap(
        long = "grep",
        value_name = "PATTERN",
        help = "Return certificates that have a User ID that \
                contains the string, case insensitively",
    )]
    pub grep: Vec<String>,

    #[clap(
        long = "email",
        value_name = "EMAIL",
        help = "Return certificates that have a User ID with \
                the specified email address, case insensitively",
    )]
    pub email: Vec<String>,

    #[clap(
        long = "domain",
        value_name = "DOMAIN",
        help = "Return certificates that have a User ID with \
                an email address from the specified domain",
    )]
    pub domain: Vec<String>,

    #[clap(
        value_name = "QUERY",
        help = "Return certificates matching QUERY. \
                This may be a subkey fingerprint or key ID, \
                an email address, or an User ID fragment.",
    )]
    pub query: Vec<String>,
}
