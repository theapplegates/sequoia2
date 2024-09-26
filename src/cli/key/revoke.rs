//! Command-line parser for `sq key revoke`.

use clap::Args;
use clap::ArgGroup;

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;

use crate::cli::types::ClapData;
use crate::cli::types::FileOrStdin;
use crate::cli::types::FileOrStdout;

use crate::cli::examples::*;
use crate::cli::key::KeyReasonForRevocation;

const REVOKE_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Setup(Setup {
            command: &[
                "sq", "key", "import", "alice-secret.pgp"
            ],
        }),
        Action::Example(Example {
            comment: "\
Revoke Alice's key, indicating that there is a new certificate.",
            command: &[
                "sq", "key", "revoke",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "superseded",
                "My new cert is C5999E8191BF7B503653BE958B1F7910D01F86E5",
            ],
        }),
        Action::Example(Example {
            comment: "\
Revoke the key, indicating that the secret key material was \
compromised.",
            command: &[
                "sq", "key", "revoke",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "compromised",
                "Computer attacked, secret key material compromised",
            ],
        }),
    ]
};
test_examples!(sq_key_revoke, REVOKE_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    about = "Revoke a certificate",
    long_about = "\
Revoke a certificate.

Creates a revocation certificate for a certificate.

If `--revoker` or `--revoker-file` is provided, then that key is used \
to create the revocation certificate.  If that key is different from \
the certificate that is being revoked, this results in a third-party \
revocation.  This is normally only useful if the owner of the \
certificate designated the key to be a designated revoker.

`sq key revoke` respects the reference time set by the top-level \
`--time` argument.  When set, it uses the specified time instead of \
the current time when determining what keys are valid, and it sets \
the revocation certificate's creation time to the reference time \
instead of the current time.
",
    after_help = REVOKE_EXAMPLES,
)]
#[clap(group(ArgGroup::new("cert_input").args(&["cert_file", "cert"]).required(true)))]
#[clap(group(ArgGroup::new("revoker_input").args(&["revoker_file", "revoker"])))]
pub struct Command {
    #[clap(
        long,
        value_name = "FINGERPRINT|KEYID",
        help = "The certificate to revoke",
    )]
    pub cert: Option<KeyHandle>,
    #[clap(
        long,
        value_name = "CERT_FILE",
        conflicts_with = "cert",
        help = "The certificate to revoke",
        long_help = "\
The certificate to revoke.

Read the certificate to revoke from FILE or stdin, if `-`.  It is \
an error for the file to contain more than one certificate.",
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
        value_name = "REASON",
        required = true,
        help = "The reason for the revocation",
        long_help = "\
The reason for the revocation.

If the reason happened in the past, you should specify that using the \
`--time` argument.  This allows OpenPGP implementations to more \
accurately reason about artifacts whose validity depends on the validity \
of the certificate.",
    value_enum,
    )]
    pub reason: KeyReasonForRevocation,

    #[clap(
        value_name = "MESSAGE",
        help = "A short, explanatory text",
        long_help = "\
A short, explanatory text.

The text is shown to a viewer of the revocation certificate, and \
explains why the certificate has been revoked.  For instance, if Alice \
has created a new key, she would generate a `superseded` revocation \
certificate for her old key, and might include the message `I've \
created a new certificate, $FINGERPRINT, please use that in the \
future.`",
    )]
    pub message: String,

    #[clap(
        long,
        value_names = &["NAME", "VALUE"],
        number_of_values = 2,
        help = "Add a notation to the certification",
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
