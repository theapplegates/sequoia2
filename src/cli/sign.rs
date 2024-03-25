//! Command-line parser for `sq sign`.

use std::path::PathBuf;

use clap::Parser;

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;

use super::types::ClapData;
use super::types::FileOrStdin;
use super::types::FileOrStdout;

#[derive(Parser, Debug)]
#[clap(
    name = "sign",
    about = "Sign messages or data files",
    long_about =
"Sign messages or data files

Creates signed messages or detached signatures.  Detached signatures
are often used to sign software packages.

The converse operation is `sq verify`.

`sq sign` respects the reference time set by the top-level \
`--time` argument.  When set, it uses the specified time instead of \
the current time, when determining what keys are valid, and it sets \
the signature's creation time to the reference time instead of the \
current time.
",
    after_help =
"EXAMPLES:

# Create a signed message
$ sq sign --signer-file juliet.pgp message.txt

# Create a detached signature
$ sq sign --detached --signer-file juliet.pgp message.txt

# Create a signature with the specified creation time
$ sq sign --time 20020304 --detached --signer-file juliet.pgp \\
     message.txt
",
    )]
pub struct Command {
    #[clap(
        default_value_t = FileOrStdin::default(),
        help = FileOrStdin::HELP_OPTIONAL,
        value_name = FileOrStdin::VALUE_NAME,
    )]
    pub input: FileOrStdin,
    #[clap(
        default_value_t = FileOrStdout::default(),
        help = FileOrStdout::HELP_OPTIONAL,
        long,
        short,
        value_name = FileOrStdout::VALUE_NAME,
    )]
    pub output: FileOrStdout,
    // TODO: Why capital B?
    #[clap(
        short = 'B',
        long,
        help = "Emit binary data",
    )]
    pub binary: bool,
    #[clap(
        long = "private-key-store",
        value_name = "KEY_STORE",
        help = "Provide parameters for private key store",
    )]
    pub private_key_store: Option<String>,
    #[clap(
        long,
        help = "Create a detached signature",
    )]
    pub detached: bool,
    #[clap(
        long = "cleartext-signature",
        help = "Create a cleartext signature",
        conflicts_with_all = &[
            "detached",
            "append",
            "notarize",
            "binary",
        ],
    )]
    pub clearsign: bool,
    #[clap(
        short,
        long,
        conflicts_with = "notarize",
        help = "Append a signature to existing signature",
    )]
    pub append: bool,
    #[clap(
        hide = true,
        short,
        long,
        conflicts_with = "append",
        help = "Sign a message and all existing signatures",
    )]
    pub notarize: bool,
    #[clap(
        long,
        value_name = "SIGNED-MESSAGE",
        conflicts_with_all = &[
            "append",
            "detached",
            "clearsign",
            "notarize",
            "secret_key_file",
        ],
        help = "Merge signatures from the input and SIGNED-MESSAGE",
    )]
    pub merge: Option<PathBuf>,
    #[clap(
        long = "signer-file",
        value_name = "KEY_FILE",
        help = "Sign the message using the key in KEY_FILE",
    )]
    pub secret_key_file: Vec<PathBuf>,
    #[clap(
        long = "signer-key",
        value_name = "KEYID|FINGERPRINT",
        help = "Sign the message using the specified key on the key store",
    )]
    pub signer_key: Vec<KeyHandle>,
    #[clap(
        long,
        value_names = &["NAME", "VALUE"],
        number_of_values = 2,
        help = "Add a notation to the certification.",
        conflicts_with = "merge",
        long_help = "Add a notation to the certification.  \
            A user-defined notation's name must be of the form \
            `name@a.domain.you.control.org`. If the notation's name starts \
            with a `!`, then the notation is marked as being critical.  If a \
            consumer of a signature doesn't understand a critical notation, \
            then it will ignore the signature.  The notation is marked as \
            being human readable."
    )]
    // TODO: Is there a better way to express that one notation consists of two arguments, and
    // there may be multiple notations? Like something like Vec<(String, String)>.
    // TODO: Also, no need for the Option
    pub notation: Vec<String>,
}
