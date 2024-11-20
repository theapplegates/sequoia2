//! Command-line parser for `sq encrypt`.

use clap::{ValueEnum, Parser};

use super::types::ClapData;
use super::types::EncryptPurpose;
use super::types::FileOrStdin;
use super::types::FileOrStdout;

use crate::cli::types::CertDesignators;
use crate::cli::types::cert_designator::*;

use crate::cli::examples;
use examples::*;

const ENCRYPT_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Setup(Setup {
            command: &[
                "sq", "pki", "link", "add",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--email", "alice@example.org",
            ],
        }),
        Action::Example(Example {
            comment: "\
Encrypt a file for a recipient given by fingerprint.",
            command: &[
                "sq", "encrypt",
                "--for", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "document.txt",
            ],
        }),
        Action::Example(Example {
            comment: "\
Encrypt a file for a recipient given by email.",
            command: &[
                "sq", "encrypt", "--for-email", "alice@example.org",
                "document.txt",
            ],
        }),
    ]
};
test_examples!(sq_encrypt, ENCRYPT_EXAMPLES);

#[derive(Parser, Debug)]
#[clap(
    name = "encrypt",
    about = "Encrypt a message",
    long_about =
"Encrypt a message

Encrypt a message for any number of recipients and with any number of \
passwords, optionally signing the message in the process.

The converse operation is `sq decrypt`.

`sq encrypt` respects the reference time set by the top-level \
`--time` argument.  It uses the reference time when selecting \
encryption keys, and it sets the signature's creation time to the \
reference time.
",
    after_help = ENCRYPT_EXAMPLES,
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
        value_name = FileOrStdout::VALUE_NAME,
    )]
    pub output: FileOrStdout,
    #[clap(
        long,
        help = "Emit binary data",
    )]
    pub binary: bool,

    #[command(flatten)]
    pub recipients: CertDesignators<CertUserIDEmailFileWithPasswordArgs,
                                    RecipientPrefix>,

    #[clap(
        help = "Set the filename of the encrypted file as metadata",
        long = "set-metadata-filename",
        long_help =
            "Set the filename of the encrypted file as metadata.  \
            Do note, that this metadata is not signed and as such relying on \
            it - on sender or receiver side - is generally considered \
            dangerous.",
    )]
    pub set_metadata_filename: Option<String>,

    #[command(flatten)]
    pub signers: CertDesignators<CertUserIDEmailFileArgs,
                                 SignerPrefix,
                                 OptionalValue,
                                 SignerDoc>,


    #[clap(
        long = "signature-notation",
        value_names = &["NAME", "VALUE"],
        number_of_values = 2,
        help = "Add a notation to the signature.",
        long_help = "Add a notation to the signature.  \
            A user-defined notation's name must be of the form \
            `name@a.domain.you.control.org`. If the notation's name starts \
            with a `!`, then the notation is marked as being critical.  If a \
            consumer of a signature doesn't understand a critical notation, \
            then it will ignore the signature.  The notation is marked as \
            being human readable.",
    )]
    pub signature_notations: Vec<String>,

    #[clap(
        long = "encrypt-for",
        value_name = "PURPOSE",
        default_value_t = EncryptPurpose::Universal,
        help = "Select what kind of keys are considered for encryption.",
        long_help =
            "Select what kind of keys are considered for \
            encryption.  'transport' selects subkeys marked \
            as suitable for transport encryption, 'storage' \
            selects those for encrypting data at rest, \
            and 'universal' selects all encryption-capable \
            subkeys.",
        value_enum,
    )]
    pub mode: EncryptPurpose,

    #[clap(
        long = "compression",
        value_name = "KIND",
        default_value_t = CompressionMode::None,
        help = "Select compression scheme to use",
        value_enum,
    )]
    pub compression: CompressionMode,
    #[clap(
        long = "use-expired-subkey",
        help = "Fall back to expired encryption subkeys",
        long_help =
            "If a certificate has only expired \
            encryption-capable subkeys, fall back \
            to using the one that expired last",
    )]
    pub use_expired_subkey: bool,
}

/// Documentation for signer arguments.
pub struct SignerDoc {}
impl AdditionalDocs for SignerDoc {
    fn help(arg: &'static str, help: &'static str) -> clap::builder::StyledStr {
        match arg {
            "file" =>
                "Sign the message using the key read from PATH"
                .into(),
            _ => {
                debug_assert!(help.starts_with("Use certificates"));
                help.replace("Use certificates",
                             "Sign the message using the key")
                    .into()
            },
        }
    }
}

#[derive(ValueEnum, Debug, Clone)]
pub enum CompressionMode {
    None,
    #[cfg(all(unix, not(unix)))] // Bottom, but: `cfg` predicate key cannot be a literal
    Pad,
    Zip,
    Zlib,
    Bzip2
}
