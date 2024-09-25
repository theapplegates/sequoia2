//! Command-line parser for `sq encrypt`.

use std::path::PathBuf;

use clap::ArgAction::Count;
use clap::{ValueEnum, Parser};

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;

use super::types::ClapData;
use super::types::EncryptPurpose;
use super::types::MetadataTime;
use super::types::FileOrStdin;
use super::types::FileOrStdout;

use crate::cli::types::CertDesignators;
use crate::cli::types::cert_designator::CertUserIDEmailFileArgs;
use crate::cli::types::cert_designator::RecipientPrefix;

use crate::cli::examples;
use examples::*;

const ENCRYPT_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Setup(Setup {
            command: &[
                "sq", "pki", "link", "add",
                "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--email", "alice@example.org",
            ],
        }),
        Action::Example(Example {
            comment: "\
Encrypt a file for a recipient given by email.",
            command: &[
                "sq", "encrypt", "--recipient-email", "alice@example.org",
                "document.txt",
            ],
        }),

        Action::Example(Example {
            comment: "\
Encrypt a file using a certificate.",
            command: &[
                "sq", "encrypt", "--recipient-file", "romeo.pgp", "document.txt",
            ],
        }),
        Action::Example(Example {
            comment: "\
Encrypt a file creating a signature in the process.",
            command: &[
                "sq", "encrypt", "--recipient-file", "romeo.pgp",
                "--signer-file", "juliet-secret.pgp", "document.txt",
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

Encrypt a message for any number of recipients and with any number of
passwords, optionally signing the message in the process.

The converse operation is `sq decrypt`.

`sq encrypt` respects the reference time set by the top-level
`--time` argument.  It uses the reference time when selecting
encryption keys, and it sets the signature's creation time to the
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
    pub recipients: CertDesignators<CertUserIDEmailFileArgs, RecipientPrefix>,

    #[clap(
        help = "Set the filename of the encrypted file as metadata",
        long,
        long_help =
            "Set the filename of the encrypted file as metadata.  \
            Do note, that this metadata is not signed and as such relying on \
            it - on sender or receiver side - is generally considered \
            dangerous.",
    )]
    pub set_metadata_filename: bool,
    #[clap(
        default_value_t = MetadataTime::default(),
        help = "Set time for encrypted file as metadata",
        long,
        long_help = format!(
            "Set time for encrypted file as metadata.  \
            Allows setting TIME either as ISO 8601 formatted string or by \
            providing custom keywords.  \
            With `{}`, the metadata is not set.  \
            With `{}`, the metadata is set to the file's creation \
            timestamp.  \
            With `{}`, the metadata is set to the file's last \
            modification timestamp.  \
            With `{}`, the metadata is set to the creation \
            timestamp of the message for which the metadata is added.  \
            Do note, that this metadata is not signed and as such relying on \
            it - on sender or receiver side - is generally considered \
            dangerous.",
            MetadataTime::None,
            MetadataTime::FileCreation,
            MetadataTime::FileModification,
            MetadataTime::MessageCreation,
        ),
        value_name = "TIME",
    )]
    pub set_metadata_time: MetadataTime,

    #[clap(
        long = "signer-file",
        value_name = "KEY_FILE",
        help = "Sign the message using the key in KEY_FILE",
    )]
    pub signer_key_file: Vec<PathBuf>,
    #[clap(
        long = "signer-key",
        value_name = "KEYID|FINGERPRINT",
        help = "Sign the message using the specified key on the key store",
    )]
    pub signer_key: Vec<KeyHandle>,

    #[clap(
        long = "with-password",
        help = "Prompt to add a password to encrypt with",
        long_help =
            "Prompt to add a password to encrypt with.  \
            When using this option, the user is asked to provide a password, \
            which is used to encrypt the message. \
            This option can be provided more than once to provide more than \
            one password. \
            The encrypted data can afterwards be decrypted with either one of \
            the recipient's keys, or one of the provided passwords.",
        action = Count,
    )]
    pub symmetric: u8,

    #[clap(
        long = "with-password-file",
        value_name = "PASSWORD_FILE",
        help = "\
File containing password to encrypt the secret key material",
        long_help = "\
File containing password to encrypt the secret key material.

Note that the entire key file will be used as the password including \
any surrounding whitespace like a trailing newline.

This option can be provided more than once to provide more than \
one password. \
The encrypted data can afterwards be decrypted with either one of \
the recipient's keys, or one of the provided passwords.",
    )]
    pub symmetric_password_file: Vec<PathBuf>,


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

#[derive(ValueEnum, Debug, Clone)]
pub enum CompressionMode {
    None,
    #[cfg(all(unix, not(unix)))] // Bottom, but: `cfg` predicate key cannot be a literal
    Pad,
    Zip,
    Zlib,
    Bzip2
}
