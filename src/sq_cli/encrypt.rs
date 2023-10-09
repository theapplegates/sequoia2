use std::path::PathBuf;

use clap::ArgAction::Count;
use clap::{ValueEnum, Parser};

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;

use super::types::ClapData;
use super::types::FileOrStdin;
use super::types::FileOrStdout;

#[derive(Parser, Debug)]
#[clap(
    name = "encrypt",
    about = "Encrypts a message",
    long_about =
"Encrypts a message

Encrypts a message for any number of recipients and with any number of
passwords, optionally signing the message in the process.

The converse operation is \"sq decrypt\".

\"sq encrypt\" respects the reference time set by the top-level
\"--time\" argument.  It uses the reference time when selecting
encryption keys, and it sets the signature's creation time to the
reference time.
",
    after_help =
"EXAMPLES:

# Encrypt a file using a certificate
$ sq encrypt --recipient-file romeo.pgp message.txt

# Encrypt a file creating a signature in the process
$ sq encrypt --recipient-file romeo.pgp --signer-file juliet.pgp message.txt

# Encrypt a file using a password
$ sq encrypt --symmetric message.txt
",
)]
pub struct Command {
    #[clap(
        default_value_t = FileOrStdin::default(),
        help = FileOrStdin::HELP,
        value_name = FileOrStdin::VALUE_NAME,
    )]
    pub input: FileOrStdin,
    #[clap(
        default_value_t = FileOrStdout::default(),
        help = FileOrStdout::HELP,
        long,
        short,
        value_name = FileOrStdout::VALUE_NAME,
    )]
    pub output: FileOrStdout,
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,

    #[clap(
        long = "recipient-email",
        value_name = "EMAIL",
        help = "Encrypts to all certificates that can be authenticated \
                for the specified email address",
    )]
    pub recipients_email: Vec<String>,
    #[clap(
        long = "recipient-userid",
        value_name = "USERID",
        help = "Encrypts to all certificates that can be authenticated \
                for the specified User ID",
    )]
    pub recipients_userid: Vec<String>,
    #[clap(
        long = "recipient-cert",
        value_name = "FINGERPRINT|KEYID",
        help = "Encrypts to the named certificates",
    )]
    pub recipients_cert: Vec<KeyHandle>,
    #[clap(
        long = "recipient-file",
        value_name = "CERT_RING_FILE",
        help = "Encrypts to all certificates in CERT_RING_FILE",
    )]
    pub recipients_file: Vec<PathBuf>,

    #[clap(
        long = "signer-file",
        value_name = "KEY_FILE",
        help = "Signs the message using the key in KEY_FILE",
    )]
    pub signer_key_file: Vec<PathBuf>,
    #[clap(
        long = "private-key-store",
        value_name = "KEY_STORE",
        help = "Provides parameters for private key store",
    )]
    pub private_key_store: Option<String>,
    #[clap(
        short = 's',
        long = "symmetric",
        help = "Prompts to add a password to encrypt with",
        long_help =
            "Prompts to add a password to encrypt with.  \
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
        long = "mode",
        value_name = "MODE",
        default_value_t = EncryptionMode::All,
        help = "Selects what kind of keys are considered for encryption.",
        long_help =
            "Selects what kind of keys are considered for \
            encryption.  Transport select subkeys marked \
            as suitable for transport encryption, rest \
            selects those for encrypting data at rest, \
            and all selects all encryption-capable \
            subkeys.",
        value_enum,
    )]
    pub mode: EncryptionMode,
    #[clap(
        long = "compression",
        value_name = "KIND",
        default_value_t = CompressionMode::Pad,
        help = "Selects compression scheme to use",
        value_enum,
    )]
    pub compression: CompressionMode,
    #[clap(
        long = "use-expired-subkey",
        help = "Falls back to expired encryption subkeys",
        long_help =
            "If a certificate has only expired \
            encryption-capable subkeys, falls back \
            to using the one that expired last",
    )]
    pub use_expired_subkey: bool,
}

#[derive(ValueEnum, Debug, Clone)]
pub enum EncryptionMode {
    Transport,
    Rest,
    All
}

#[derive(ValueEnum, Debug, Clone)]
pub enum CompressionMode {
    None,
    Pad,
    Zip,
    Zlib,
    Bzip2
}
