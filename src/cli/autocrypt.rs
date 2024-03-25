use std::path::PathBuf;

use clap::{ValueEnum, Args, Parser, Subcommand};

use super::types::ClapData;
use super::types::FileOrStdin;
use super::types::FileOrStdout;
use super::types::SessionKey;

#[derive(Parser, Debug)]
#[clap(
    name = "autocrypt",
    about = "Communicate certificates using Autocrypt",
    long_about = "Communicate certificates using Autocrypt

Autocrypt is a standard for mail user agents to provide convenient
end-to-end encryption of emails.  This subcommand provides a limited
way to produce and consume headers that are used by Autocrypt to
communicate certificates between clients.

See <https://autocrypt.org/>.
",
    subcommand_required = true,
    arg_required_else_help = true
)]
pub struct Command {
    #[clap(subcommand)]
    pub subcommand: Subcommands,
}

#[derive(Debug, Subcommand)]
pub enum Subcommands {
    Import(ImportCommand),
    Decode(DecodeCommand),

    EncodeSender(EncodeSenderCommand),
}

#[derive(Debug, Args)]
#[clap(
    about = "Import Autocrypt-encoded certificates",
    long_about = "Import Autocrypt-encoded certificates

Given a mail containing autocrypt headers (or an key-gossip headers),
this command extracts and imports the certificates encoded within it.
",
    after_help = "EXAMPLES:

# Imports all certificates from a mail
$ sq autocrypt import autocrypt.eml
"
)]
pub struct ImportCommand {
    #[clap(
        long = "recipient-file",
        value_name = "KEY_FILE",
        help = "Decrypt the message using the key in KEY_FILE",
    )]
    pub secret_key_file: Vec<PathBuf>,

    #[clap(
        long = "session-key",
        value_name = "SESSION-KEY",
        help = "Decrypt an encrypted message using SESSION-KEY",
    )]
    pub session_key: Vec<SessionKey>,

    #[clap(
        default_value_t = FileOrStdin::default(),
        help = FileOrStdin::HELP_OPTIONAL,
        value_name = FileOrStdin::VALUE_NAME,
    )]
    pub input: FileOrStdin,
}

#[derive(Debug, Args)]
#[clap(
    about = "Read Autocrypt-encoded certificates",
    long_about = "Read Autocrypt-encoded certificates

Given an autocrypt header (or an key-gossip header), this command
extracts the certificate encoded within it.

The converse operation is `sq autocrypt encode-sender`.
",
    after_help = "EXAMPLES:

# Extract all certificates from a mail
$ sq autocrypt decode autocrypt.eml
"
)]
pub struct DecodeCommand {
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
    #[clap(short = 'B', long, help = "Emit binary data")]
    pub binary: bool,
}

//#[derive(Subcommand)]
#[derive(Debug, Args)]
#[clap(
    name = "encode-sender",
    about = "Encode a certificate into an Autocrypt header",
    long_about = "Encode a certificate into an Autocrypt header

A certificate can be encoded and included in a header of an email
message.  This command encodes the certificate, adds the senders email
address (which must match the one used in the `From` header), and the
senders `prefer-encrypt` state (see the Autocrypt spec for more
information).

The converse operation is `sq autocrypt decode`.
",
    after_help = "EXAMPLES:

# Encodes a certificate
$ sq autocrypt encode-sender juliet.pgp

# Encodes a certificate with an explicit sender address
$ sq autocrypt encode-sender --email juliet@example.org juliet.pgp

# Encodes a certificate while indicating the willingness to encrypt
$ sq autocrypt encode-sender --prefer-encrypt mutual juliet.pgp
"
)]
pub struct EncodeSenderCommand {
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
    // TODO the help message looks like "primary userid" might be the default
    // email. clarify
    #[clap(
        long = "email",
        value_name = "ADDRESS",
        help = "Set the address [default: primary userid]"
    )]
    pub address: Option<String>,
    #[clap(
            long = "prefer-encrypt",
            value_name = "PREFER-ENCRYPT",
            default_value_t = PreferEncryptArgs::NoPreference,
            help = "Set the prefer-encrypt attribute",
            value_enum,
        )]
    pub prefer_encrypt: PreferEncryptArgs,
}

#[derive(ValueEnum, Debug, Clone)]
pub enum PreferEncryptArgs {
    #[clap(name = "nopreference")]
    NoPreference,
    Mutual,
}

impl std::fmt::Display for PreferEncryptArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PreferEncryptArgs::Mutual => write!(f, "mutual"),
            PreferEncryptArgs::NoPreference => write!(f, "nopreference"),
        }
    }
}
