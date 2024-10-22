//! Command-line parser for `sq key`.

use std::path::PathBuf;

use clap::{ValueEnum, ArgGroup, Args, Parser, Subcommand};

use sequoia_openpgp as openpgp;
use openpgp::cert::CipherSuite as SqCipherSuite;
use openpgp::KeyHandle;
use openpgp::types::ReasonForRevocation;

use crate::cli::types::ClapData;
use crate::cli::types::EncryptPurpose;
use crate::cli::types::Expiration;
use crate::cli::types::FileOrStdin;
use crate::cli::types::FileOrStdout;

use crate::cli::examples;
use examples::Action;
use examples::Actions;
use examples::Example;
use examples::Setup;

pub mod approvals;
pub mod delete;
pub mod expire;
pub mod export;
pub mod generate;
pub mod list;
pub mod revoke;
pub mod subkey;
pub mod userid;

/// The revocation reason for a certificate or subkey
#[derive(ValueEnum, Clone, Debug)]
pub enum KeyReasonForRevocation {
    /// The secret key material may have been compromised.  Prefer
    /// this value if you suspect that the secret key has been leaked.
    Compromised,
    /// The owner of the certificate has a new certificate.  Prefer
    /// `compromised` if the secret key material has been compromised
    /// even if the certificate is also being replaced!  You should
    /// include the fingerprint of the new certificate in the message.
    Superseded,
    /// The certificate should not be used anymore, and there is no
    /// replacement.  This is appropriate when someone leaves an
    /// organisation.  Prefer `compromised` if the secret key material
    /// has been compromised even if the certificate is also being
    /// retired!  You should include how to contact the owner, or who
    /// to contact instead in the message.
    Retired,
    /// None of the other reasons apply.  OpenPGP implementations
    /// conservatively treat this type of revocation similar to a
    /// compromised key.
    Unspecified,
}

impl From<KeyReasonForRevocation> for ReasonForRevocation {
    fn from(rr: KeyReasonForRevocation) -> Self {
        match rr {
            KeyReasonForRevocation::Compromised => ReasonForRevocation::KeyCompromised,
            KeyReasonForRevocation::Superseded => ReasonForRevocation::KeySuperseded,
            KeyReasonForRevocation::Retired => ReasonForRevocation::KeyRetired,
            KeyReasonForRevocation::Unspecified => ReasonForRevocation::Unspecified,
        }
    }
}

#[derive(Parser, Debug)]
#[clap(
    name = "key",
    about = "Manage keys",
    long_about =
"Manage keys

We use the term \"key\" to refer to OpenPGP keys that do contain \
secrets.  This subcommand provides primitives to generate and \
otherwise manipulate keys.

Conversely, we use the term \"certificate\", or \"cert\" for short, to refer \
to OpenPGP keys that do not contain secrets.  See `sq cert` for operations on \
certificates.
",
    subcommand_required = true,
    arg_required_else_help = true,
)]
pub struct Command {
    #[clap(subcommand)]
    pub subcommand: Subcommands,
}

#[derive(Debug, Subcommand)]
pub enum Subcommands {
    List(list::Command),
    Generate(generate::Command),
    Import(ImportCommand),
    Export(export::Command),
    Delete(delete::Command),
    Password(PasswordCommand),
    Expire(expire::Command),
    Revoke(revoke::Command),
    #[clap(subcommand)]
    Userid(userid::Command),
    #[clap(subcommand)]
    Subkey(subkey::Command),
    #[clap(subcommand)]
    Approvals(approvals::Command),
}

#[derive(ValueEnum, Clone, Debug, Default)]
pub enum CipherSuite {
    Rsa2k,
    Rsa3k,
    Rsa4k,
    #[default]
    Cv25519
}

impl CipherSuite {

    /// Return a matching `sequoia_openpgp::cert::CipherSuite`
    pub fn as_ciphersuite(&self) -> SqCipherSuite {
        match self {
            CipherSuite::Rsa2k => SqCipherSuite::RSA2k,
            CipherSuite::Rsa3k => SqCipherSuite::RSA3k,
            CipherSuite::Rsa4k => SqCipherSuite::RSA4k,
            CipherSuite::Cv25519 => SqCipherSuite::Cv25519,
        }
    }
}

const IMPORT_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Example(Example {
            comment: "\
Import the keys into the key store.",
            command: &[
                "sq", "key", "import", "alice-secret.pgp",
            ],
        }),
    ]
};
test_examples!(sq_key_import, IMPORT_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    about = "Import keys into the key store",
    after_help = IMPORT_EXAMPLES,
)]
pub struct ImportCommand {
    #[clap(
        value_name = "KEY_FILE",
        help = "Import the keys in KEY_FILE",
    )]
    pub file: Vec<PathBuf>,
}

const PASSWORD_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Setup(Setup {
            command: &[
                "sq", "key", "import", "alice-secret.pgp"
            ],
        }),
        Action::Example(Example {
            comment: "\
Change the password for all of Alice's keys to the password in the \
specified file.",
            command: &[
                "sq", "key", "password",
                "--new-password-file", "password-file.txt",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0"
            ],
        }),
        Action::Example(Example {
            comment: "\
Clear the password protection for all of Alice's keys.",
            command: &[
                "sq", "key", "password",
                "--password-file", "password-file.txt",
                "--clear-password",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0"
            ],
        }),
    ]
};
test_examples!(sq_key_password, PASSWORD_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    name = "password",
    about = "Change the password protecting secret key material",
    long_about = "
Change the password protecting secret key material.

Secret key material can be protected by a password.  This subcommand \
changes or clears the password.

To strip the password either use `--clear` or supply a zero-length \
password when prompted for the new password.

If a key is password protected, and the correct password was not \
supplied using the `--password-file` argument, the user is \
prompted for the password.  Likewise, if the new password isn't \
provided, the user is prompted.
",
    after_help = PASSWORD_EXAMPLES,
)]
#[clap(group(ArgGroup::new("cert_input").args(&["cert_file", "cert"]).required(true)))]
pub struct PasswordCommand {
    #[clap(
        long,
        help = "Change the password of the specified certificate's keys",
        value_name = FileOrStdin::VALUE_NAME,
    )]
    pub cert: Option<KeyHandle>,
    #[clap(
        long,
        value_name = "CERT_FILE",
        help = "Change the password of the specified certificate's keys",
        long_help = "\
Change the password of the specified certificate's keys.

Read the certificate from FILE or stdin, if `-`.  It is an error \
for the file to contain more than one certificate.",
    )]
    pub cert_file: Option<FileOrStdin>,

    #[clap(
        long,
        value_name = "PASSWORD_FILE",
        help = "\
File containing password to encrypt the secret key material",
        long_help = "\
File containing password to encrypt the secret key material.

Note that the entire key file will be used as the password including \
any surrounding whitespace like a trailing newline."
    )]
    pub new_password_file: Option<PathBuf>,
    #[clap(
        long,
        help = "Clear the password protecting the secret key material",
    )]
    pub clear_password: bool,

    #[clap(
        help = FileOrStdout::HELP_OPTIONAL,
        long,
        value_name = FileOrStdout::VALUE_NAME,
        conflicts_with = "cert",
    )]
    pub output: Option<FileOrStdout>,
    #[clap(
        long,
        requires = "output",
        help = "Emit binary data",
    )]
    pub binary: bool,
}
