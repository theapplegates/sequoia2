//! Command-line parser for `sq key`.

use std::path::PathBuf;

use clap::{ValueEnum, Args, Parser, Subcommand};

use sequoia_openpgp as openpgp;
use openpgp::cert::CipherSuite as SqCipherSuite;
use openpgp::types::ReasonForRevocation;

use crate::cli::examples;
use examples::Action;
use examples::Actions;
use examples::Example;

pub mod approvals;
pub mod delete;
pub mod expire;
pub mod export;
pub mod generate;
pub mod list;
pub mod password;
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
    Password(password::Command),
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
