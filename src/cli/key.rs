//! Command-line parser for `sq key`.

use std::path::PathBuf;

use clap::{ValueEnum, ArgGroup, Args, Parser, Subcommand};

use sequoia_openpgp as openpgp;
use openpgp::cert::CipherSuite as SqCipherSuite;
use openpgp::KeyHandle;
use openpgp::packet::UserID;
use openpgp::types::ReasonForRevocation;

use crate::cli::KEY_VALIDITY_DURATION;
use crate::cli::KEY_VALIDITY_IN_YEARS;
use crate::cli::types::ClapData;
use crate::cli::types::EncryptPurpose;
use crate::cli::types::Expiration;
use crate::cli::types::FileOrCertStore;
use crate::cli::types::FileOrStdin;
use crate::cli::types::FileOrStdout;
use crate::cli::types::Time;

use crate::cli::examples;
use examples::Action;
use examples::Actions;
use examples::Example;

pub mod expire;

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

/// The revocation reason for a UserID
#[derive(ValueEnum, Clone, Debug)]
pub enum UserIDReasonForRevocation {
    Retired,
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
#[derive(Parser, Debug)]
#[clap(
    name = "key",
    about = "Manage keys",
    long_about =
"Manage keys

We use the term \"key\" to refer to OpenPGP keys that do contain
secrets.  This subcommand provides primitives to generate and
otherwise manipulate keys.

Conversely, we use the term \"certificate\", or \"cert\" for short, to refer
to OpenPGP keys that do not contain secrets.  See `sq toolbox keyring` for
operations on certificates.
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
    List(ListCommand),
    Generate(GenerateCommand),
    Import(ImportCommand),
    Export(ExportCommand),
    Delete(DeleteCommand),
    Password(PasswordCommand),
    Expire(expire::Command),
    Revoke(RevokeCommand),
    #[clap(subcommand)]
    Userid(UseridCommand),
    #[clap(subcommand)]
    Subkey(SubkeyCommand),
    AttestCertifications(AttestCertificationsCommand),
    Adopt(AdoptCommand),
}

const LIST_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Example(Example {
            comment: "\
List the keys managed by the keystore server.",
            command: &[
                "sq", "key", "list",
            ],
        }),
    ]
};
test_examples!(sq_key_list, LIST_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    about = "List keys managed by the key store",
    after_help = LIST_EXAMPLES,
)]
pub struct ListCommand {
}

const GENERATE_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Example(Example {
            comment: "\
Generate a key, and save it on the key store.",
            command: &[
                "sq", "key", "generate",
                "--userid", "Alice <alice@example.org>",
            ],
        }),
        Action::Example(Example {
            comment: "\
Generate a key, and save it in a file instead of in the key store.",
            command: &[
                "sq", "key", "generate",
                "--userid", "Alice <alice@example.org>",
                "--output", "alice-priv.pgp",
            ],
        }),
        Action::Example(Example {
            comment: "\
Strip the secret key material from the new key.",
            command: &[
                "sq", "toolbox", "extract-cert",
                "alice-priv.pgp",
                "--output", "alice.pgp",
            ],
        }),
    ]
};
test_examples!(sq_key_generate, GENERATE_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    about = "Generate a new key",
    long_about = format!(
"Generate a new key

Generating a key is the prerequisite to receiving encrypted messages \
and creating signatures.  There are a few parameters to this process, \
but we provide reasonable defaults for most users.

When generating a key, we also generate an emergency revocation \
certificate. This can be used in case the key is lost or compromised.  \
It is saved alongside the key.  This can be changed using the \
`--rev-cert` argument.

By default a key expires after {} years.  This can be changed using \
the `--expiration` argument.

`sq key generate` respects the reference time set by the top-level \
`--time` argument.  It sets the creation time of the primary key, any \
subkeys, and the binding signatures to the reference time.
",
        KEY_VALIDITY_IN_YEARS,
    ),
    after_help = GENERATE_EXAMPLES,
)]
#[clap(group(ArgGroup::new("cap-sign").args(&["can_sign", "cannot_sign"])))]
#[clap(group(ArgGroup::new("cap-authenticate").args(&["can_authenticate", "cannot_authenticate"])))]
#[clap(group(ArgGroup::new("cap-encrypt").args(&["can_encrypt", "cannot_encrypt"])))]
#[clap(group(ArgGroup::new("cert-userid").args(&["userid", "no_userids"]).required(true)))]
pub struct GenerateCommand {
    #[clap(
        short = 'u',
        long = "userid",
        value_name = "USERID",
        help = "Add a user ID to the key"
    )]
    pub userid: Vec<UserID>,
    #[clap(
        long = "allow-non-canonical-userids",
        help = "Don't reject user IDs that are not in canonical form",
        long_help = "\
Don't reject user IDs that are not in canonical form.

Canonical user IDs are of the form `Name (Comment) \
<localpart@example.org>`.",

    )]
    pub allow_non_canonical_userids: bool,
    #[clap(
        long = "no-userids",
        help = "Create a key without any user IDs",
        conflicts_with = "userid",
    )]
    pub no_userids: bool,
    #[clap(
        short = 'c',
        long = "cipher-suite",
        value_name = "CIPHER-SUITE",
        default_value_t = CipherSuite::Cv25519,
        help = "Select the cryptographic algorithms for the key",
        value_enum,
    )]
    pub cipher_suite: CipherSuite,
    #[clap(
        long = "with-password",
        help = "Protect the secret key material with a password",
    )]
    pub with_password: bool,
    #[clap(
        long = "expiration",
        value_name = "EXPIRATION",
        default_value_t = Expiration::Duration(KEY_VALIDITY_DURATION),
        help =
            "Sets the certificate's expiration time",
        long_help = "\
Sets the certificate's expiration time.

EXPIRATION is either an ISO 8601 formatted string or a custom duration, \
which takes the form `N[ymwds]`, where the letters stand for years, \
months, weeks, days, and seconds, respectively.  Alternatively, the \
keyword `never` does not set an expiration time.

When using an ISO 8601 formatted string, the validity period is from \
the certificate's creation time to the specified time.  When using a \
duration, the validity period is from the certificate's creation time \
for the specified duration.",
    )]
    pub expiration: Expiration,
    #[clap(
        long = "can-sign",
        help ="Add a signing-capable subkey (default)",
    )]
    pub can_sign: bool,
    #[clap(
        long = "cannot-sign",
        help = "Don't add a signing-capable subkey",
    )]
    pub cannot_sign: bool,
    #[clap(
        long = "can-authenticate",
        help = "Add an authentication-capable subkey (default)",
    )]
    pub can_authenticate: bool,
    #[clap(
        long = "cannot-authenticate",
        help = "Don't add an authentication-capable subkey",
    )]
    pub cannot_authenticate: bool,
    #[clap(
        long = "can-encrypt",
        value_name = "PURPOSE",
        help = "Add an encryption-capable subkey [default: universal]",
        long_help = "\
Add an encryption-capable subkey.

Encryption-capable subkeys can be marked as suitable for transport \
encryption, storage encryption, or both, i.e., universal.  [default: \
universal]",
        value_enum,
    )]
    pub can_encrypt: Option<EncryptPurpose>,
    #[clap(
        long = "cannot-encrypt",
        help = "Don't add an encryption-capable subkey",
    )]
    pub cannot_encrypt: bool,
    #[clap(
        long,
        short,
        value_name = FileOrStdout::VALUE_NAME,
        help = "Write the key to the specified file",
        long_help = "\
Write the key to the specified file.

When not specified, the key is saved on the key store.",
    )]
    pub output: Option<FileOrStdout>,
    #[clap(
        long = "rev-cert",
        value_name = "FILE",
        help = "Write the emergency revocation certificate to FILE",
        long_help = format!("\
Write the emergency revocation certificate to FILE.

When the key is stored on the key store, the revocation certificate is \
stored in {} by default.

When `--output` is specified, the revocation certificate is written to \
`FILE.rev` by default.

If `--output` is `-`, then this option must be provided.",
            sequoia_directories::Home::default()
            .map(|home| {
                let p = home.data_dir(sequoia_directories::Component::Other(
                    "revocation-certificates".into()));
                let p = p.display().to_string();
                if let Some(home) = dirs::home_dir() {
                    let home = home.display().to_string();
                    if let Some(rest) = p.strip_prefix(&home) {
                        return format!("$HOME{}", rest);
                    }
                }
                p
            })
            .unwrap_or("<unknown>".to_string()))
    )]
    pub rev_cert: Option<PathBuf>
}

#[derive(ValueEnum, Clone, Debug)]
pub enum CipherSuite {
    Rsa3k,
    Rsa4k,
    Cv25519
}

impl CipherSuite {

    /// Return a matching `sequoia_openpgp::cert::CipherSuite`
    pub fn as_ciphersuite(&self) -> SqCipherSuite {
        match self {
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

const EXPORT_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Example(Example {
            comment: "\
Import a certificate.",
            command: &[
                "sq", "key", "import", "alice-secret.pgp",
            ],
        }),
        Action::Example(Example {
            comment: "\
Export Alice's certificate with all available secret key material.",
            command: &[
                "sq", "key", "export",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            ],
        }),
        Action::Example(Example {
            comment: "\
Export Alice's signing-capable and encryption-capable subkeys, but not \
her primary key or her authentication-capable subkey.",
            command: &[
                "sq", "key", "export",
                "--key", "42020B87D51877E5AF8D272124F3955B0B8DECC8",
                "--key", "74DCDEAF17D9B995679EB52BA6E65EA2C8497728",
            ],
        }),
    ]
};
test_examples!(sq_key_export, EXPORT_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    about = "Export keys from the key store",
    after_help = EXPORT_EXAMPLES,
)]
#[clap(group(ArgGroup::new("export").args(&["cert", "key"])))]
pub struct ExportCommand {
    #[clap(
        long,
        value_name = "FINGERPRINT|KEYID",
        help = "Export the specified certificate with its secret key material",
        long_help = "\
Export the specified certificate with its secret key material.

Iterate over the specified certificate's primary key and subkeys and \
export any keys with secret key material.  An error is returned if \
the certificate does not contain any secret key material.",
    )]
    pub cert: Vec<KeyHandle>,

    #[clap(
        long,
        value_name = "FINGERPRINT|KEYID",
        help = "\
Export the secret key material for the specified key, and its certificate",
        long_help = "\
Export the specified key.

The entire certificate is exported, but only the specified key's \
secret key material is exported.  An error is returned if the secret \
key material for the specified key is not available.",
    )]
    pub key: Vec<KeyHandle>,
}

const DELETE_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Example(Example {
            comment: "\
Import Alice's key.",
            command: &[
                "sq", "key", "import", "alice-secret.pgp",
            ],
        }),
        Action::Example(Example {
            comment: "\
Delete any secret key associated with the certificate.",
            command: &[
                "sq", "key", "delete",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            ],
        }),
    ]
};
test_examples!(sq_key_delete, DELETE_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    name = "delete",
    about = "Delete a certificate's secret key material",
    after_help = DELETE_EXAMPLES,
)]
#[clap(group(ArgGroup::new("cert_input").args(&["cert_file", "cert"]).required(true)))]
pub struct DeleteCommand {
    #[clap(
        long,
        help = "Delete the secret key material from the specified certificate",
        value_name = FileOrStdin::VALUE_NAME,
    )]
    pub cert: Option<KeyHandle>,
    #[clap(
        long,
        value_name = "CERT_FILE",
        help = "Delete the secret key material from the specified certificate",
        long_help = "\
Delete the secret key material from the specified certificate.

Read the certificate from FILE or stdin, if `-`.  It is an error \
for the file to contain more than one certificate.",
    )]
    pub cert_file: Option<FileOrStdin>,

    #[clap(
        long,
        short,
        value_name = FileOrStdout::VALUE_NAME,
        conflicts_with = "cert",
        help = "Write the stripped certificate to the specified file",
    )]
    pub output: Option<FileOrStdout>,

    #[clap(
        short = 'B',
        long,
        help = "Emit binary data",
    )]
    pub binary: bool,
}

const PASSWORD_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Example(Example {
            comment: "\
Import a key that has no password protection.",
            command: &[
                "sq", "key", "import", "alice-secret.pgp"
            ],
        }),
        Action::Example(Example {
            comment: "\
Change the password for all keys to password in the specified file.",
            command: &[
                "sq", "key", "password",
                "--new-password-file", "password-file.txt",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0"
            ],
        }),
        Action::Example(Example {
            comment: "\
Clear the password protection.",
            command: &[
                "sq", "key", "password",
                "--old-password-file", "password-file.txt",
                "--clear",
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
supplied using the `--old-password-file` argument, the user is \
prompted for the password.  Likewise, if the new password isn't \
provided, the user is prompted.",
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
File containing password to decrypt the secret key material",
        long_help = "\
File containing password to decrypt the secret key material.

Note that the entire key file will be used as the password, including \
any surrounding whitespace like a trailing newline."
    )]
    pub old_password_file: Vec<PathBuf>,
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
    pub clear: bool,

    #[clap(
        help = FileOrStdout::HELP_OPTIONAL,
        long,
        short,
        value_name = FileOrStdout::VALUE_NAME,
        conflicts_with = "cert",
    )]
    pub output: Option<FileOrStdout>,
    #[clap(
        short = 'B',
        long,
        help = "Emit binary data",
    )]
    pub binary: bool,
}

const REVOKE_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Example(Example {
            comment: "\
Import a key.",
            command: &[
                "sq", "key", "import", "alice-secret.pgp"
            ],
        }),
        Action::Example(Example {
            comment: "\
Revoke the key, indicating that there is a new certificate.",
            command: &[
                "sq", "key", "revoke",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "superseded",
                "My new cert is 31EC6A9453BC59F1239C785E4CA79EF01933A2ED",
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
instead of the current time.",
    after_help = REVOKE_EXAMPLES,
)]
#[clap(group(ArgGroup::new("cert_input").args(&["cert_file", "cert"]).required(true)))]
#[clap(group(ArgGroup::new("revoker_input").args(&["revoker_file", "revoker"])))]
pub struct RevokeCommand {
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
        short,
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
        short = 'B',
        long,
        help = "Emit binary data",
    )]
    pub binary: bool,
}

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
pub enum UseridCommand {
    Add(UseridAddCommand),
    Revoke(UseridRevokeCommand),
    Strip(UseridStripCommand),
}

const USERID_ADD_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Example(Example {
            comment: "\
Import a key.",
            command: &[
                "sq", "key", "import", "alice-secret.pgp"
            ],
        }),
        Action::Example(Example {
            comment: "\
Add a new user ID.",
            command: &[
                "sq", "key", "userid", "add",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--userid", "Alice <alice@work.example.com>",
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

`sq userid add` respects the reference time set by the top-level \
`--time` argument.  It sets the creation time of the user ID's \
binding signature to the specified time.
",
    after_help = USERID_ADD_EXAMPLES,
)]
#[clap(group(ArgGroup::new("cert_input").args(&["cert_file", "cert"]).required(true)))]
pub struct UseridAddCommand {
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
        long,
        value_name = "USERID",
        required = true,
        help = "User ID to add",
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
        short,
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
        short = 'B',
        long,
        help = "Emit binary data",
    )]
    pub binary: bool,
}

#[derive(Debug, Args)]
#[clap(
    about = "Revoke a User ID",
    long_about =
"Revoke a User ID

Creates a revocation certificate for a User ID.

If `--revocation-key` is provided, then that key is used to create \
the signature.  If that key is different from the certificate being \
revoked, this creates a third-party revocation.  This is normally only \
useful if the owner of the certificate designated the key to be a \
designated revoker.

If `--revocation-key` is not provided, then the certificate must \
include a certification-capable key.

`sq key userid revoke` respects the reference time set by the top-level \
`--time` argument.  When set, it uses the specified time instead of \
the current time, when determining what keys are valid, and it sets \
the revocation certificate's creation time to the reference time \
instead of the current time.
",)]
#[clap(group(ArgGroup::new("cert_input").args(&["cert_file", "cert"]).required(true)))]
#[clap(group(ArgGroup::new("revoker_input").args(&["revoker_file", "revoker"])))]
pub struct UseridRevokeCommand {
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
        long_help =
"Read the certificate whose user ID should be revoked from FILE or \
stdin.  It is an error for the file to contain more than one \
certificate.",
    )]
    pub cert_file: Option<FileOrStdin>,

    #[clap(
        long,
        value_name = "FINGERPRINT|KEYID",
        help = "Revoke the user ID with the specified certificate",
        long_help =
"Sign the revocation certificate using the specified key.  If the key is \
different from the certificate, this creates a third-party revocation.  If \
this option is not provided, and the certificate includes secret key material, \
then that key is used to sign the revocation certificate.",
    )]
    pub revoker: Option<KeyHandle>,
    #[clap(
        long,
        value_name = "KEY_FILE",
        conflicts_with = "revoker",
        help = "Sign the revocation certificate using the key in KEY_FILE",
        long_help =
"Sign the revocation certificate using the key in KEY_FILE.  If the key is \
different from the certificate, this creates a third-party revocation.  If \
this option is not provided, and the certificate includes secret key material, \
then that key is used to sign the revocation certificate.",
    )]
    pub revoker_file: Option<FileOrStdin>,

    #[clap(
        long,
        value_name = "USERID",
        help = "The User ID to revoke",
        long_help =
"The User ID to revoke.  By default, this must exactly match a \
self-signed User ID.  Use `--force` to generate a revocation certificate \
for a User ID, which is not self signed."
    )]
    pub userid: String,

    #[clap(
        value_enum,
        value_name = "REASON",
        help = "The reason for the revocation",
        long_help =
"The reason for the revocation.  This must be either: `retired`, or
`unspecified`:

  - `retired` means that this User ID is no longer valid.  This is
    appropriate when someone leaves an organisation, and the
    organisation does not have their secret key material.  For
    instance, if someone was part of Debian and retires, they would
    use this to indicate that a Debian-specific User ID is no longer
    valid.

  - `unspecified` means that a different reason applies.

If the reason happened in the past, you should specify that using the \
`--time` argument.  This allows OpenPGP implementations to more
accurately reason about objects whose validity depends on the validity \
of a User ID."
    )]
    pub reason: UserIDReasonForRevocation,

    #[clap(
        value_name = "MESSAGE",
        help = "A short, explanatory text",
        long_help =
"A short, explanatory text that is shown to a viewer of the revocation \
certificate.  It explains why the certificate has been revoked.  For \
instance, if Alice has created a new key, she would generate a \
`superseded` revocation certificate for her old key, and might include \
the message `I've created a new certificate, FINGERPRINT, please use
that in the future.`",
    )]
    pub message: String,

    #[clap(
        long,
        value_names = &["NAME", "VALUE"],
        number_of_values = 2,
        help = "Add a notation to the certification.",
        long_help = "Add a notation to the certification.  \
            A user-defined notation's name must be of the form \
            `name@a.domain.you.control.org`. If the notation's name starts \
            with a `!`, then the notation is marked as being critical.  If a \
            consumer of a signature doesn't understand a critical notation, \
            then it will ignore the signature.  The notation is marked as \
            being human readable."
    )]
    pub notation: Vec<String>,

    #[clap(
        long,
        short,
        value_name = FileOrCertStore::VALUE_NAME,
        help = "Write to the specified FILE.  If not specified, and the \
                certificate was read from the certificate store, imports the \
                modified certificate into the cert store.  If not specified, \
                and the certificate was read from a file, writes the modified \
                certificate to stdout.",
    )]
    pub output: Option<FileOrStdout>,

    #[clap(
        short = 'B',
        long,
        help = "Emit binary data",
    )]
    pub binary: bool,
}

#[derive(Debug, Args)]
#[clap(
    about = "Strip a User ID",
    long_about =
"Strip a User ID

Note that this operation does not reliably remove User IDs from a
certificate that has already been disseminated! (OpenPGP software
typically appends new information it receives about a certificate
to its local copy of that certificate.  Systems that have obtained
a copy of your certificate with the User ID that you are trying to
strip will not drop that User ID from their copy.)

In most cases, you will want to use the 'sq key userid revoke' operation
instead.  That issues a revocation for a User ID, which can be used to mark
the User ID as invalidated.

However, this operation can be useful in very specific cases, in particular:
to remove a mistakenly added User ID before it has been uploaded to key
servers or otherwise shared.

Stripping a User ID may change how a certificate is interpreted.  This
is because information about the certificate like algorithm preferences,
the primary key's key flags, etc. is stored in the User ID's binding
signature.
",
    after_help =
"EXAMPLES:

# First, generate a key:
$ sq key generate --userid '<juliet@example.org>' \\
     --output juliet.key.pgp

# Then, strip a User ID:
$ sq key userid strip --userid '<juliet@example.org>' \\
     --output juliet-new.key.pgp juliet.key.pgp
",
)]
pub struct UseridStripCommand {
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
    #[clap(
        value_name = "USERID",
        short,
        long,
        help = "User IDs to strip",
        long_help = "The User IDs to strip.  Values must exactly match a \
User ID."
    )]
    pub userid: Vec<UserID>,
    #[clap(
        short = 'B',
        long,
        help = "Emit binary data",
    )]
    pub binary: bool,
}

#[derive(Debug, Args)]
#[clap(
    name = "adopt",
    about = "Bind keys from one certificate to another",
    long_about =
"Bind keys from one certificate to another

This command allows one to transfer primary keys and subkeys into an
existing certificate.  Say you want to transition to a new
certificate, but have an authentication subkey on your current
certificate.  You want to keep the authentication subkey because it
allows access to SSH servers and updating their configuration is not
feasible.
",
    after_help =
"EXAMPLES:

# Adopt an subkey into the new cert
$ sq key adopt --keyring juliet-old.pgp --key 0123456789ABCDEF \\
     juliet-new.pgp
",
)]
#[clap(group(ArgGroup::new("cert_input").args(&["cert_file", "cert"]).required(true)))]
pub struct AdoptCommand {
    #[clap(
        short = 'k',
        long = "key",
        value_name = "KEY",
        required(true),
        help = "Add the key or subkey KEY to the TARGET-KEY",
    )]
    pub key: Vec<KeyHandle>,
    #[clap(
        long,
        value_name = "EXPIRATION",
        help = "Make adopted subkeys expire at the given time",
    )]
    pub expiration: Option<Time>,
    #[clap(
        long = "allow-broken-crypto",
        help = "Allow adopting keys from certificates \
            using broken cryptography",
    )]
    pub allow_broken_crypto: bool,
    #[clap(
        long,
        help = "Add keys to TARGET-KEY",
        value_name = FileOrStdin::VALUE_NAME,
    )]
    pub cert: Option<KeyHandle>,
    #[clap(
        long,
        value_name = "TARGET-KEY",
        help = "Add keys to TARGET-KEY",
    )]
    pub cert_file: Option<FileOrStdin>,
    #[clap(
        help = FileOrStdout::HELP_OPTIONAL,
        long,
        short,
        value_name = FileOrStdout::VALUE_NAME,
    )]
    pub output: Option<FileOrStdout>,
    #[clap(
        short = 'B',
        long,
        help = "Emit binary data",
    )]
    pub binary: bool,
}

#[derive(Debug, Args)]
#[clap(
    name = "attest-certifications",
    about = "Attest to third-party certifications",
    long_about =
"Attest to third-party certifications allowing for their distribution

To prevent certificate flooding attacks, modern key servers prevent
uncontrolled distribution of third-party certifications on
certificates.  To make the key holder the sovereign over the
information over what information is distributed with the certificate,
the key holder needs to explicitly attest to third-party
certifications.

After the attestation has been created, the certificate has to be
distributed, e.g. by uploading it to a key server.
",
    after_help =
"EXAMPLES:

# Attest to all certifications present on the key
$ sq key attest-certifications --all --cert-file juliet.pgp

# Retract prior attestations on the key
$ sq key attest-certifications --none --cert-file juliet.pgp
",
)]
#[clap(group(ArgGroup::new("certifications_input").args(&["all", "none"]).required(true)))]
#[clap(group(ArgGroup::new("cert_input").args(&["cert_file", "cert"]).required(true)))]
pub struct AttestCertificationsCommand {
    #[clap(
        long = "none",
        conflicts_with = "all",
        help = "Remove all prior attestations",
    )]
    pub none: bool,
    #[clap(
        long = "all",
        conflicts_with = "none",
        help = "Attest to all certifications",
    )]
    pub all: bool,
    #[clap(
        long,
        value_name = "CERT",
        help = "Change attestations on the specified key",
    )]
    pub cert: Option<KeyHandle>,
    #[clap(
        long,
        value_name = "CERT_FILE",
        help = "Change attestations on the specified key",
    )]
    pub cert_file: Option<FileOrStdin>,
    #[clap(
        long,
        short,
        value_name = FileOrCertStore::VALUE_NAME,
        help = "Write to the specified FILE.  If not specified, and the \
                certificate was read from the certificate store, imports the \
                modified certificate into the cert store.  If not specified, \
                and the certificate was read from a file, writes the modified \
                certificate to stdout.",
    )]
    pub output: Option<FileOrStdout>,
    #[clap(
        short = 'B',
        long,
        help = "Emit binary data",
    )]
    pub binary: bool,
}

#[derive(Debug, Subcommand)]
#[clap(
    name = "subkey",
    about = "Manage Subkeys",
    long_about =
"Manage Subkeys

Add new subkeys to an existing key.
",
    subcommand_required = true,
    arg_required_else_help = true,
)]
#[non_exhaustive]
pub enum SubkeyCommand {
    Add(SubkeyAddCommand),
    Expire(SubkeyExpireCommand),
    Revoke(SubkeyRevokeCommand),
}

#[derive(Debug, Args)]
#[clap(
    about = "Add a newly generated Subkey",
    long_about =
"Add a newly generated Subkey

A subkey has one or more flags. `--can-sign` sets the signing flag,
and means that the key may be used for signing. `--can-authenticate`
sets the authentication flags, and means that the key may be used for
authentication (e.g., as an SSH key). These two flags may be combined.

`--can-encrypt=storage` sets the storage encryption flag, and means that the key
may be used for storage encryption. `--can-encrypt=transport` sets the transport
encryption flag, and means that the key may be used for transport encryption.
`--can-encrypt=universal` sets both the storage and the transport encryption
flag, and means that the key may be used for both storage and transport
encryption. Only one of the encryption flags may be used and it can not be
combined with the signing or authentication flag.

At least one flag must be chosen.

When using `--with-password`, `sq` prompts the user for a password, that is
used to encrypt the subkey.
The password for the subkey may be different from that of the primary key.

Furthermore the subkey may use one of several available cipher suites, that can
be selected using `--cipher-suite`.

By default a new subkey never expires. However, its validity period is limited
by that of the primary key it is added for.
Using the `--expiration` argument specific validity periods may be defined.
It allows for providing a point in time for validity to end or a validity
duration.

`sq key subkey add` respects the reference time set by the top-level
`--time` argument. It sets the creation time of the subkey to the specified
time.
",
    after_help =
"EXAMPLES:

# First, generate a key
$ sq key generate --userid '<juliet@example.org>' \\
     --output juliet.key.pgp

# Add a new Subkey for universal encryption which expires at the same
# time as the primary key
$ sq key subkey add --output juliet-new.key.pgp \\
     --can-encrypt universal juliet.key.pgp

# Add a new Subkey for signing using the rsa3k cipher suite which
# expires in five days
$ sq key subkey add --output juliet-new.key.pgp --can-sign \\
     --expiration 5d --cipher-suite rsa3k juliet.key.pgp
",
)]
#[clap(group(ArgGroup::new("cert_input").args(&["cert_file", "cert"]).required(true)))]
#[clap(group(ArgGroup::new("authentication-group").args(&["can_authenticate", "can_encrypt"])))]
#[clap(group(ArgGroup::new("sign-group").args(&["can_sign", "can_encrypt"])))]
#[clap(group(ArgGroup::new("required-group").args(&["can_authenticate", "can_sign", "can_encrypt"]).required(true)))]
pub struct SubkeyAddCommand {
    #[clap(
        long,
        value_name = "FINGERPRINT|KEYID",
        help = "Add a subkey to the specified certificate",
    )]
    pub cert: Option<KeyHandle>,
    #[clap(
        long,
        help = FileOrStdin::HELP_OPTIONAL,
        value_name = "CERT_FILE",
        conflicts_with = "cert",
        help = "Add a subkey to the specified certificate",
        long_help =
"Read the certificate that should be modified from FILE or \
stdin.  It is an error for the file to contain more than one \
certificate.",
    )]
    pub cert_file: Option<FileOrStdin>,

    #[clap(
        long,
        short,
        value_name = FileOrCertStore::VALUE_NAME,
        help = "Write to the specified FILE.  If not specified, and the \
                certificate was read from the certificate store, imports the \
                modified certificate into the cert store.  If not specified, \
                and the certificate was read from a file, writes the modified \
                certificate to stdout.",
    )]
    pub output: Option<FileOrStdout>,

    #[clap(
        short = 'B',
        long,
        help = "Emit binary data",
    )]
    pub binary: bool,
    #[clap(
        short = 'c',
        long = "cipher-suite",
        value_name = "CIPHER-SUITE",
        default_value_t = CipherSuite::Cv25519,
        help = "Select the cryptographic algorithms for the subkey",
        value_enum,
    )]
    pub cipher_suite: CipherSuite,
    #[clap(
        long = "expiration",
        value_name = "EXPIRATION",
        default_value_t = Expiration::Never,
        help =
            "Define EXPIRATION for the subkey as ISO 8601 formatted string or \
            custom duration.",
        long_help =
            "Define EXPIRATION for the subkey as ISO 8601 formatted string or \
            custom duration. \
            If an ISO 8601 formatted string is provided, the validity period \
            reaches from the reference time (may be set using `--time`) to \
            the provided time. \
            Custom durations starting from the reference time may be set using \
            `N[ymwds]`, for N years, months, weeks, days, or seconds. \
            The special keyword `never` sets an unlimited expiration.",
    )]
    pub expiration: Expiration,
    #[clap(
        long = "can-sign",
        help = "Add signing capability to subkey",
    )]
    pub can_sign: bool,
    #[clap(
        long = "can-authenticate",
        help = "Add authentication capability to subkey",
    )]
    pub can_authenticate: bool,
    #[clap(
        long = "can-encrypt",
        value_name = "PURPOSE",
        help = "Add an encryption capability to subkey [default: universal]",
        long_help =
            "Add an encryption capability to subkey. \
            Encryption-capable subkeys can be marked as \
            suitable for transport encryption, storage \
            encryption, or both, i.e., universal. \
            [default: universal]",
        value_enum,
    )]
    pub can_encrypt: Option<EncryptPurpose>,
    #[clap(
        long = "with-password",
        help = "Protect the subkey with a password",
    )]
    pub with_password: bool,
}


const SQ_KEY_SUBKEY_EXPIRE_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Example(Example {
            comment: "Make Bob's authentication subkey expire in six months.",
            command: &[
                "sq", "key", "subkey", "expire", "6m",
                "--cert-file", "bob-secret.pgp",
                "--key", "6AEACDD24F896624",
            ],
        }),
    ],
};
test_examples!(sq_key_subkey_expire, SQ_KEY_SUBKEY_EXPIRE_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    name = "expire",
    about = "Change expiration times",
    long_about =
"Change expiration times

Change or clear a key's expiration time.

This subcommand changes a key's expiration time.  To change the
expiration time of the certificate, use the `sq key expire`
subcommand.

Changing the expiration time of the primary key is equivalent to
changing the certificate's expiration time.
",
    after_help = SQ_KEY_SUBKEY_EXPIRE_EXAMPLES,
)]
#[clap(group(ArgGroup::new("cert_input").args(&["cert_file", "cert"]).required(true)))]
pub struct SubkeyExpireCommand {
    #[clap(
        help = FileOrStdout::HELP_OPTIONAL,
        long,
        short,
        value_name = FileOrStdout::VALUE_NAME,
    )]
    pub output: Option<FileOrStdout>,

    #[clap(
        short = 'B',
        long,
        help = "Emit binary data",
    )]
    pub binary: bool,

    #[clap(
        long,
        help = "Change expiration of this subkey",
        required = true,
    )]
    pub key: Vec<KeyHandle>,

    #[clap(
        value_name = "EXPIRATION",
        help =
            "Define EXPIRATION for the key as ISO 8601 formatted string or \
            custom duration.",
        long_help =
            "Define EXPIRATION for the key as ISO 8601 formatted string or \
            custom duration. \
            If an ISO 8601 formatted string is provided, the validity period \
            reaches from the reference time (may be set using `--time`) to \
            the provided time. \
            Custom durations starting from the reference time may be set using \
            `N[ymwds]`, for N years, months, weeks, days, or seconds. \
            The special keyword `never` sets an unlimited expiry.",
    )]
    pub expiration: Expiration,

    #[clap(
        long,
        value_name = "FINGERPRINT|KEYID",
        help = "Change the expiration time of keys on the specified \
                certificate",
    )]
    pub cert: Option<KeyHandle>,
    #[clap(
        long,
        value_name = "CERT_FILE",
        help = "Change the expiration time of keys on the specified \
                certificate",
    )]
    pub cert_file: Option<FileOrStdin>,
}

#[derive(Debug, Args)]
#[clap(
    about = "Revoke a subkey",
    long_about =
"Revoke a subkey

Creates a revocation certificate for a subkey.

If `--revocation-file` is provided, then that key is used to \
create the signature.  If that key is different from the certificate \
being revoked, this creates a third-party revocation.  This is \
normally only useful if the owner of the certificate designated the \
key to be a designated revoker.

If `--revocation-file` is not provided, then the certificate \
must include a certification-capable key.

`sq key subkey revoke` respects the reference time set by the top-level \
`--time` argument.  When set, it uses the specified time instead of \
the current time, when determining what keys are valid, and it sets \
the revocation certificate's creation time to the reference time \
instead of the current time.
",
)]
#[clap(group(ArgGroup::new("cert_input").args(&["cert_file", "cert"]).required(true)))]
#[clap(group(ArgGroup::new("revoker_input").args(&["revoker_file", "revoker"])))]
pub struct SubkeyRevokeCommand {
    #[clap(
        long,
        value_name = "FINGERPRINT|KEYID",
        help = "Revoke the user ID on the specified certificate",
    )]
    pub cert: Option<KeyHandle>,
    #[clap(
        long,
        value_name = FileOrStdin::VALUE_NAME,
        conflicts_with = "cert",
        help = "Revoke the subkey on the specified certificate",
        long_help =
"Read the certificate whose subkey should be revoked from FILE or \
stdin.  It is an error for the file to contain more than one \
certificate.",
    )]
    pub cert_file: Option<FileOrStdin>,

    #[clap(
        long,
        value_name = "FINGERPRINT|KEYID",
        help = "Revoke the user ID with the specified certificate",
        long_help =
"Sign the revocation certificate using the specified key.  If the key is \
different from the certificate, this creates a third-party revocation.  If \
this option is not provided, and the certificate includes secret key material, \
then that key is used to sign the revocation certificate.",
    )]
    pub revoker: Option<KeyHandle>,
    #[clap(
        long,
        value_name = "KEY_FILE",
        conflicts_with = "revoker",
        help = "Sign the revocation certificate using the key in KEY_FILE",
        long_help =
"Sign the revocation certificate using the key in KEY_FILE.  If the key is \
different from the certificate, this creates a third-party revocation.  If \
this option is not provided, and the certificate includes secret key material, \
then that key is used to sign the revocation certificate.",
    )]
    pub revoker_file: Option<FileOrStdin>,

    #[clap(
        value_name = "SUBKEY",
        help = "The subkey to revoke",
        long_help =
"The subkey to revoke.  This must either be the subkey's Key ID or its \
fingerprint.",
    )]
    pub subkey: KeyHandle,

    #[clap(
        value_name = "REASON",
        required = true,
        help = "The reason for the revocation",
        long_help =
"The reason for the revocation.  This must be either: `compromised`,
`superseded`, `retired`, or `unspecified`:

  - `compromised` means that the secret key material may have been
    compromised.  Prefer this value if you suspect that the secret
    key has been leaked.

  - `superseded` means that the owner of the certificate has replaced
    it with a new certificate.  Prefer `compromised` if the secret
    key material has been compromised even if the certificate is also
    being replaced!  You should include the fingerprint of the new
    certificate in the message.

  - `retired` means that this certificate should not be used anymore,
    and there is no replacement.  This is appropriate when someone
    leaves an organisation.  Prefer `compromised` if the secret key
    material has been compromised even if the certificate is also
    being retired!  You should include how to contact the owner, or
    who to contact instead in the message.

  - `unspecified` means that none of the three other three reasons
    apply.  OpenPGP implementations conservatively treat this type
    of revocation similar to a compromised key.

If the reason happened in the past, you should specify that using the
`--time` argument.  This allows OpenPGP implementations to more
accurately reason about objects whose validity depends on the validity
of the certificate.",
    value_enum,
    )]
    pub reason: KeyReasonForRevocation,

    #[clap(
        value_name = "MESSAGE",
        help = "A short, explanatory text",
        long_help =
"A short, explanatory text that is shown to a viewer of the revocation \
certificate.  It explains why the subkey has been revoked.  For \
instance, if Alice has created a new key, she would generate a \
`superseded` revocation certificate for her old key, and might include \
the message `I've created a new subkey, please refresh the certificate.`"
    )]
    pub message: String,

    #[clap(
        long,
        value_names = &["NAME", "VALUE"],
        number_of_values = 2,
        help = "Add a notation to the certification.",
        long_help = "Add a notation to the certification.  \
            A user-defined notation's name must be of the form \
            `name@a.domain.you.control.org`. If the notation's name starts \
            with a `!`, then the notation is marked as being critical.  If a \
            consumer of a signature doesn't understand a critical notation, \
            then it will ignore the signature.  The notation is marked as \
            being human readable."
    )]
    pub notation: Vec<String>,

    #[clap(
        long,
        short,
        value_name = FileOrStdout::VALUE_NAME,
        help = "Write to the specified FILE.  If not specified, and the \
                certificate was read from the certificate store, imports the \
                modified certificate into the cert store.  If not specified, \
                and the certificate was read from a file, writes the modified \
                certificate to stdout.",
    )]
    pub output: Option<FileOrStdout>,

    #[clap(
        short = 'B',
        long,
        help = "Emit binary data",
    )]
    pub binary: bool,
}

