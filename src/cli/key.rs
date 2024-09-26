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
use crate::cli::types::FileOrStdin;
use crate::cli::types::FileOrStdout;
use crate::cli::types::Time;

use crate::cli::examples;
use examples::Action;
use examples::Actions;
use examples::Example;
use examples::Setup;

pub mod approvals;
pub mod expire;
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
certificates.",
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
    Revoke(revoke::Command),
    #[clap(subcommand)]
    Userid(userid::Command),
    #[clap(subcommand)]
    Subkey(subkey::Command),
    #[clap(subcommand)]
    Approvals(approvals::Command),
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
                "--without-password",
                "--name", "Alice",
                "--email", "alice@example.org",
            ],
        }),
        Action::Example(Example {
            comment: "\
Generate a key, and save it in a file instead of in the key store.",
            command: &[
                "sq", "key", "generate",
                "--without-password",
                "--name", "Alice",
                "--email", "alice@example.org",
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
#[clap(group(ArgGroup::new("cert-userid").args(&["names", "emails", "userid", "no_userids"]).required(true).multiple(true)))]
pub struct GenerateCommand {
    #[clap(
        long = "name",
        value_name = "NAME",
        help = "Add a name as user ID to the key"
    )]
    pub names: Vec<String>,

    #[clap(
        long = "email",
        value_name = "ADDRESS",
        help = "Add an email address as user ID to the key"
    )]
    pub emails: Vec<String>,

    #[clap(
        long = "userid",
        value_name = "USERID",
        help = "Add a user ID to the key",
        long_help = "
Add a user ID to the key.

This user ID can combine name and email address, can optionally
contain a comment, or even be free-form if
`--allow-non-canonical-userids` is given.  However, user IDs that
include different information such as name and email address are more
difficult to reason about, so using distinct user IDs for name and
email address is preferred nowadays.

In doubt, prefer `--name` and `--email`.
",
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
        conflicts_with_all = ["names", "emails", "userid"],
    )]
    pub no_userids: bool,
    #[clap(
        long = "cipher-suite",
        value_name = "CIPHER-SUITE",
        default_value_t = Default::default(),
        help = "Select the cryptographic algorithms for the key",
        value_enum,
    )]
    pub cipher_suite: CipherSuite,

    #[clap(
        long = "new-password-file",
        value_name = "PASSWORD_FILE",
        help = "\
File containing password to encrypt the secret key material",
        long_help = "\
File containing password to encrypt the secret key material.

Note that the entire key file will be used as the password including \
any surrounding whitespace like a trailing newline.",
        conflicts_with = "without_password",
    )]
    pub new_password_file: Option<PathBuf>,

    #[clap(
        long = "without-password",
        help = "Don't protect the secret key material with a password",
    )]
    pub without_password: bool,

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

const EXPORT_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Setup(Setup {
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
    ]
};
test_examples!(sq_key_export, EXPORT_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    about = "Export keys from the key store",
    long_about = "
Export keys from the key store.

Exports the secret key material associated with a certificate.  Note \
that even if secret key material is available, it may not be \
exportable.  For instance, secret key material stored on a hardware \
security module usually cannot be exported from the device.

If you only want to export a particular key and not all keys associate \
with a certificate, use `sq key subkey export`.",
    after_help = EXPORT_EXAMPLES,
)]
pub struct ExportCommand {
    #[clap(
        long,
        value_name = "FINGERPRINT|KEYID",
        required = true,
        help = "Export the specified certificate with its secret key material",
        long_help = "\
Export the specified certificate with its secret key material.

Iterate over the specified certificate's primary key and subkeys and \
export any keys with secret key material.  An error is returned if \
the certificate does not contain any secret key material.",
    )]
    pub cert: Vec<KeyHandle>,
}

const DELETE_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Setup(Setup {
            command: &[
                "sq", "key", "import", "alice-secret.pgp",
            ],
        }),
        Action::Example(Example {
            comment: "\
Delete any secret key associated with Alice's certificate.",
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
        value_name = FileOrStdout::VALUE_NAME,
        conflicts_with = "cert",
        help = "Write the stripped certificate to the specified file",
    )]
    pub output: Option<FileOrStdout>,

    #[clap(
        long,
        requires = "output",
        help = "Emit binary data",
    )]
    pub binary: bool,
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

const ADOPT_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Setup(Setup {
            command: &[
                "sq", "key", "import",
                "alice-secret.pgp", "alice-new-secret.pgp",
            ],
        }),
        Action::Example(Example {
            comment: "\
Have Alice's new certificate adopt Alice's old authentication subkey.",
            command: &[
                "sq", "key", "adopt",
                "--cert", "C5999E8191BF7B503653BE958B1F7910D01F86E5",
                "--key", "0D45C6A756A038670FDFD85CB1C82E8D27DB23A1",
            ],
        }),
        Action::Example(Example {
            comment: "\
Have Alice's certificate adopt a bare key.  A bare key is a public key
without any components or signatures.  This simplifies working with raw
keys, e.g., keys generated on an OpenPGP card, a TPM device, etc.",
            command: &[
                "sq", "key", "adopt",
                "--keyring", "bare.pgp",
                "--cert", "C5999E8191BF7B503653BE958B1F7910D01F86E5",
                "--key", "B321BA8F650CB16443E06826DBFA98A78CF6562F",
                "--can-encrypt", "universal",
            ],
        }),
    ]
};
test_examples!(sq_key_adopt, ADOPT_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    name = "adopt",
    about = "Bind keys from one certificate to another",
    long_about = "\
Bind keys from one certificate to another.

This command allows the user to attach a primary key or a subkey \
attached to one certificate to another certificate.  Say you want to \
transition to a new certificate, but have an authentication subkey on \
your current certificate that you want to keep because it allows access \
a server and updating its configuration is not feasible.  This command \
makes it easy to attach the subkey to the new certificate.",
    after_help = ADOPT_EXAMPLES,
)]
#[clap(group(ArgGroup::new("cap-sign").args(&["can_sign", "cannot_sign"])))]
#[clap(group(ArgGroup::new("cap-authenticate").args(&["can_authenticate", "cannot_authenticate"])))]
#[clap(group(ArgGroup::new("cap-encrypt").args(&["can_encrypt", "cannot_encrypt"])))]
#[clap(group(ArgGroup::new("cert_input").args(&["cert_file", "cert"]).required(true)))]
pub struct AdoptCommand {
    #[clap(
        long,
        value_name = "KEY",
        required(true),
        help = "Add the key or subkey KEY to the certificate",
    )]
    pub key: Vec<KeyHandle>,
    #[clap(
        long,
        value_name = "CREATION_TIME",
        help = "Make adopted subkeys have the specified creation time",
        long_help = "\
Make adopted subkeys have the specified creation time.

Normally, the key's creation time is preserved.  This option allows \
setting the key's creation time to a specified value.  Note: changing \
the key's creation time also changes its fingerprint.",
    )]
    pub creation_time: Option<Time>,
    #[clap(
        long,
        value_name = "EXPIRATION",
        help = "Make adopted subkeys expire at the given time",
    )]
    pub expiration: Option<Time>,
    #[clap(
        long,
        help = "Allow adopting keys from certificates \
            using broken cryptography",
    )]
    pub allow_broken_crypto: bool,
    #[clap(
        long,
        help = "Add keys to the specified certificate",
        value_name = "CERT_FILE",
    )]
    pub cert: Option<KeyHandle>,
    #[clap(
        long,
        value_name = "CERT_FILE",
        help = "Add keys to the specified certificate",
    )]
    pub cert_file: Option<FileOrStdin>,

    #[clap(
        long = "can-sign",
        help ="Set the signing-capable flag",
    )]
    pub can_sign: bool,
    #[clap(
        long = "cannot-sign",
        help = "Don't set the signing-capable flag",
    )]
    pub cannot_sign: bool,
    #[clap(
        long = "can-authenticate",
        help = "Set the authentication-capable flag",
    )]
    pub can_authenticate: bool,
    #[clap(
        long = "cannot-authenticate",
        help = "Don't set the authentication-capable flag",
    )]
    pub cannot_authenticate: bool,
    #[clap(
        long = "can-encrypt",
        value_name = "PURPOSE",
        help = "Set the encryption-capable flag",
        long_help = "\
Encryption-capable subkeys can be marked as suitable for transport \
encryption, storage encryption, or both, i.e., universal.  [default: \
universal]",
        value_enum,
    )]
    pub can_encrypt: Option<EncryptPurpose>,
    #[clap(
        long = "cannot-encrypt",
        help = "Don't set the encryption-capable flag",
    )]
    pub cannot_encrypt: bool,

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
