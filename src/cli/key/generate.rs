use std::path::PathBuf;

use clap::{ArgGroup, Args};

use sequoia_openpgp as openpgp;
use openpgp::packet::UserID;

use crate::cli::KEY_VALIDITY_DURATION;
use crate::cli::KEY_VALIDITY_IN_YEARS;
use crate::cli::types::ClapData;
use crate::cli::types::EncryptPurpose;
use crate::cli::types::Expiration;
use crate::cli::types::ExpirationArg;
use crate::cli::types::FileOrStdout;

use crate::cli::examples::*;
use crate::cli::key::CipherSuite;

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
#[clap(mut_arg("expiration", |arg| {
    arg.default_value(Expiration::from_duration(KEY_VALIDITY_DURATION))
}))]
pub struct Command {
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

    #[command(flatten)]
    pub expiration: ExpirationArg,

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
        requires = "rev_cert",
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
the file specified by `--rev-cert`.

If `--output` is `-`, then this option must not also be `-`.",
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
    pub rev_cert: Option<FileOrStdout>
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
                "--rev-cert", "alice-priv.rev",
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
