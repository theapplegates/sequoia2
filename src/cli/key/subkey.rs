use clap::{ArgGroup, Args, Subcommand};

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;

use crate::cli::types::ClapData;
use crate::cli::types::ExpirationArg;
use crate::cli::types::FileOrCertStore;
use crate::cli::types::FileOrStdout;
use crate::cli::types::Time;

use crate::cli::key::{
    EncryptPurpose,
    KeyReasonForRevocation,
};

use crate::cli::examples;
use examples::Action;
use examples::Actions;
use examples::Example;
use examples::Setup;
use crate::cli::types::CertDesignators;
use crate::cli::types::cert_designator;

pub mod add;
pub mod delete;
pub mod expire;
pub mod export;
pub mod password;

#[derive(Debug, Subcommand)]
#[clap(
    name = "subkey",
    about = "Manage subkeys",
    long_about = "\
Manage subkeys.

Add new subkeys to an existing certificate, change their expiration, \
and revoke them.",
    subcommand_required = true,
    arg_required_else_help = true,
)]
#[non_exhaustive]
pub enum Command {
    Add(add::Command),
    Export(export::Command),
    Delete(delete::Command),
    Password(password::Command),
    Expire(expire::Command),
    Revoke(RevokeCommand),
    Bind(BindCommand),
}

const SUBKEY_REVOKE_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Setup(Setup {
            command: &[
                "sq", "key", "import",
                "alice-secret.pgp",
            ],
        }),

        Action::Example(Example {
            comment: "\
Revoke Alice's signing subkey.",
            command: &[
                "sq", "key", "subkey", "revoke",
                "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--key=42020B87D51877E5AF8D272124F3955B0B8DECC8",
                "--reason", "retired",
                "--message", "Subkey rotation.",
            ],
        }),

        Action::Example(Example {
            comment: "\
Revoke Alice's signing subkey and encryption subkeys.",
            command: &[
                "sq", "key", "subkey", "revoke",
                "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--key=42020B87D51877E5AF8D272124F3955B0B8DECC8",
                "--key=74DCDEAF17D9B995679EB52BA6E65EA2C8497728",
                "--reason", "retired",
                "--message", "Subkey rotation.",
            ],
        }),
    ],
};
test_examples!(sq_key_subkey_revoke, SUBKEY_REVOKE_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    about = "Revoke a subkey",
    long_about =
"Revoke a subkey.

Creates a revocation certificate for a subkey.

If `--revoker` or `--revoker-file` is provided, then that key is used \
to create the revocation certificate.  If that key is different from \
the certificate that is being revoked, this results in a third-party \
revocation.  This is normally only useful if the owner of the \
certificate designated the key to be a designated revoker.

`sq key subkey revoke` respects the reference time set by the top-level \
`--time` argument.  When set, it uses the specified time instead of \
the current time when determining what keys are valid, and it sets \
the revocation certificate's creation time to the reference time \
instead of the current time.
",
    after_help = SUBKEY_REVOKE_EXAMPLES,
)]
pub struct RevokeCommand {
    #[command(flatten)]
    pub cert: CertDesignators<
        cert_designator::CertUserIDEmailFileArgs,
        cert_designator::NoPrefix,
        cert_designator::OneValueAndFileRequiresOutput,
        SubkeyRevokeCertDoc>,

    #[command(flatten)]
    pub revoker: CertDesignators<
        cert_designator::CertUserIDEmailFileArgs,
        cert_designator::RevokerPrefix,
        cert_designator::OneOptionalValue,
        SubkeyRevokeRevokerDoc>,

    #[clap(
        long = "key",
        value_name = "FINGERPRINT|KEYID",
        help = "Revoke this subkey",
        required = true,
    )]
    pub keys: Vec<KeyHandle>,

    #[clap(
        long,
        value_name = "REASON",
        required = true,
        help = "The reason for the revocation",
        long_help = "\
The reason for the revocation.

If the reason happened in the past, you should specify that using the \
`--time` argument.  This allows OpenPGP implementations to more \
accurately reason about artifacts whose validity depends on the validity \
of the user ID.",
        value_enum,
    )]
    pub reason: KeyReasonForRevocation,

    #[clap(
        long,
        value_name = "MESSAGE",
        required = true,
        help = "A short, explanatory text",
        long_help = "\
A short, explanatory text.

The text is shown to a viewer of the revocation certificate, and \
explains why the subkey has been revoked.  For instance, if Alice has \
created a new key, she would generate a `superseded` revocation \
certificate for her old key, and might include the message \"I've \
created a new subkey, please refresh the certificate.\"",
    )]
    pub message: String,

    #[clap(
        long,
        value_names = &["NAME", "VALUE"],
        number_of_values = 2,
        help = "Add a notation to the certification.",
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
        long,
        help = "Emit binary data",
    )]
    pub binary: bool,
}

/// Documentation for the cert designators for the cert argument of
/// the key subkey revoke command.
pub struct SubkeyRevokeCertDoc {}

impl cert_designator::AdditionalDocs for SubkeyRevokeCertDoc {
    fn help(arg: &'static str, help: &'static str) -> clap::builder::StyledStr {
        match arg {
            "file" =>
                "Revoke the specified (sub)keys on the key read from PATH"
                .into(),
            _ => {
                debug_assert!(help.starts_with("Use certificates"));
                help.replace("Use certificates",
                             "Revoke the specified (sub)keys on the key")
                    .into()
            },
        }
    }
}

/// Documentation for the revoker designators for revoker argument of
/// the key subkey revoke command .
pub struct SubkeyRevokeRevokerDoc {}

impl cert_designator::AdditionalDocs for SubkeyRevokeRevokerDoc {
    fn help(_: &'static str, help: &'static str) -> clap::builder::StyledStr {
        format!("{} to create the revocation certificate.

Sign the revocation certificate using the specified key.  By default, \
the certificate being revoked is used.  Using this option, it is \
possible to create a third-party revocation.",
                help.replace("certificates", "key")).into()
    }
}

#[derive(Debug, Args)]
#[clap(
    name = "bind",
    about = "Bind keys from one certificate to another",
    long_about = "\
Bind keys from one certificate to another.

This command allows the user to attach a primary key or a subkey \
attached to one certificate to another certificate.  Say you want to \
transition to a new certificate, but have an authentication subkey on \
your current certificate that you want to keep because it allows access \
a server and updating its configuration is not feasible.  This command \
makes it easy to attach the subkey to the new certificate.

After the operation, the key is bound both to the old certificate and to \
the new one.  To remove secret key material from the old certificate, use \
`sq key subkey delete` or `sq key delete`, as appropriate.  To revoke the \
old subkey or key, use `sq key subkey revoke` or `sq key revoke`, \
respectively.
",
    after_help = BIND_EXAMPLES,
)]
#[clap(group(ArgGroup::new("cap-sign").args(&["can_sign", "cannot_sign"])))]
#[clap(group(ArgGroup::new("cap-authenticate").args(&["can_authenticate", "cannot_authenticate"])))]
#[clap(group(ArgGroup::new("cap-encrypt").args(&["can_encrypt", "cannot_encrypt"])))]
pub struct BindCommand {
    #[command(flatten)]
    pub cert: CertDesignators<
        cert_designator::CertUserIDEmailFileArgs,
        cert_designator::NoPrefix,
        cert_designator::OneValueAndFileRequiresOutput,
        SubkeyBindDoc>,

    #[clap(
        long,
        value_name = "KEY",
        required(true),
        help = "Add the key or subkey KEY to the certificate",
    )]
    pub key: Vec<KeyHandle>,
    #[clap(
        long,
        allow_hyphen_values = true,
        value_name = "CREATION_TIME",
        help = "Make bound subkeys have the specified creation time",
        long_help = "\
Make bound subkeys have the specified creation time.

Normally, the key's creation time is preserved.  The exception is if \
the key's creation time is the Unix epoch.  In that case, the current \
time is used.

This option allows setting the key's creation time to a specified value.  \
Note: changing a key's creation time also changes its fingerprint.  \
Changing the fingerprint will make it impossible to look up the key for \
the purpose of signature verification, for example.",
    )]
    pub creation_time: Option<Time>,
    #[clap(flatten)]
    pub expiration: ExpirationArg,
    #[clap(
        long,
        help = "Allow adopting keys from certificates \
            using broken cryptography",
    )]
    pub allow_broken_crypto: bool,

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

const BIND_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Setup(Setup {
            command: &[
                "sq", "key", "import",
                "alice-secret.pgp", "alice-new-secret.pgp",
            ],
        }),
        Action::Example(Example {
            comment: "\
Bind Alice's old authentication subkey to Alice's new certificate.",
            command: &[
                "sq", "key", "subkey", "bind",
                "--cert=C5999E8191BF7B503653BE958B1F7910D01F86E5",
                "--key=0D45C6A756A038670FDFD85CB1C82E8D27DB23A1",
            ],
        }),
        Action::Example(Example {
            comment: "\
Bind a bare key to Alice's certificate.  A bare key is a public key \
without any components or signatures.  This simplifies working with raw \
keys, e.g., keys generated on an OpenPGP card, a TPM device, etc.",
            command: &[
                "sq", "key", "subkey", "bind",
                "--keyring=bare.pgp",
                "--cert=C5999E8191BF7B503653BE958B1F7910D01F86E5",
                "--key=B321BA8F650CB16443E06826DBFA98A78CF6562F",
                "--can-encrypt=universal",
            ],
        }),
    ]
};
test_examples!(sq_key_bind, BIND_EXAMPLES);

/// Documentation for the cert argument of the key subkey bind
/// command.
pub struct SubkeyBindDoc {}

impl cert_designator::AdditionalDocs for SubkeyBindDoc {
    fn help(arg: &'static str, help: &'static str) -> clap::builder::StyledStr {
        match arg {
            "file" =>
                "Add the specified subkeys to the key read from PATH"
                .into(),
            _ => {
                debug_assert!(help.starts_with("Use certificates"));
                help.replace("Use certificates",
                             "Add the specified subkeys on the key")
                    .into()
            },
        }
    }
}
