use std::path::PathBuf;

use clap::{ArgGroup, Args, Subcommand};

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;

use crate::cli::types::ClapData;
use crate::cli::types::FileOrCertStore;
use crate::cli::types::FileOrStdin;
use crate::cli::types::FileOrStdout;
use crate::cli::types::Time;

use crate::cli::key::{
    CipherSuite,
    EncryptPurpose,
    Expiration,
    KeyReasonForRevocation,
};

use crate::cli::examples;
use examples::Action;
use examples::Actions;
use examples::Example;
use examples::Setup;
use crate::cli::types::cert_designator::*;

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
    Add(AddCommand),
    Export(ExportCommand),
    Delete(DeleteCommand),
    Password(PasswordCommand),
    Expire(ExpireCommand),
    Revoke(RevokeCommand),
    Bind(BindCommand),
}

const SUBKEY_ADD_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Setup(Setup {
            command: &[
                "sq", "key", "import",
                "alice-secret.pgp",
            ],
        }),
        Action::Example(Example {
            comment: "\
Add a new signing-capable subkey to Alice's key.",
            command: &[
                "sq", "key", "subkey", "add",
                "--without-password",
                "--can-sign",
                "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            ],
        }),
    ]
};
test_examples!(sq_key_subkey_add, SUBKEY_ADD_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    about = "Add a new subkey to a certificate",
    long_about = "\
Add a new subkey to a certificate.

A subkey has one or more capabilities.

`--can-sign` sets the signing capability, and means that the key may \
be used for signing. `--can-authenticate` sets the authentication \
capability, and means that the key may be used for authentication \
(e.g., as an SSH key).  `--can-certify` sets the certificate \
capability, and means that the key may be used to make third-party \
certifications.  These capabilities may be combined.

`--can-encrypt=storage` sets the storage encryption capability, and \
means that the key may be used for storage \
encryption. `--can-encrypt=transport` sets the transport encryption \
capability, and means that the key may be used for transport \
encryption.  `--can-encrypt=universal` sets both the storage and the \
transport encryption capability, and means that the key may be used \
for both storage and transport encryption.  The encryption \
capabilities must not be combined with the signing or authentication \
capability.

Normally, `sq` prompts the user for a password to use to encrypt the \
secret key material.  The password for the new subkey may be different \
from the other keys.  When using `--without-password`, `sq` doesn't \
prompt for a password, and doesn't password-protect the subkey.

By default a new subkey doesn't expire on its own.  However, its \
validity period is limited by that of the certificate.  Using the \
`--expiration` argument allows setting a different expiration time.

`sq key subkey add` respects the reference time set by the top-level \
`--time` argument.  It sets the creation time of the subkey to the specified \
time.
",
    after_help = SUBKEY_ADD_EXAMPLES,
)]
#[clap(group(ArgGroup::new("authentication-group").args(&["can_authenticate", "can_encrypt"])))]
#[clap(group(ArgGroup::new("sign-group").args(&["can_sign", "can_encrypt"])))]
#[clap(group(ArgGroup::new("required-group").args(&["can_authenticate", "can_sign", "can_encrypt"]).required(true)))]
pub struct AddCommand {
    #[command(flatten)]
    pub cert: CertDesignators<CertUserIDEmailFileArgs,
                              NoPrefix,
                              OneValueAndFileRequiresOutput,
                              SubkeyAddDoc>,

    #[clap(
        long,
        value_name = "CIPHER-SUITE",
        default_value_t = CipherSuite::Cv25519,
        help = "Select the cryptographic algorithms for the subkey",
        value_enum,
    )]
    pub cipher_suite: CipherSuite,
    #[clap(
        long,
        value_name = "EXPIRATION",
        default_value_t = Expiration::Never,
        help = "Sets the key's expiration time",
        long_help = "\
Sets the key's expiration time.

EXPIRATION is either an ISO 8601 formatted string or a custom duration, \
which takes the form `N[ymwds]`, where the letters stand for years, \
months, weeks, days, and seconds, respectively.  Alternatively, the \
keyword `never` does not set an expiration time.

When using an ISO 8601 formatted string, the validity period is from \
the key's creation time to the specified time.  When using a \
duration, the validity period is from the key's creation time \
for the specified duration.",
    )]
    pub expiration: Expiration,
    #[clap(
        long,
        help = "Add a signing-capable subkey",
    )]
    pub can_sign: bool,
    #[clap(
        long,
        help = "Add an authentication-capable subkey",
    )]
    pub can_authenticate: bool,
    #[clap(
        long,
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
        long,
        help = "Don't protect the subkey's secret key material with a password",
    )]
    pub without_password: bool,

    #[clap(
        long,
        value_name = FileOrStdout::VALUE_NAME,
        help = "Write to the specified FILE",
        long_help = "\
Write to the specified FILE.

If not specified, and the certificate was read from the certificate \
store, imports the modified certificate into the key store.  If not \
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


/// Documentation for the cert designators for the key subkey add
/// command.
pub struct SubkeyAddDoc {}

impl AdditionalDocs for SubkeyAddDoc {
    fn help(arg: &'static str, help: &'static str) -> clap::builder::StyledStr {
        match arg {
            "file" =>
                "Add a subkey to the key read from PATH"
                .into(),
            _ => {
                debug_assert!(help.starts_with("Use certificates"));
                help.replace("Use certificates",
                             "Add a subkey to the key")
                    .into()
            },
        }
    }
}

const SUBKEY_EXPORT_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Setup(Setup {
            command: &[
                "sq", "key", "import", "alice-secret.pgp",
            ],
        }),
        Action::Example(Example {
            comment: "\
Export Alice's signing-capable and encryption-capable subkeys, but not \
her primary key or her authentication-capable subkey.",
            command: &[
                "sq", "key", "subkey", "export",
                "--key=42020B87D51877E5AF8D272124F3955B0B8DECC8",
                "--key=74DCDEAF17D9B995679EB52BA6E65EA2C8497728",
            ],
        }),
    ]
};
test_examples!(sq_subkey_key_export, SUBKEY_EXPORT_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    about = "Export keys from the key store",
    long_about = "
Export secret key material from the secret key store.

Exports the secret key material.  Note that even if secret key \
material is available, it may not be exportable.  For instance, secret \
key material stored on a hardware security module usually cannot be \
exported from the device.

If you want to export all secret key material associated with a \
certificate, use `sq key export`.
",
    after_help = SUBKEY_EXPORT_EXAMPLES,
)]
pub struct ExportCommand {
    #[clap(
        long,
        value_name = "FINGERPRINT|KEYID",
        required = true,
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

const SQ_KEY_SUBKEY_DELETE_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Setup(Setup {
            command: &[
                "sq", "key", "import", "alice-secret.pgp",
            ],
        }),
        Action::Example(Example {
            comment: "\
Delete Alice's signing subkey.",
            command: &[
                "sq", "key", "subkey", "delete",
                "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--key=42020B87D51877E5AF8D272124F3955B0B8DECC8",
            ],
        }),
    ]
};
test_examples!(sq_key_subkey_delete, SQ_KEY_SUBKEY_DELETE_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    name = "delete",
    about = "Delete a certificate's secret key material",
    long_about = "\
Delete a certificate's secret key material.

Unlike `sq key delete`, which deletes all the secret key material, this \
command only deletes the specified secret key material.

Although the secret key material is deleted, the public keys are \
retained.  If you don't want the keys to be used anymore you should \
revoke the keys using `sq key subkey revoke`.
",
    after_help = SQ_KEY_SUBKEY_DELETE_EXAMPLES,
)]
pub struct DeleteCommand {
    #[command(flatten)]
    pub cert: CertDesignators<CertUserIDEmailFileArgs,
                              NoPrefix,
                              OneValueAndFileRequiresOutput,
                              SubkeyDeleteDoc>,

    #[clap(
        long,
        value_name = "FINGERPRINT|KEYID",
        required = true,
        help = "The keys to delete",
        long_help = "\
The keys to delete.

The specified keys may be either the primary key or subkeys.

If the secret key material is managed by multiple devices, it is \
deleted from all of them.",
    )]
    pub key: Vec<KeyHandle>,

    #[clap(
        long,
        value_name = FileOrStdout::VALUE_NAME,
        conflicts_with = "cert",
        help = "Write the stripped certificate to the specified file",
        long_help = "\
Write the stripped certificate to the specified file.

This option only makes sense when deleting the secret key material from a \
file.  When deleting secret key material managed by the key store using \
`--cert`, you can get the stripped certificate using `sq key export`.",
    )]
    pub output: Option<FileOrStdout>,

    #[clap(
        long,
        requires = "output",
        help = "Emit binary data",
    )]
    pub binary: bool,
}

/// Documentation for the cert designators for the key subkey delete
/// command.
pub struct SubkeyDeleteDoc {}

impl AdditionalDocs for SubkeyDeleteDoc {
    fn help(arg: &'static str, help: &'static str) -> clap::builder::StyledStr {
        match arg {
            "file" =>
                "Delete the secret key material from the key read from PATH"
                .into(),
            _ => {
                debug_assert!(help.starts_with("Use certificates"));
                help.replace("Use certificates",
                             "Delete secret key material from the key")
            },
        }.into()
    }
}

const SQ_KEY_SUBKEY_PASSWORD_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Setup(Setup {
            command: &[
                "sq", "key", "import", "alice-secret.pgp"
            ],
        }),
        Action::Example(Example {
            comment: "\
Change the password for Alice's signing key to the password in the \
specified file.",
            command: &[
                "sq", "key", "subkey", "password",
                "--new-password-file=password-file.txt",
                "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--key=42020B87D51877E5AF8D272124F3955B0B8DECC8",
            ],
        }),
        Action::Example(Example {
            comment: "\
Clear the password protection for Alice's signing key.",
            command: &[
                "sq", "key", "subkey", "password",
                "--password-file=password-file.txt",
                "--clear-password",
                "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--key=42020B87D51877E5AF8D272124F3955B0B8DECC8",
            ],
        }),
    ]
};
test_examples!(sq_key_subkey_password, SQ_KEY_SUBKEY_PASSWORD_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    name = "password",
    about = "Change the password protecting secret key material",
    long_about = "
Change the password protecting secret key material.

Secret key material can be protected by a password.  This subcommand \
changes or clears the password of one or more keys.

To strip the password either use `--clear` or supply a zero-length \
password when prompted for the new password.

If a key is password protected, and the correct password was not \
supplied using the `--password-file` argument, the user is \
prompted for the password.  Likewise, if the new password isn't \
provided, the user is prompted.
",
    after_help = SQ_KEY_SUBKEY_PASSWORD_EXAMPLES,
)]
pub struct PasswordCommand {
    #[command(flatten)]
    pub cert: CertDesignators<CertUserIDEmailFileArgs,
                              NoPrefix,
                              OneValueAndFileRequiresOutput,
                              SubkeyPasswordDoc>,

    #[clap(
        long,
        help = "Change the password of the specified key",
        long_help = "\
Change the password of the specified key.

The key may be either the primary key or a subkey.",
        required = true,
    )]
    pub key: Vec<KeyHandle>,

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

const SQ_KEY_SUBKEY_EXPIRE_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Setup(Setup {
            command: &[
                "sq", "key", "import",
                "alice-secret.pgp",
            ],
        }),
        Action::Example(Example {
            comment: "\
Change Alice's authentication subkey to expire in 6 months.",
            command: &[
                "sq", "key", "subkey", "expire", "6m",
                "--cert=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--key=0D45C6A756A038670FDFD85CB1C82E8D27DB23A1",
            ],
        }),
    ],
};
test_examples!(sq_key_subkey_expire, SQ_KEY_SUBKEY_EXPIRE_EXAMPLES);

/// Documentation for the cert designators for the key password.
pub struct SubkeyPasswordDoc {}

impl AdditionalDocs for SubkeyPasswordDoc {
    fn help(arg: &'static str, help: &'static str) -> clap::builder::StyledStr {
        match arg {
            "file" =>
                "Change the password for the secret key material of the \
                 specified (sub)keys from the key read from PATH"
                .into(),
            _ => {
                debug_assert!(help.starts_with("Use certificates"));
                help.replace("Use certificates",
                             "Change the password for the secret key material \
                              of the specified (sub)keys from the key")
                   .into()
            },
        }
    }
}

#[derive(Debug, Args)]
#[clap(
    name = "expire",
    about = "Change a subkey's expiration time",
    long_about = "\
Change a subkey's expiration time.

This subcommand changes a key's expiration time.  To change the \
expiration time of the certificate, use the `sq key expire` \
subcommand.

Changing the expiration time of the primary key is equivalent to \
changing the certificate's expiration time.  The expiration time \
of a subkey is bound by the expiration of the certificate.
",
    after_help = SQ_KEY_SUBKEY_EXPIRE_EXAMPLES,
)]
#[clap(group(ArgGroup::new("cert_input").args(&["cert_file", "cert"]).required(true)))]
pub struct ExpireCommand {
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

    #[clap(
        long,
        value_name = "FINGERPRINT|KEYID",
        help = "Change the expiration of this subkey",
        required = true,
    )]
    pub key: Vec<KeyHandle>,

    #[clap(
        value_name = "EXPIRATION",
        help = "Sets the key's expiration time",
        long_help = "\
Sets the key's expiration time.

EXPIRATION is either an ISO 8601 formatted string or a custom duration, \
which takes the form `N[ymwds]`, where the letters stand for years, \
months, weeks, days, and seconds, respectively.  Alternatively, the \
keyword `never` does not set an expiration time.

When using an ISO 8601 formatted string, the validity period is from \
the key's creation time to the specified time.  When using a \
duration, the validity period is from the key's creation time \
for the specified duration.",
    )]
    pub expiration: Expiration,

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
                "retired",
                "Subkey rotation.",
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
                "retired",
                "Subkey rotation.",
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
#[clap(group(ArgGroup::new("cert_input").args(&["cert_file", "cert"]).required(true)))]
#[clap(group(ArgGroup::new("revoker_input").args(&["revoker_file", "revoker"])))]
pub struct RevokeCommand {
    #[clap(
        long,
        value_name = "FINGERPRINT|KEYID",
        help = "Revoke the subkey on the specified certificate",
    )]
    pub cert: Option<KeyHandle>,
    #[clap(
        long,
        help = FileOrStdin::HELP_OPTIONAL,
        value_name = "CERT_FILE",
        conflicts_with = "cert",
        help = "Revoke the subkey on the specified certificate",
        long_help = "\
Revoke the subkey on the specified certificate.

Read the certificate whose subkey should be revoked from FILE or \
stdin, if `-`.  It is an error for the file to contain more than one \
certificate.",
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
        long = "key",
        value_name = "FINGERPRINT|KEYID",
        help = "Revoke this subkey",
        required = true,
    )]
    pub keys: Vec<KeyHandle>,

    #[clap(
        value_name = "REASON",
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
        value_name = "MESSAGE",
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
#[clap(group(ArgGroup::new("cert_input").args(&["cert_file", "cert"]).required(true)))]
pub struct BindCommand {
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
    #[clap(
        long,
        value_name = "EXPIRATION",
        help = "Make bound subkeys expire at the given time",
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
