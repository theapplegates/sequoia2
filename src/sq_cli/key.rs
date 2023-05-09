use clap::{ValueEnum, ArgGroup, Args, Parser, Subcommand};

use sequoia_openpgp::cert::CipherSuite as SqCipherSuite;

use crate::sq_cli::types::IoArgs;
use crate::sq_cli::types::Expiry;
use crate::sq_cli::types::Time;
use crate::sq_cli::KEY_VALIDITY_DURATION;

#[derive(Parser, Debug)]
#[clap(
    name = "key",
    about = "Manages keys",
    long_about =
"Manages keys

We use the term \"key\" to refer to OpenPGP keys that do contain
secrets.  This subcommand provides primitives to generate and
otherwise manipulate keys.

Conversely, we use the term \"certificate\", or cert for short, to refer
to OpenPGP keys that do not contain secrets.  See \"sq keyring\" for
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
    Generate(GenerateCommand),
    Password(PasswordCommand),
    #[clap(subcommand)]
    Userid(UseridCommand),
    #[clap(subcommand)]
    Subkey(SubkeyCommand),
    ExtractCert(ExtractCertCommand),
    AttestCertifications(AttestCertificationsCommand),
    Adopt(AdoptCommand),
}

#[derive(Debug, Args)]
#[clap(
    about = "Generates a new key",
    long_about =
"Generates a new key

Generating a key is the prerequisite to receiving encrypted messages
and creating signatures.  There are a few parameters to this process,
but we provide reasonable defaults for most users.

When generating a key, we also generate a revocation certificate.
This can be used in case the key is superseded, lost, or compromised.
It is a good idea to keep a copy of this in a safe place.

After generating a key, use \"sq key extract-cert\" to get the
certificate corresponding to the key.  The key must be kept secure,
while the certificate should be handed out to correspondents, e.g. by
uploading it to a keyserver.

\"sq key generate\" respects the reference time set by the top-level
\"--time\" argument.  It sets the creation time of the key, any
subkeys, and the binding signatures to the reference time.
",
    after_help =
"EXAMPLES:

# First, this generates a key
$ sq key generate --userid \"<juliet@example.org>\" --export juliet.key.pgp

# Then, this extracts the certificate for distribution
$ sq key extract-cert --output juliet.cert.pgp juliet.key.pgp

# Generates a key protecting it with a password
$ sq key generate --userid \"<juliet@example.org>\" --with-password

# Generates a key with multiple userids
$ sq key generate --userid \"<juliet@example.org>\" --userid \"Juliet Capulet\"

# Generates a key whose creation time is June 9, 2011 at midnight UTC
$ sq key generate --time 20110609 --userid \"Noam\" --export noam.pgp
",
)]
#[clap(group(ArgGroup::new("cap-sign").args(&["can_sign", "cannot_sign"])))]
#[clap(group(ArgGroup::new("cap-authenticate").args(&["can_authenticate", "cannot_authenticate"])))]
#[clap(group(ArgGroup::new("cap-encrypt").args(&["can_encrypt", "cannot_encrypt"])))]
pub struct GenerateCommand {
    #[clap(
        short = 'u',
        long = "userid",
        value_name = "EMAIL",
        help = "Adds a userid to the key"
    )]
    pub userid: Vec<String>,
    #[clap(
        short = 'c',
        long = "cipher-suite",
        value_name = "CIPHER-SUITE",
        default_value_t = CipherSuite::Cv25519,
        help = "Selects the cryptographic algorithms for the key",
        value_enum,
    )]
    pub cipher_suite: CipherSuite,
    #[clap(
        long = "with-password",
        help = "Protects the key with a password",
    )]
    pub with_password: bool,
    #[clap(
        long = "expiry",
        value_name = "EXPIRY",
        default_value_t = Expiry::Duration(KEY_VALIDITY_DURATION),
        help =
            "Defines EXPIRY for the key as ISO 8601 formatted string or \
            custom duration.",
        long_help =
            "Defines EXPIRY for the key as ISO 8601 formatted string or \
            custom duration. \
            If an ISO 8601 formatted string is provided, the validity period \
            reaches from the reference time (may be set using \"--time\") to \
            the provided time. \
            Custom durations starting from the reference time may be set using \
            \"N[ymwds]\", for N years, months, weeks, days, or seconds. \
            The special keyword \"never\" sets an unlimited expiry.",
    )]
    pub expiry: Expiry,
    #[clap(
        long = "can-sign",
        help ="Adds a signing-capable subkey (default)",
    )]
    pub can_sign: bool,
    #[clap(
        long = "cannot-sign",
        help = "Adds no signing-capable subkey",
    )]
    pub cannot_sign: bool,
    #[clap(
        long = "can-authenticate",
        help = "Adds an authentication-capable subkey (default)",
    )]
    pub can_authenticate: bool,
    #[clap(
        long = "cannot-authenticate",
        help = "Adds no authentication-capable subkey",
    )]
    pub cannot_authenticate: bool,
    #[clap(
        long = "can-encrypt",
        value_name = "PURPOSE",
        help = "Adds an encryption-capable subkey [default: universal]",
        long_help =
            "Adds an encryption-capable subkey. \
            Encryption-capable subkeys can be marked as \
            suitable for transport encryption, storage \
            encryption, or both, i.e., universal. \
            [default: universal]",
        value_enum,
    )]
    pub can_encrypt: Option<EncryptPurpose>,
    #[clap(
        long = "cannot-encrypt",
        help = "Adds no encryption-capable subkey",
    )]
    pub cannot_encrypt: bool,
    #[clap(
        short = 'e',
        long = "export",
        value_name = "OUTFILE",
        help = "Writes the key to OUTFILE",
    )]
    // TODO this represents a filename, so it should be a Path
    pub export: Option<String>,
    #[clap(
        long = "rev-cert",
        value_name = "FILE or -",
        required_if_eq("export", "-"),
        help = "Writes the revocation certificate to FILE",
        long_help =
            "Writes the revocation certificate to FILE. \
            mandatory if OUTFILE is \"-\". \
            [default: <OUTFILE>.rev]",
    )]
    // TODO this represents a filename, so it should be a Path
    pub rev_cert: Option<String>
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

#[derive(ValueEnum, Clone, Debug)]
pub enum EncryptPurpose {
    Transport,
    Storage,
    Universal
}

#[derive(Debug, Args)]
#[clap(
    name = "password",
    about = "Changes password protecting secrets",
    long_about = 
"Changes password protecting secrets

Secret key material in keys can be protected by a password.  This
subcommand changes or clears this encryption password.

To emit the key with unencrypted secrets, either use `--clear` or
supply a zero-length password when prompted for the new password.
",
    after_help =
"EXAMPLES:

# First, generate a key
$ sq key generate --userid \"<juliet@example.org>\" --export juliet.key.pgp

# Then, encrypt the secrets in the key with a password.
$ sq key password < juliet.key.pgp > juliet.encrypted_key.pgp

# And remove the password again.
$ sq key password --clear < juliet.encrypted_key.pgp > juliet.decrypted_key.pgp
",
)]
pub struct PasswordCommand {
    #[clap(flatten)]
    pub io: IoArgs,
    #[clap(
        long = "clear",
        help = "Emit a key with unencrypted secrets",
    )]
    pub clear: bool,
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,
}

#[derive(Debug, Args)]
#[clap(
    name = "extract-cert",
    about = "Converts a key to a cert",
    long_about =
"Converts a key to a cert

After generating a key, use this command to get the certificate
corresponding to the key.  The key must be kept secure, while the
certificate should be handed out to correspondents, e.g. by uploading
it to a keyserver.
",
    after_help = "EXAMPLES:

# First, this generates a key
$ sq key generate --userid \"<juliet@example.org>\" --export juliet.key.pgp

# Then, this extracts the certificate for distribution
$ sq key extract-cert --output juliet.cert.pgp juliet.key.pgp
",
)]
pub struct ExtractCertCommand {
    #[clap(flatten)]
    pub io: IoArgs,
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,
}

#[derive(Debug, Subcommand)]
#[clap(
    name = "userid",
    about = "Manages User IDs",
    long_about =
"Manages User IDs

Add User IDs to, or strip User IDs from a key.
",
    subcommand_required = true,
    arg_required_else_help = true,
)]
pub enum UseridCommand {
    Add(UseridAddCommand),
    Strip(UseridStripCommand),
}

#[derive(Debug, Args)]
#[clap(
    about = "Adds a User ID",
    long_about =
"Adds a User ID

A User ID can contain a name, like \"Juliet\" or an email address, like
\"<juliet@example.org>\".  Historically, a name and email address were often
combined as a single User ID, like \"Juliet <juliet@example.org>\".

\"sq userid add\" respects the reference time set by the top-level
\"--time\" argument.  It sets the creation time of the User ID's
binding signature to the specified time.
",
    after_help =
"EXAMPLES:

# First, this generates a key
$ sq key generate --userid \"<juliet@example.org>\" --export juliet.key.pgp

# Then, this adds a User ID
$ sq key userid add --userid \"Juliet\" juliet.key.pgp \\
  --output juliet-new.key.pgp

# This adds a User ID whose creation time is set to June 28, 2022 at
# midnight UTC:
$ sq key userid add --userid \"Juliet\" --creation-time 20210628 \\
   juliet.key.pgp --output juliet-new.key.pgp
",
)]
pub struct UseridAddCommand {
    #[clap(flatten)]
    pub io: IoArgs,
    #[clap(
        value_name = "USERID",
        short,
        long,
        help = "User ID to add",
    )]
    pub userid: Vec<String>,
    #[clap(
        long = "private-key-store",
        value_name = "KEY_STORE",
        help = "Provides parameters for private key store",
    )]
    pub private_key_store: Option<String>,
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,
}


#[derive(Debug, Args)]
#[clap(
    about = "Strips a User ID",
    long_about =
"Strips a User ID

Note that this operation does not reliably remove User IDs from a
certificate that has already been disseminated! (OpenPGP software
typically appends new information it receives about a certificate
to its local copy of that certificate.  Systems that have obtained
a copy of your certificate with the User ID that you are trying to
strip will not drop that User ID from their copy.)

In most cases, you will want to use the 'sq revoke userid' operation
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

# First, this generates a key
$ sq key generate --userid \"<juliet@example.org>\" --export juliet.key.pgp

# Then, this strips a User ID
$ sq key userid strip --userid \"<juliet@example.org>\" \\
  --output juliet-new.key.pgp juliet.key.pgp
",
)]
pub struct UseridStripCommand {
    #[clap(flatten)]
    pub io: IoArgs,
    #[clap(
        value_name = "USERID",
        short,
        long,
        help = "User IDs to strip",
        long_help = "The User IDs to strip.  Values must exactly match a \
User ID."
    )]
    pub userid: Vec<String>,
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,
}

#[derive(Debug, Args)]
#[clap(
    name = "adopt",
    about = "Binds keys from one certificate to another",
    long_about =
"Binds keys from one certificate to another

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
$ sq key adopt --keyring juliet-old.pgp --key 0123456789ABCDEF -- juliet-new.pgp
",
)]
pub struct AdoptCommand {
    #[clap(
        short = 'r',
        long = "keyring",
        value_name = "KEY-RING",
        help = "Supplies keys for use in --key.",
    )]
    pub keyring: Vec<String>,
    #[clap(
        short = 'k',
        long = "key",
        value_name = "KEY",
        required(true),
        help = "Adds the key or subkey KEY to the TARGET-KEY",
    )]
    // TODO Type should be KeyHandle, improve help
    pub key: Vec<String>,
    #[clap(
        long = "expire",
        value_name = "KEY-EXPIRATION-TIME",
        help = "Makes adopted subkeys expire at the given time",
    )]
    pub expire: Option<Time>,
    #[clap(
        long = "allow-broken-crypto",
        help = "Allows adopting keys from certificates \
            using broken cryptography",
    )]
    pub allow_broken_crypto: bool,
    #[clap(
        value_name = "TARGET-KEY",
        help = "Adds keys to TARGET-KEY",
    )]
    pub certificate: Option<String>,
    #[clap(
        short,
        long,
        value_name = "FILE",
        help = "Writes to FILE or stdout if omitted"
    )]
    pub output: Option<String>,
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,
}

#[derive(Debug, Args)]
#[clap(
    name = "attest-certifications",
    about = "Attests to third-party certifications",
    long_about =
"Attests to third-party certifications allowing for their distribution

To prevent certificate flooding attacks, modern key servers prevent
uncontrolled distribution of third-party certifications on
certificates.  To make the key holder the sovereign over the
information over what information is distributed with the certificate,
the key holder needs to explicitly attest to third-party
certifications.

After the attestation has been created, the certificate has to be
distributed, e.g. by uploading it to a keyserver.
",
    after_help =
"EXAMPLES:

# Attest to all certifications present on the key
$ sq key attest-certifications juliet.pgp

# Retract prior attestations on the key
$ sq key attest-certifications --none juliet.pgp
",
)]
pub struct AttestCertificationsCommand {
    #[clap(
        long = "none",
        conflicts_with = "all",
        help = "Removes all prior attestations",
    )]
    pub none: bool,
    #[clap(
        long = "all",
        conflicts_with = "none",
        help = "Attests to all certifications [default]",
    )]
    pub all: bool,
    #[clap(
        value_name = "KEY",
        help = "Changes attestations on KEY",
    )]
    pub key: Option<String>,
    #[clap(
        short,
        long,
        value_name = "FILE",
        help = "Writes to FILE or stdout if omitted"
    )]
    pub output: Option<String>,
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,

}

#[derive(Debug, Subcommand)]
#[clap(
    name = "subkey",
    about = "Manages Subkeys",
    long_about =
"Manages Subkeys

Add new subkeys to an existing key.
",
    subcommand_required = true,
    arg_required_else_help = true,
)]
#[non_exhaustive]
pub enum SubkeyCommand {
    Add(SubkeyAddCommand),
}

#[derive(Debug, Args)]
#[clap(
    about = "Adds a newly generated Subkey",
    long_about =
"Adds a newly generated Subkey

A subkey has one or more flags. \"--can-sign\" sets the signing flag,
and means that the key may be used for signing. \"--can-authenticate\"
sets the authentication flags, and means that the key may be used for
authentication (e.g., as an SSH key). These two flags may be combined.

\"--can-encrypt=storage\" sets the storage encryption flag, and means that the key
may be used for storage encryption. \"--can-encrypt=transport\" sets the transport
encryption flag, and means that the key may be used for transport encryption.
\"--can-encrypt=universal\" sets both the storage and the transport encryption
flag, and means that the key may be used for both storage and transport
encryption. Only one of the encryption flags may be used and it can not be
combined with the signing or authentication flag.

At least one flag must be chosen.

Furthermore the subkey may use one of several available cipher suites, that can
be selected using \"--cipher-suite\".

By default a new subkey never expires. However, its validity period is limited
by that of the primary key it is added for.
Using the \"--expiry=EXPIRY\" argument specific validity periods may be defined.
It allows for providing a point in time for validity to end or a validity
duration.

\"sq key subkey add\" respects the reference time set by the top-level
\"--time\" argument. It sets the creation time of the subkey to the specified
time.
",
    after_help =
"EXAMPLES:

# First, this generates a key
$ sq key generate --userid \"alice <alice@example.org>\" --export alice.key.pgp

# Add a new Subkey for universal encryption which expires at the same time as
# the primary key
$ sq key subkey add --output alice-new.key.pgp --can-encrypt universal alice.key.pgp

# Add a new Subkey for signing using the rsa3k cipher suite which expires in five days
$ sq key subkey add --output alice-new.key.pgp --can-sign --cipher-suite rsa3k --expiry 5d alice.key.pgp
",
)]
#[clap(group(ArgGroup::new("authentication-group").args(&["can_authenticate", "can_encrypt"])))]
#[clap(group(ArgGroup::new("sign-group").args(&["can_sign", "can_encrypt"])))]
#[clap(group(ArgGroup::new("required-group").args(&["can_authenticate", "can_sign", "can_encrypt"]).required(true)))]
pub struct SubkeyAddCommand {
    #[clap(flatten)]
    pub io: IoArgs,
    #[clap(
        long = "private-key-store",
        value_name = "KEY_STORE",
        help = "Provides parameters for private key store",
    )]
    pub private_key_store: Option<String>,
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,
    #[clap(
        short = 'c',
        long = "cipher-suite",
        value_name = "CIPHER-SUITE",
        default_value_t = CipherSuite::Cv25519,
        help = "Selects the cryptographic algorithms for the subkey",
        value_enum,
    )]
    pub cipher_suite: CipherSuite,
    #[clap(
        long = "expiry",
        value_name = "EXPIRY",
        default_value_t = Expiry::Never,
        help =
            "Defines EXPIRY for the subkey as ISO 8601 formatted string or \
            custom duration.",
        long_help =
            "Defines EXPIRY for the subkey as ISO 8601 formatted string or \
            custom duration. \
            If an ISO 8601 formatted string is provided, the validity period \
            reaches from the reference time (may be set using \"--time\") to \
            the provided time. \
            Custom durations starting from the reference time may be set using \
            \"N[ymwds]\", for N years, months, weeks, days, or seconds. \
            The special keyword \"never\" sets an unlimited expiry.",
    )]
    pub expiry: Expiry,
    #[clap(
        long = "can-sign",
        help = "Adds signing capability to subkey",
    )]
    pub can_sign: bool,
    #[clap(
        long = "can-authenticate",
        help = "Adds authentication capability to subkey",
    )]
    pub can_authenticate: bool,
    #[clap(
        long = "can-encrypt",
        value_name = "PURPOSE",
        help = "Adds an encryption capability to subkey [default: universal]",
        long_help =
            "Adds an encryption capability to subkey. \
            Encryption-capable subkeys can be marked as \
            suitable for transport encryption, storage \
            encryption, or both, i.e., universal. \
            [default: universal]",
        value_enum,
    )]
    pub can_encrypt: Option<EncryptPurpose>,
}
