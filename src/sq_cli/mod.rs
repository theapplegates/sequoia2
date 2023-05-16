use std::path::PathBuf;

/// Command-line parser for sq.
use clap::{Command, CommandFactory, Parser, Subcommand};

#[cfg(feature = "autocrypt")]
pub mod autocrypt;

use sequoia_openpgp as openpgp;
use openpgp::Fingerprint;

pub mod armor;
pub mod certify;
pub mod dane;
mod dearmor;
mod decrypt;
pub mod encrypt;
pub mod export;
pub mod import;
pub mod inspect;
pub mod key;
pub mod keyring;
pub mod keyserver;
pub mod link;
mod output_versions;
pub mod packet;
pub mod revoke;
mod sign;
mod verify;
pub mod wkd;
pub mod wot;

pub mod types;

/// The seconds in a day
pub const SECONDS_IN_DAY : u64 = 24 * 60 * 60;
/// The seconds in a year
pub const SECONDS_IN_YEAR : u64 =
    // Average number of days in a year.
    (365.2422222 * SECONDS_IN_DAY as f64) as u64;

pub fn build() -> Command {
    let sq_version = Box::leak(
        format!(
            "{} (sequoia-openpgp {}, using {})",
            env!("CARGO_PKG_VERSION"),
            sequoia_openpgp::VERSION,
            sequoia_openpgp::crypto::backend()
        )
        .into_boxed_str(),
    ) as &str;
    SqCommand::command().version(sq_version)
}

/// Defines the CLI.
#[derive(Parser, Debug)]
#[clap(
    name = "sq",
    about = "A command-line frontend for Sequoia, an implementation of OpenPGP",
    long_about = "A command-line frontend for Sequoia, an implementation of OpenPGP

Functionality is grouped and available using subcommands.  This
interface is not completely stateless.  In particular, the user's
default certificate store is used.  This can be disabled using
\"--no-cert-store\".

OpenPGP data can be provided in binary or ASCII armored form.  This
will be handled automatically.  Emitted OpenPGP data is ASCII armored
by default.

We use the term \"certificate\", or cert for short, to refer to OpenPGP
keys that do not contain secrets.  Conversely, we use the term \"key\"
to refer to OpenPGP keys that do contain secrets.
",
    subcommand_required = true,
    arg_required_else_help = true,
    disable_colored_help = true,
)]
pub struct SqCommand {
    #[clap(
        short = 'f',
        long = "force",
        help = "Overwrites existing files"
    )]
    pub force: bool,
    #[clap(
        long,
        help = "Disables the use of a certificate store",
        long_help = "\
Disables the use of a certificate store.  Normally sq uses the user's \
standard cert-d, which is located in $HOME/.local/share/pgp.cert.d."
    )]
    pub no_cert_store: bool,
    #[clap(
        long,
        value_name = "PATH",
        env = "SQ_CERT_STORE",
        conflicts_with_all = &[ "no_cert_store" ],
        help = "Specifies the location of the certificate store",
        long_help = "\
Specifies the location of the certificate store.  By default, sq uses \
the OpenPGP certificate directory at `$HOME/.local/share/pgp.cert.d`, \
and creates it if it does not exist."
    )]
    pub cert_store: Option<PathBuf>,
    #[clap(
        long,
        value_name = "PATH",
        env = "PEP_CERT_STORE",
        help = "Specifies the location of a pEp certificate store",
        long_help = "\
Specifies the location of a pEp certificate store.  sq does not use a \
pEp certificate store by default; it must be explicitly enabled \
using this argument or the corresponding environment variable, \
PEP_CERT_STORE.  The pEp Engine's default certificate store is at \
\"$HOME/.pEp/keys.db\"."
    )]
    pub pep_cert_store: Option<PathBuf>,
    #[clap(
        long,
        value_name = "PATH",
        help = "Specifies the location of a keyring to use",
        long_help = "\
Specifies the location of a keyring to use.  Keyrings are used in \
addition to any certificate store.  The content of the keyring is \
not imported into the certificate store.  When a certificate is \
looked up, it is looked up in all keyrings and any certificate \
store, and the results are merged together."
    )]
    pub keyring: Vec<PathBuf>,
    #[clap(
        long = "output-format",
        value_name = "FORMAT",
        value_parser = ["human-readable", "json", "dot"],
        default_value = "human-readable",
        env = "SQ_OUTPUT_FORMAT",
        help = "Produces output in FORMAT, if possible",
    )]
    pub output_format: String,
    #[clap(
        long = "output-version",
        value_name = "VERSION",
        env = "SQ_OUTPUT_VERSION",
        help = "Produces output variant VERSION.",
        long_help = "Produces output variant VERSION, such as 0.0.0. \
                     The default is the newest version. The output version \
                     is separate from the version of the sq program. To see \
                     the current supported versions, use output-versions \
                     subcommand."
    )]
    pub output_version: Option<String>,
    #[clap(
        long = "known-notation",
        value_name = "NOTATION",
        help = "Adds NOTATION to the list of known notations",
        long_help = "Adds NOTATION to the list of known notations. \
            This is used when validating signatures. \
            Signatures that have unknown notations with the \
            critical bit set are considered invalid."
    )]
    // TODO is this the right type?
    pub known_notation: Vec<String>,
    #[clap(
        long = "time",
        value_name = "TIME",
        help = "Sets the reference time as ISO 8601 formatted timestamp",
        global = true,
        long_help = "\
Sets the reference time as an ISO 8601 formatted timestamp.  Normally, \
commands use the current time as the reference time.  This argument allows \
the user to use a difference reference time.  For instance, when creating a \
key using \"sq key generate\", the creation time is normally set to the \
current time, but can be overridden using this option.  Similarly, when \
verifying a message, the message is verified with respect to the current \
time.  This option allows the user to use a different time.

TIME is interpreted as an ISO 8601 timestamp.  To set the \
certification time to June 9, 2011 at midnight UTC, you can do:

$ sq --time 20130721 verify msg.pgp

To include a time, add a T, the time and optionally the timezone (the \
default timezone is UTC):

$ sq --time 20130721T0550+0200 verify msg.pgp
",
    )]
    pub time: Option<String>,
    #[clap(
        long = "trust-root",
        value_name = "FINGERPRINT|KEYID",
        help = "Considers the specified certificate to be a trust root",
        long_help = "Considers the specified certificate to be a trust root. \
                     Trust roots are used by trust models, e.g., the web of \
                     trust, to authenticate certificates and User IDs."
    )]
    pub trust_roots: Vec<Fingerprint>,
    #[clap(subcommand)]
    pub subcommand: SqSubcommands,
}

/// The order of top-level subcommands is:
///
///   - Encryption & decryption
///   - Signing & verification
///   - Key & cert-ring management
///   - Key discovery & networking
///   - Armor
///   - Inspection & packet manipulation
///
/// The order is derived from the order of variants in this enum.
#[derive(Debug, Subcommand)]
pub enum SqSubcommands {
    Encrypt(encrypt::Command),
    Decrypt(decrypt::Command),

    Sign(sign::Command),
    Verify(verify::Command),

    Key(key::Command),
    Keyring(keyring::Command),
    Import(import::Command),
    Export(export::Command),
    Certify(certify::Command),
    Link(link::Command),
    Wot(wot::Command),

    #[cfg(feature = "autocrypt")]
    Autocrypt(autocrypt::Command),
    Keyserver(keyserver::Command),
    Wkd(wkd::Command),
    Dane(dane::Command),

    Armor(armor::Command),
    Dearmor(dearmor::Command),

    Inspect(inspect::Command),
    Packet(packet::Command),

    Revoke(revoke::Command),

    OutputVersions(output_versions::Command),
}
