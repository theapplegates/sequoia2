// XXX: The following comment should be an inner comment, but cannot
// until https://github.com/rust-lang/rust/issues/66920 is resolved.

/// Defines the command-line interface.
///
/// This module contains sq's command-line interface, i.e. the clap
/// definitions and associated types that can be used by clap.
///
/// We also generate manual pages from this module.  To that end,
/// `build.rs` includes this module, so all of its dependencies must
/// be also listed as build-dependencies.  Further, this module must
/// be self-contained, i.e. it must not use code from other parts of
/// sq.
///
/// # Interface guidelines
///
/// In order to provide a consistent user experience, please follow
/// these guidelines.
///
/// ## General guidelines
///
/// - The same subcommand or option in different places should do the
///   same or an equivalent thing, and should use the same phrases in
///   the help texts, to the extent possible.
///
/// - Subcommands SHOULD be of the form `sq [OBJECT..] VERB`.
///
///   - The object SHOULD be present, except for the top level
///     commands `encrypt`, `decrypt`, `sign`, `verify`, and
///     `inspect`.
///
/// - Subcommands SHOULD be grouped by topic, and ordered from most
///   often used to least often used.
///
/// - Use the imperative mood in the first sentence documenting
///   commands, subcommands, and arguments.
///
/// ## Terminology
///
/// - "certificate" or "cert" instead of "public key", "key", or
///   "TPK".
///
/// - "key" instead of "secret key", "private key", or "TSK".
///
/// - "key server" instead of "keyserver".
///
/// - "Web of Trust" instead of other variations.
///
/// ## Typography
///
/// - The first line of the about texts MUST NOT end in a period.
///
/// - To define terms, enclose them in double quotes: `"certificate"`.
///
/// - To include inline code fragments, like options or other
///   subcommands, use back ticks: `--foo` or `sq foo bar`.
///
/// - When referring to options, do not include the `VALUENAME`.
///
/// - Enclose URLs in angle brackets: `<https://example.org>`.
///
/// - Use a spaced en dash for parenthetical statements (` – `).
///
/// ## Examples
///
/// - Every subcommand SHOULD have at least one example.
///
/// - Every example MUST have a brief description.
///
/// - Examples SHOULD be short and to the point, they SHOULD NOT
///   include unnecessary options (like `--keyring`).
///
/// - Examples MUST use single quotes where necessary.
///
/// - Examples MUST NOT use unnecessary quoting.
// Workaround so that the above documentation is rendered somewhere in
// the API docs.
#[allow(dead_code)]
pub const USER_INTERFACE_GUIDELINES: () = ();

use std::fmt::Write;
use std::path::PathBuf;
use std::time::Duration;

/// Command-line parser for sq.
use clap::{Command, CommandFactory, Parser, Subcommand};
use clap::builder::StyledStr;

use sequoia_openpgp as openpgp;
use openpgp::Fingerprint;

#[macro_use]
pub mod examples;

pub mod autocrypt;
pub mod cert;
pub mod decrypt;
pub mod encrypt;
pub mod inspect;
pub mod key;
pub mod network;
pub mod output;
pub mod pki;
pub mod sign;
pub mod toolbox;
pub mod verify;
pub mod version;

pub mod types;
use types::paths::{AbsolutePathOrDefault, AbsolutePathOrDefaultValueParser};

/// The seconds in a day
pub const SECONDS_IN_DAY : u64 = 24 * 60 * 60;
/// The seconds in a year
pub const SECONDS_IN_YEAR : u64 =
    // Average number of days in a year.
    (365.2422222 * SECONDS_IN_DAY as f64) as u64;
/// The default validity (in years) for keys and subkeys
pub const KEY_VALIDITY_IN_YEARS: u64 = 3;
/// The default validity period (as Duration) for keys and subkeys
pub const KEY_VALIDITY_DURATION: Duration =
    Duration::new(SECONDS_IN_YEAR * KEY_VALIDITY_IN_YEARS, 0);
/// The default validity (in years) for third party certifications
pub const THIRD_PARTY_CERTIFICATION_VALIDITY_IN_YEARS: u64 = 5;
/// The default validity period (as Duration) for third party certifications
pub const THIRD_PARTY_CERTIFICATION_VALIDITY_DURATION: Duration = Duration::new(
    SECONDS_IN_YEAR * THIRD_PARTY_CERTIFICATION_VALIDITY_IN_YEARS,
    0,
);

pub const GLOBAL_OPTIONS_HEADER: &str = "Global Options";

/// Builds the top-level Clap command.
///
/// If `globals_hidden` is true, then top-level, global arguments are
/// marked as hidden, which means they won't be displayed in the help
/// output.
pub fn build(globals_hidden: bool) -> Command {
    let sq_version = Box::leak(
        format!(
            "{} (sequoia-openpgp {}, using {})",
            env!("CARGO_PKG_VERSION"),
            sequoia_openpgp::VERSION,
            sequoia_openpgp::crypto::backend()
        )
        .into_boxed_str(),
    ) as &str;

    let mut command = SqCommand::command().version(sq_version);

    // Change the globals to be hidden.
    if globals_hidden {
        fn add_after_help(command: &mut Command) {
            // We want to append to after_long_help.
            let mut after_long_help
                = if let Some(s) = command.get_after_long_help() {
                    let mut s = s.clone();
                    s.write_char('\n').expect("Can write to string");
                    s.write_char('\n').expect("Can write to string");
                    s
                } else if let Some(s) = command.get_after_help() {
                    // If after_long_help is not explicitly set, it
                    // falls back to after_help.  If we set
                    // after_long_help, the fallback no longer happens
                    // so we need to do it manually.
                    let mut s = s.clone();
                    s.write_char('\n').expect("Can write to string");
                    s.write_char('\n').expect("Can write to string");
                    s
                } else {
                    StyledStr::new()
                };

            after_long_help.write_str(&format!("\
{}:\nSee 'sq --help' for a description of the global options.",
                                               GLOBAL_OPTIONS_HEADER))
                .expect("Can write to string");

            *command = command.clone()
                .after_long_help(after_long_help);

            for sc in command.get_subcommands_mut() {
                add_after_help(sc);
            }
        }

        command = command
            .mut_args(|mut a| {
                if a.is_global_set() {
                    a = a.hide(globals_hidden);
                }
                a
            });

        add_after_help(&mut command);
    };

    command
}

/// Defines the CLI.
#[derive(Parser, Debug)]
#[clap(
    name = "sq",
    about = "A command-line frontend for Sequoia, an implementation of OpenPGP",
    long_about = "A command-line frontend for Sequoia, an implementation of OpenPGP

Functionality is grouped and available using subcommands.  This \
interface is not completely stateless.  In particular, the user's \
default certificate store is used.  This can be disabled using \
`--no-cert-store`.  Similarly, a key store is used to manage and \
protect secret key material.  This can be disabled using \
`--no-key-store`.

OpenPGP data can be provided in binary or ASCII armored form.  This \
will be handled automatically.  Emitted OpenPGP data is ASCII armored \
by default.

We use the term \"certificate\", or \"cert\" for short, to refer to OpenPGP \
keys that do not contain secrets.  Conversely, we use the term \"key\" \
to refer to OpenPGP keys that do contain secrets.
",
    subcommand_required = true,
    arg_required_else_help = true,
    disable_colored_help = true,
    disable_version_flag = true,
)]
pub struct SqCommand {
    #[clap(
        long = "overwrite",
        global = true,
        help_heading = GLOBAL_OPTIONS_HEADER,
        help = "Overwrite existing files",
    )]
    pub overwrite: bool,

    #[clap(
        long,
        value_name = "PATH",
        env = "SEQUOIA_HOME",
        global = true,
        help_heading = GLOBAL_OPTIONS_HEADER,
        help = "Set the home directory.",
        long_help = format!("\
Set the home directory.

Sequoia's default home directory is `{}`.  When using the default \
location, files are placed according to the local standard, \
e.g., the XDG Base Directory Specification.  When an alternate \
location is specified, the user data, configuration files, and \
cache data are placed under a single, unified directory.  This is \
a lightweight way to partially isolate `sq`.",
            sequoia_directories::Home::default_location()
                .map(|p| {
                    let p = p.display().to_string();
                    if let Some(home) = dirs::home_dir() {
                        let home = home.display().to_string();
                        if let Some(rest) = p.strip_prefix(&home) {
                            return format!("$HOME{}", rest);
                        }
                    }
                    p
                })
                .unwrap_or("<unknown>".to_string())),
        value_parser = AbsolutePathOrDefaultValueParser::default(),
    )]
    pub home: Option<AbsolutePathOrDefault>,

    #[clap(
        long,
        global = true,
        help_heading = GLOBAL_OPTIONS_HEADER,
        help = "Disable the use of the key store.",
        long_help = "\
Disable the use of the key store.

It is still possible to use functionality that does not require the
key store."
    )]
    pub no_key_store: bool,

    #[clap(
        long,
        value_name = "PATH",
        env = "SEQUOIA_KEY_STORE",
        conflicts_with_all = &[ "no_key_store" ],
        global = true,
        help_heading = GLOBAL_OPTIONS_HEADER,
        help = "Override the key store server and its data",
        long_help = format!("\
A key store server manages and protects secret key material.  By \
default, `sq` connects to the key store server for Sequoia's default \
home directory (see `--home`), {}.  If no key store server is running, \
one is started.

This option causes `sq` to use an alternate key store server.  If \
necessary, a key store server is started, and configured to look for \
its data in the specified location.",
            sequoia_directories::Home::default()
                .map(|home| {
                    let p = home.data_dir(sequoia_directories::Component::Keystore);
                    let p = p.display().to_string();
                    if let Some(home) = dirs::home_dir() {
                        let home = home.display().to_string();
                        if let Some(rest) = p.strip_prefix(&home) {
                            return format!("$HOME{}", rest);
                        }
                    }
                    p
                })
                .unwrap_or("<unknown>".to_string())),
        value_parser = AbsolutePathOrDefaultValueParser::default(),
    )]
    pub key_store: Option<AbsolutePathOrDefault>,

    #[clap(
        long,
        global = true,
        help_heading = GLOBAL_OPTIONS_HEADER,
        help = "Disable the use of a certificate store",
        long_help = "\
Disable the use of a certificate store.  Normally sq uses the user's \
standard cert-d, which is located in `$HOME/.local/share/pgp.cert.d`."
    )]
    pub no_cert_store: bool,

    #[clap(
        long,
        value_name = "PATH",
        env = "SEQUOIA_CERT_STORE",
        conflicts_with_all = &[ "no_cert_store" ],
        global = true,
        help_heading = GLOBAL_OPTIONS_HEADER,
        help = "Specify the location of the certificate store",
        long_help = format!("\
Specify the location of the certificate store.  By default, `sq` uses \
the OpenPGP certificate directory in Sequoia's home directory (see `--home`), \
{}.  This can be overridden by setting the `PGP_CERT_D` environment \
variable.  That in turn can be overridden by setting the `SEQUOIA_CERT_STORE` \
environment variable.",
            sequoia_directories::Home::default()
                .map(|home| {
                    let p = home.data_dir(sequoia_directories::Component::CertD);
                    let p = p.display().to_string();
                    if let Some(home) = dirs::home_dir() {
                        let home = home.display().to_string();
                        if let Some(rest) = p.strip_prefix(&home) {
                            return format!("$HOME{}", rest);
                        }
                    }
                    p
                })
                .unwrap_or("<unknown>".to_string())),
        value_parser = AbsolutePathOrDefaultValueParser::default(),
    )]
    pub cert_store: Option<AbsolutePathOrDefault>,

    #[clap(
        long,
        value_name = "PATH",
        env = "PEP_CERT_STORE",
        global = true,
        help_heading = GLOBAL_OPTIONS_HEADER,
        help = "Specify the location of a pEp certificate store",
        long_help = "\
Specify the location of a pEp certificate store.  sq does not use a \
pEp certificate store by default; it must be explicitly enabled \
using this argument or the corresponding environment variable, \
PEP_CERT_STORE.  The pEp Engine's default certificate store is at \
`$HOME/.pEp/keys.db`."
    )]
    pub pep_cert_store: Option<PathBuf>,
    #[clap(
        long,
        value_name = "PATH",
        global = true,
        help_heading = GLOBAL_OPTIONS_HEADER,
        help = "Specify the location of a keyring to use",
        long_help = "\
Specify the location of a keyring to use.  Keyrings are used in \
addition to any certificate store.  The content of the keyring is \
not imported into the certificate store.  When a certificate is \
looked up, it is looked up in all keyrings and any certificate \
store, and the results are merged together."
    )]
    pub keyring: Vec<PathBuf>,

    #[clap(
        long = "known-notation",
        value_name = "NOTATION",
        global = true,
        help_heading = GLOBAL_OPTIONS_HEADER,
        help = "Add NOTATION to the list of known notations",
        long_help = "Add NOTATION to the list of known notations. \
            This is used when validating signatures. \
            Signatures that have unknown notations with the \
            critical bit set are considered invalid."
    )]
    // TODO is this the right type?
    pub known_notation: Vec<String>,
    #[clap(
        long = "time",
        value_name = "TIME",
        help = "Set the reference time as ISO 8601 formatted timestamp",
        global = true,
        help_heading = GLOBAL_OPTIONS_HEADER,
        long_help = "\
Set the reference time as an ISO 8601 formatted timestamp.  Normally, \
commands use the current time as the reference time.  This argument allows \
the user to use a difference reference time.  For instance, when creating a \
key using `sq key generate`, the creation time is normally set to the \
current time, but can be overridden using this option.  Similarly, when \
verifying a message, the message is verified with respect to the current \
time.  This option allows the user to use a different time.

TIME is interpreted as an ISO 8601 timestamp.  To set the \
certification time to July 21, 2013 at midnight UTC, you can do:

$ sq --time 20130721 verify msg.pgp

To include a time, say 5:50 AM, add a T, the time and optionally the timezone \
(the default timezone is UTC):

$ sq --time 20130721T0550+0200 verify msg.pgp
",
    )]
    pub time: Option<types::Time>,
    #[clap(
        long = "trust-root",
        value_name = "FINGERPRINT|KEYID",
        global = true,
        help_heading = GLOBAL_OPTIONS_HEADER,
        help = "Consider the specified certificate to be a trust root",
        long_help = "Consider the specified certificate to be a trust root. \
                     Trust roots are used by trust models, e.g., the Web of \
                     Trust, to authenticate certificates and User IDs."
    )]
    pub trust_roots: Vec<Fingerprint>,
    #[clap(
        long,
        value_name = "FILE",
        global = true,
        help_heading = GLOBAL_OPTIONS_HEADER,
        help = "Seed the password cache with the specified password",
        long_help = "\
Seed the password cache with the specified password.

The password is added to the password cache.  When decrypting secret \
key material, the password cache is only used if the key is not \
protected by a retry counter, which automatically locks the key if \
a wrong password is entered too many times.

Note that the entire key file will be used as the password, including \
any surrounding whitespace like a trailing newline.",
    )]
    pub password_file: Vec<PathBuf>,

    #[clap(
        short = 'v',
        long,
        global = true,
        help_heading = GLOBAL_OPTIONS_HEADER,
        help = "Be more verbose.",
    )]
    pub verbose: bool,

    #[clap(
        short = 'q',
        long = "quiet",
        global = true,
        help_heading = GLOBAL_OPTIONS_HEADER,
        help = "Be more quiet.",
        conflicts_with = "verbose",
    )]
    pub quiet: bool,

    #[clap(
        long = "batch",
        global = true,
        help_heading = GLOBAL_OPTIONS_HEADER,
        help = "Prevents any kind of prompting",
        long_help = "\
Prevents any kind of prompting

Enables batch mode.  In batch mode, sq will never ask for user input,
such as prompting for passwords.
",
    )]
    pub batch: bool,

    #[clap(subcommand)]
    pub subcommand: SqSubcommands,
}

/// The order of top-level subcommands is:
///
///   - Encryption & decryption
///   - Signing & verification
///   - Inspection
///   - Key & cert-ring management
///   - Key discovery & networking
///   - Tools for developers, maintainers, forensic specialists
///
/// The order is derived from the order of variants in this enum.
#[derive(Debug, Subcommand)]
pub enum SqSubcommands {
    Encrypt(encrypt::Command),
    Decrypt(decrypt::Command),

    Sign(sign::Command),
    Verify(verify::Command),

    Inspect(inspect::Command),

    Cert(cert::Command),
    Key(key::Command),
    Pki(pki::Command),

    Autocrypt(autocrypt::Command),
    Network(network::Command),

    Toolbox(toolbox::Command),

    Version(version::Command),
}
