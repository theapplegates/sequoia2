use std::time::Duration;

use clap::{Args, Parser, Subcommand};

use crate::cli::types::ClapData;
use crate::cli::types::FileOrCertStore;
use crate::cli::types::FileOrStdin;
use crate::cli::types::FileOrStdout;

#[derive(Parser, Debug)]
#[clap(
    name = "dane",
    about = "Retrieves and publishes certificates via DANE",
    long_about =
"Retrieves and publishes certificates via DANE

DNS-Based Authentication of Named Entities (DANE) is a method for
publishing and retrieving certificates in DNS as specified in RFC
7929.
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
    Fetch(FetchCommand),
}

#[derive(Debug, Args)]
#[clap(
    about = "Generates DANE records for the given domain and certs",
    long_about =
"Generates DANE records for the given domain and certs

The certificates are minimized, and one record per email address is
emitted.  If multiple user IDs map to one email address, then all
matching user IDs are included in the emitted certificates.

By default, OPENPGPKEY resource records are emitted.  If your DNS
server doesn't understand those, use `--generic` to emit generic
records instead.",
    after_help =
"EXAMPLES:

# Generate DANE records from certs.pgp for example.com.
$ sq dane generate example.com certs.pgp
",
)]
pub struct GenerateCommand {
    #[clap(
        value_name = "FQDN",
        help = "Generates DANE records for this domain name",
    )]
    pub domain: String,
    #[clap(
        default_value_t = FileOrStdin::default(),
        value_name = "CERT-RING",
        help = "Emits records for certificates from CERT-RING \
                (or stdin if omitted)",
    )]
    pub input: FileOrStdin,
    #[clap(
        long = "ttl",
        value_name = "DURATION",
        value_parser = |arg: &str| -> Result<Duration, std::num::ParseIntError>
            { Ok(Duration::from_secs(arg.parse()?)) },
        default_value = "10800",
        help = "Sets the TTL (maximum cache duration) of the resource records",
    )]
    pub ttl: Duration,
    #[clap(
        long = "size-limit",
        value_name = "BYTES",
        default_value = "12288",
        help = "Try to shrink the certificates to this size",
    )]
    pub size_limit: usize,
    #[clap(
        long = "generic",
        help = "Emits generic resource records [default: OPENPGPKEY records]",
    )]
    pub generic: bool,
    #[clap(
        short = 's',
        long = "skip",
        help = "Skips expired certificates and those that do not have \
                User IDs for given domain.",
    )]
    pub skip: bool,
}

#[derive(Debug, Args)]
#[clap(
    about = "Retrieves certificates using DANE",
    long_about =
"Retrieves certificates using DANE

By default, any returned certificates are stored in the local
certificate store.  This can be overridden by using `--output`
option.

When a certificate is retrieved using DANE, and imported into the
local certificate store, any User IDs with the email address that was
looked up are certificated with a local DANE-specific key.  That proxy
certificate is in turn certified as a minimally trusted CA (trust
amount: 1 of 120) by the local trust root.  How much the DANE proxy CA
is trusted can be tuned using `sq pki link add` or `sq pki link retract`
in the usual way.
"
)]
pub struct FetchCommand {
    #[clap(
        value_name = "ADDRESS",
        required = true,
        help = "Queries a cert for ADDRESS",
    )]
    pub addresses: Vec<String>,
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,
    #[clap(
        help = FileOrCertStore::HELP_OPTIONAL,
        long,
        short,
        value_name = FileOrCertStore::VALUE_NAME,
    )]
    pub output: Option<FileOrStdout>,
}
