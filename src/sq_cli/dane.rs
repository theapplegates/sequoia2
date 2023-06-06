use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::sq_cli::types::NetworkPolicy;

#[derive(Parser, Debug)]
#[clap(
    name = "dane",
    about = "Interacts with DANE",
    long_about = "DNS-Based Authentication of Named Entities (DANE) is a method for publishing public keys in DNS as specified in RFC 7929.",
    subcommand_required = true,
    arg_required_else_help = true,
)]
pub struct Command {
    #[clap(
        short,
        long,
        value_name = "NETWORK-POLICY",
        default_value_t = NetworkPolicy::Encrypted,
        value_enum,
        help = "Sets the network policy to use",
    )]
    pub network_policy: NetworkPolicy,
    #[clap(subcommand)]
    pub subcommand: Subcommands,
}

#[derive(Debug, Subcommand)]
pub enum Subcommands {
    Get(GetCommand),
}

#[derive(Debug, Args)]
#[clap(
    about = "Looks up certificates using DANE",
    long_about =
"Looks up certificates using DANE

By default, any returned certificates are stored in the local
certificate store.  This can be overridden by using \"--output\"
option.

When a certificate is downloaded using DANE, and imported into the
local certificate store, any User IDs with the email address that was
looked up are certificated with a local DANE-specific key.  That proxy
certificate is in turn certified as a minimally trusted CA (trust
amount: 1 of 120) by the local trust root.  How much the DANE proxy CA
is trusted can be tuned using \"sq link add\" or \"sq link retract\"
in the usual way.
"
)]
pub struct GetCommand {
    #[clap(
        value_name = "ADDRESS",
        help = "Queries a cert for ADDRESS",
    )]
    pub email_address: String,
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,
    #[clap(
        short,
        long,
        value_name = "FILE",
        help = "Writes to FILE instead of importing into the certificate store"
    )]
    pub output: Option<PathBuf>,
}
