use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::cli::types::ClapData;
use crate::cli::types::FileOrCertStore;
use crate::cli::types::FileOrStdin;
use crate::cli::types::FileOrStdout;

#[derive(Parser, Debug)]
#[clap(
    name = "wkd",
    about = "Retrieves and publishes certificates via Web Key Directories",
    long_about =
"Retrieves and publishes certificates via Web Key Directories

The Web Key Directory (WKD) is a method for publishing and retrieving
certificates from web servers.
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
    DirectUrl(DirectUrlCommand),
    Url(UrlCommand),
}

#[derive(Debug, Args)]
#[clap(
    about = "Prints the advanced Web Key Directory URL of an email address",
)]
pub struct UrlCommand {
    #[clap(
        value_name = "ADDRESS",
        help = "Queries for ADDRESS",
    )]
    pub email_address: String,
}

#[derive(Debug, Args)]
#[clap(
    about = "Prints the direct Web Key Directory URL of an email address",
)]
pub struct DirectUrlCommand {
    #[clap(
        value_name = "ADDRESS",
        help = "Queries for ADDRESS",
    )]
    pub email_address: String,
}

#[derive(Debug, Args)]
#[clap(
    about = "Retrieves certificates from a Web Key Directory",
    long_about =
"Retrieves certificates from a Web Key Directory

By default, any returned certificates are stored in the local
certificate store.  This can be overridden by using `--output`
option.

When a certificate is retrieved from a WKD, and imported into the
local certificate store, any User IDs with the email address that was
looked up are certificated with a local WKD-specific key.  That proxy
certificate is in turn certified as a minimally trusted CA (trust
amount: 1 of 120) by the local trust root.  How much the WKD proxy CA
is trusted can be tuned using `sq link add` or `sq link retract`
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

#[derive(Debug, Args)]
#[clap(
    about = "Generates a Web Key Directory for the given domain and keys",
    long_about =
"Generates a Web Key Directory for the given domain and keys

If the WKD exists, the new keys will be inserted and it \
is updated and existing ones will be updated.

A WKD is per domain, and can be queried using the advanced or the \
direct method. The advanced method uses a URL with a subdomain \
'openpgpkey'. As per the specification, the advanced method is to be \
preferred. The direct method may only be used if the subdomain \
doesn't exist. The advanced method allows web key directories for \
several domains on one web server.

The contents of the generated WKD must be copied to a web server so that \
they are accessible under https://openpgpkey.example.com/.well-known/openpgp/... \
for the advanced version, and https://example.com/.well-known/openpgp/... \
for the direct version. sq does not copy files to the web server.",
    after_help =
"EXAMPLES:

# Generate a WKD in /tmp/wkdroot from certs.pgp for example.com.
$ sq wkd generate /tmp/wkdroot example.com certs.pgp
",
)]
pub struct GenerateCommand {
    #[clap(
        value_name = "WEB-ROOT",
        help = "Writes the WKD to WEB-ROOT",
        long_help = "Writes the WKD to WEB-ROOT. Transfer this directory to \
            the webserver.",
    )]
    pub base_directory: PathBuf,
    #[clap(
        value_name = "FQDN",
        help = "Generates a WKD for a fully qualified domain name for email",
    )]
    pub domain: String,
    #[clap(
        default_value_t = FileOrStdin::default(),
        value_name = "CERT-RING",
        help = "Adds certificates from CERT-RING (or stdin if omitted) to the WKD",
    )]
    pub input: FileOrStdin,
    #[clap(
        short = 'd',
        long = "direct-method",
        help = "Uses the direct method [default: advanced method]",
    )]
    pub direct_method: bool,
    #[clap(
        short = 's',
        long = "skip",
        help = "Skips certificates that do not have User IDs for given domain.",
    )]
    pub skip: bool,
}
