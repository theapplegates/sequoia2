use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use sequoia_net::wkd;

use crate::cli::types::ClapData;
use crate::cli::types::FileOrCertStore;
use crate::cli::types::FileOrStdin;
use crate::cli::types::FileOrStdout;

use crate::cli::examples;
use examples::Action;
use examples::Actions;
use examples::Example;

#[derive(Parser, Debug)]
#[clap(
    name = "wkd",
    about = "Retrieve and publishes certificates via Web Key Directories",
    long_about =
"Retrieve and publishes certificates via Web Key Directories

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
    Fetch(FetchCommand),
    Generate(GenerateCommand),
    Publish(PublishCommand),
    DirectUrl(DirectUrlCommand),
    Url(UrlCommand),
}

#[derive(Debug, Args)]
#[clap(
    about = "Print the advanced Web Key Directory URL of an email address",
)]
pub struct UrlCommand {
    #[clap(
        value_name = "ADDRESS",
        help = "Query for ADDRESS",
    )]
    pub email_address: String,
}

#[derive(Debug, Args)]
#[clap(
    about = "Print the direct Web Key Directory URL of an email address",
)]
pub struct DirectUrlCommand {
    #[clap(
        value_name = "ADDRESS",
        help = "Query for ADDRESS",
    )]
    pub email_address: String,
}

#[derive(Debug, Args)]
#[clap(
    about = "Retrieve certificates from a Web Key Directory",
    long_about =
"Retrieve certificates from a Web Key Directory

By default, any returned certificates are stored in the local
certificate store.  This can be overridden by using `--output`
option.

When a certificate is retrieved from a WKD, and imported into the
local certificate store, any User IDs with the email address that was
looked up are certificated with a local WKD-specific key.  That proxy
certificate is in turn certified as a minimally trusted CA (trust
amount: 1 of 120) by the local trust root.  How much the WKD proxy CA
is trusted can be tuned using `sq pki link add` or `sq pki link retract`
in the usual way.
"
)]
pub struct FetchCommand {
    #[clap(
        long,
        conflicts_with = "addresses",
        help = "Fetch updates for all known certificates",
    )]
    pub all: bool,

    #[clap(
        value_name = "ADDRESS",
        required = true,
        help = "Retrieve certificate(s) for ADDRESS",
    )]
    pub addresses: Vec<String>,
    #[clap(
        short = 'B',
        long,
        help = "Emit binary data",
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
    about = "Generate a Web Key Directory for the given domain and certs",
    long_about =
"Generate a Web Key Directory for the given domain and certs

If the WKD exists, the new certificates will be inserted and existing
ones will be updated.

A WKD is per domain, and can be queried using the advanced or the \
direct method. The advanced method uses a URL with a subdomain \
'openpgpkey'. As per the specification, the advanced method is to be \
preferred. The direct method may only be used if the subdomain \
doesn't exist. The advanced method allows Web Key Directories for \
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
        help = "Write the WKD to WEB-ROOT",
        long_help = "Write the WKD to WEB-ROOT. Transfer this directory to \
            the webserver.",
    )]
    pub base_directory: PathBuf,
    #[clap(
        value_name = "FQDN",
        help = "Generate a WKD for a fully qualified domain name for email",
    )]
    pub domain: String,
    #[clap(
        default_value_t = FileOrStdin::default(),
        value_name = "CERT-RING",
        help = "Add certificates from CERT-RING (or stdin if omitted) to the WKD",
    )]
    pub input: FileOrStdin,
    #[clap(
        short = 'd',
        long = "direct-method",
        help = "Use the direct method [default: advanced method]",
    )]
    pub direct_method: bool,
    #[clap(
        short = 's',
        long = "skip",
        help = "Skip certificates that do not have User IDs for given domain.",
    )]
    pub skip: bool,
}

const PUBLISH_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Example(Example {
            comment: "Create a new WKD hierarchy in the local directory \
                      `public_html`, and insert Alice's cert.",
            command: &[
                "sq", "network", "wkd", "publish", "--create",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "example.org", "public_html",
            ],
        }),

        Action::Example(Example {
            comment: "Add Bob's cert to the existing WKD hierarchy \
                      in the local directory `public_html`.",
            command: &[
                "sq", "network", "wkd", "publish",
                "--cert", "511257EBBF077B7AEDAE5D093F68CB84CE537C9A",
                "example.org", "public_html",
            ],
        }),

        Action::Example(Example {
            comment: "Refresh all certs in the existing WKD hierarchy \
                      in the local directory `public_html` from the \
                      cert store.",
            command: &[
                "sq", "network", "wkd", "publish",
                "example.org", "public_html",
            ],
        }),
    ],
};

test_examples!(sq_network_wkd_publish, PUBLISH_EXAMPLES);

#[derive(Debug, Args)]
#[clap(
    about = "Publish certificates in a Web Key Directory",
    long_about =
"Publish certificates in a Web Key Directory

Publishes certificates or certificate updates in a Web Key Directory
(WKD).  You can create or update a WKD hierarchy on the local system by
specifying a path as destination.

Typically, a WKD is stored on a web server.  If --rsync is given, this
command manages remote WKD directory hierarchies by using rsync(1).

To update a WKD hierarchy, it is first copied to a temporary location
on the local machine, new certificates or certificate updates are
inserted into the local copy, and the hierarchy is copied back to its
original location.  As this is not an atomic operation, care must be
taken to avoid concurrent updates.
",
    after_help = PUBLISH_EXAMPLES,
)]
pub struct PublishCommand {
    #[clap(
        long = "create",
        value_name = "METHOD",
        default_missing_value = "advanced",
        num_args = 0..=1,
        help = "Create the WKD hierarchy if it does not exist yet",
    )]
    pub create: Option<Method>,
    #[clap(
        long = "cert",
        value_name = "FINGERPRINT",
        help = "Insert the given cert into the WKD",
    )]
    pub certs: Vec<String>,
    #[clap(
        long = "rsync",
        value_name = "RSYNC",
        default_missing_value = "rsync",
        num_args = 0..=1,
        help = "Path to the local rsync command to use",
    )]
    pub rsync: Option<String>,
    #[clap(
        value_name = "FQDN",
        help = "Generate a WKD for a fully qualified domain name for email",
    )]
    pub domain: String,
    #[clap(
        value_name = "DEST",
        help = "WKD location on the server, passed to rsync(1)",
        long_help = "Location of the WKD hierarchy on the local machine or \
                     a remote server.  If --rsync is given, this is passed \
                     as-is to rsync(1).",
    )]
    pub destination: String,
}

#[derive(clap::ValueEnum, Debug, Clone)]
pub enum Method {
    Advanced,
    Direct,
}

impl From<Method> for wkd::Variant {
    fn from(v: Method) -> wkd::Variant {
        match v {
            Method::Advanced => wkd::Variant::Advanced,
            Method::Direct => wkd::Variant::Direct,
        }
    }
}
