//! Command-line parser for `sq cert list`.

use clap::Parser;

use crate::cli::examples::Action;
use crate::cli::examples::Actions;
use crate::cli::examples::Example;
use crate::cli::examples::Setup;
use crate::cli::pki::CertificationNetworkArg;
use crate::cli::pki::EmailArg;
use crate::cli::pki::GossipArg;
use crate::cli::pki::RequiredTrustAmountArg;
use crate::cli::pki::ShowPathsArg;

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::Setup(Setup {
            command: &[
                "sq", "pki", "link", "add",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--all",
            ],
        }),
        Action::Example(Example {
            comment: "\
List all bindings for user IDs containing an email address from \
example.org, and that can be authenticated.",
            command: &[
                "sq", "cert", "list", "@example.org",
            ],
        })
    ]
};
test_examples!(sq_cert_list, EXAMPLES);

/// List all authenticated bindings (User ID and certificate
/// pairs).
///
/// Only bindings that meet the specified trust amount (by default
/// bindings that are fully authenticated, i.e., have a trust
/// amount of 120), are shown.
///
/// Even if no bindings are shown, the exit status is 0.
///
/// If `--email` is provided, then a pattern matches if it is a case
/// insensitive substring of the email address as-is or the
/// normalized email address.  Note: unlike the email address, the
/// pattern is not normalized.  In particular, puny code
/// normalization is not done on the pattern.
#[derive(Parser, Debug)]
#[clap(
    name = "list",
    after_help = EXAMPLES,
)]
pub struct Command {
    #[command(flatten)]
    pub show_paths: ShowPathsArg,

    #[command(flatten)]
    pub email: EmailArg,

    #[command(flatten)]
    pub gossip: GossipArg,

    #[command(flatten)]
    pub certification_network: CertificationNetworkArg,

    #[command(flatten)]
    pub trust_amount: RequiredTrustAmountArg,

    /// A pattern to select the bindings to authenticate.
    ///
    /// The pattern is treated as a UTF-8 encoded string and a
    /// case insensitive substring search (using the current
    /// locale) is performed against each User ID.  If a User ID
    /// is not valid UTF-8, the binding is ignored.
    pub pattern: Option<String>,
}

