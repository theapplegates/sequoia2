//! Command-line parser for `sq pki identify`.

use clap::Parser;

use crate::cli::examples;
use examples::Action;
use examples::Actions;
use examples::Example;
use examples::Setup;

use super::CertArg;
use super::CertificationNetworkArg;
use super::GossipArg;
use super::RequiredTrustAmountArg;
use super::ShowPathsArg;

/// Identify a certificate.
///
/// Identify a certificate by finding authenticated bindings (User
/// ID and certificate pairs).
///
/// An error is return if no binding could be authenticated to the
/// specified level (by default: fully authenticated, i.e., a trust
/// amount of 120).
///
/// If a binding could be partially authenticated (i.e., its trust
/// amount is greater than 0), then the binding is displayed, even
/// if the trust is below the specified threshold.
#[derive(Parser, Debug)]
#[clap(
    name = "identify",
    after_help = EXAMPLES,
)]
pub struct Command {
    #[command(flatten)]
    pub show_paths: ShowPathsArg,

    #[command(flatten)]
    pub gossip: GossipArg,

    #[command(flatten)]
    pub certification_network: CertificationNetworkArg,

    #[command(flatten)]
    pub trust_amount: RequiredTrustAmountArg,

    #[command(flatten)]
    pub cert: CertArg,
}

const EXAMPLES: Actions = Actions {
    actions: &[
        // Link Alice's certificate.
        Action::Setup(Setup {
            command: &[
                "sq", "pki", "link", "add",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--all",
            ],
        }),
        Action::Example(Example {
            comment: "\
Identify the user IDs that can be authenticated for the certificate.",
            command: &[
                "sq", "pki", "identify",
                "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            ],
        }),
        Action::Example(Example {
            comment: "\
List all user IDs that have that have been certified by anyone.",
            command: &[
                "sq", "pki", "identify", "--gossip",
                "511257EBBF077B7AEDAE5D093F68CB84CE537C9A",
            ],
        }),
    ]
};
test_examples!(sq_pki_identify, EXAMPLES);
