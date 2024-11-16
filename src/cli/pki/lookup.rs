//! Command-line parser for `sq pki lookup`.

use clap::Parser;

use crate::cli::examples;
use examples::Action;
use examples::Actions;
use examples::Example;
use examples::Setup;

use super::CertificationNetworkArg;
use super::GossipArg;
use super::RequiredTrustAmountArg;
use super::ShowPathsArg;

use crate::cli::types::userid_designator;
use crate::cli::types::UserIDDesignators;

/// Lookup the certificates associated with a User ID.
///
/// Identifies authenticated bindings (User ID and certificate
/// pairs) where the User ID matches the specified User ID.
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
    name = "lookup",
    after_help = EXAMPLES,
)]
pub struct Command {
    #[command(flatten)]
    pub userid: UserIDDesignators<
        userid_designator::AnyUserIDEmailArgs,
        userid_designator::OneValueNoLinting>,

    #[command(flatten)]
    pub show_paths: ShowPathsArg,

    #[command(flatten)]
    pub gossip: GossipArg,

    #[command(flatten)]
    pub certification_network: CertificationNetworkArg,

    #[command(flatten)]
    pub trust_amount: RequiredTrustAmountArg,
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
Lookup certificates that can be authenticated for the given user ID.",
            command: &[
                "sq", "pki", "lookup",
                "--userid", "Alice <alice@example.org>"
            ],
        }),
        Action::Example(Example {
            comment: "\
Lookup certificates that have a user ID with the specified email \
address, and that user ID can be authenticated.",
            command: &[
                "sq", "pki", "lookup",
                "--email", "alice@example.org",
            ],
        }),
    ]
};
test_examples!(sq_pki_lookup, EXAMPLES);
