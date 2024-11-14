//! Command-line parser for `sq pki authenticate`.

use clap::Parser;

use crate::cli::examples;
use examples::Action;
use examples::Actions;
use examples::Example;
use examples::Setup;

use super::CertArg;
use super::CertificationNetworkArg;
use super::EmailArg;
use super::GossipArg;
use super::RequiredTrustAmountArg;
use super::ShowPathsArg;
use super::UserIDArg;

/// Authenticate a binding.
///
/// Authenticate a binding (a certificate and User ID) by looking
/// for a path from the trust roots to the specified binding in
/// the Web of Trust.  Because certifications may express
/// uncertainty (i.e., certifications may be marked as conveying
/// only partial or marginal trust), multiple paths may be needed.
///
/// An error is return if no binding could be authenticated to the
/// specified level (by default: fully authenticated, i.e., a trust
/// amount of 120).
///
/// If any valid paths to the binding are found, they are printed
/// on stdout whether they are sufficient to authenticate the
/// binding or not.
#[derive(Parser, Debug)]
#[clap(
    name = "authenticate",
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

    #[command(flatten)]
    pub cert: CertArg,

    #[command(flatten)]
    pub userid: UserIDArg,
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
Authenticate a specific binding.",
            command: &[
                "sq", "pki", "authenticate",
                "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "Alice <alice@example.org>",
            ]
        }),
        Action::Example(Example {
            comment: "\
Check whether we can authenticate any user ID with the specified email \
address for the given certificate.",
            command: &[
                "sq", "pki", "authenticate",
                "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--email", "alice@example.org",
            ],
        }),
    ]
};
test_examples!(sq_pki_authenticate, EXAMPLES);
