//! Command-line parser for `sq pki authenticate`.

use clap::Parser;

use crate::cli::examples;
use examples::Action;
use examples::Actions;
use examples::Example;
use examples::Setup;

use crate::cli::types::CertDesignators;
use crate::cli::types::UserIDDesignators;
use crate::cli::types::cert_designator;
use crate::cli::types::userid_designator;

use super::CertificationNetworkArg;
use super::GossipArg;
use super::RequiredTrustAmountArg;
use super::ShowPathsArg;

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
    // Note: don't add --cert-file: the certificate needs to be merged
    // into the certificate store, and --cert-file doesn't do that.
    // Instead, the user should use --keyring FILE and --cert FPR.
    #[command(flatten)]
    pub cert: CertDesignators<
        cert_designator::CertArg,
        cert_designator::CertPrefix,
        cert_designator::OneValue>,

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
Authenticate a specific binding.",
            command: &[
                "sq", "pki", "authenticate",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--userid", "Alice <alice@example.org>",
            ],
            hide: &[],
        }),
        Action::Example(Example {
            comment: "\
Check whether we can authenticate any user ID with the specified email \
address for the given certificate.",
            command: &[
                "sq", "pki", "authenticate",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--email", "alice@example.org",
            ],
            hide: &[],
        }),
    ]
};
test_examples!(sq_pki_authenticate, EXAMPLES);
