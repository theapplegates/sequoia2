use clap::Parser;

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;
use openpgp::packet::UserID;

use crate::cli::examples;
use examples::Action;
use examples::Actions;
use examples::Example;

use super::CertificationNetworkArg;
use super::RequiredTrustAmountArg;

/// Verify the specified path.
///
/// A path is a sequence of certificates starting at the root, and
/// a User ID.  This function checks that each path segment has a
/// valid certification, which also satisfies any constraints
/// (trust amount, trust depth, regular expressions).
///
/// If a valid path is not found, then this subcommand also lints
/// the path.  In particular, it report if any certifications are
/// insufficient, e.g., not enough trust depth, or invalid, e.g.,
/// because they use SHA-1, but the use of SHA-1 has been
/// disabled.
#[derive(Parser, Debug)]
#[clap(
    name = "path",
    after_help = EXAMPLES,
)]
pub struct Command {
    #[clap(
        value_name = "FINGERPRINT|KEYID",
        required = true,
        num_args = 1..,
        help = "The path to authenticate",
        long_help = "\
The path to authenticate.

A path consists of one or more certificates.  The first certificate is \
the root, and the last certificate is the one being authenticated for \
the specified user ID.
",
    )]
    pub path: Vec<KeyHandle>,

    #[clap(
        long = "userid",
        value_name = "USERID",
        help = "The user ID to authenticate",
    )]
    pub userid: UserID,

    #[command(flatten)]
    pub certification_network: CertificationNetworkArg,

    #[command(flatten)]
    pub trust_amount: RequiredTrustAmountArg,
}

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::Example(Example {
            comment: "\
Verify that Alice ceritified a particular User ID for Bob's certificate.",
            command: &[
                "sq", "pki", "path",
                "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "511257EBBF077B7AEDAE5D093F68CB84CE537C9A",
                "--userid", "Bob <bob@example.org>",
            ],
        })
    ],
};
test_examples!(sq_pki_path, EXAMPLES);
