use clap::Parser;

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;
use openpgp::packet::UserID;

use crate::cli::examples;
use examples::Action;
use examples::Actions;
use examples::Example;

use crate::Result;

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
    #[command(flatten)]
    pub certification_network: CertificationNetworkArg,

    #[command(flatten)]
    pub trust_amount: RequiredTrustAmountArg,

    // This should actually be a repeatable positional argument
    // (Vec<Cert>) followed by a manadatory positional argument (a
    // User ID), but that is not allowed by Clap v3 and Clap v4
    // even though it worked fine in Clap v2.  (Curiously, it
    // works in `--release` mode fine and the only error appears
    // to be one caught by a `debug_assert`).
    //
    // https://github.com/clap-rs/clap/issues/3281
    #[command(flatten)]
    pub path: PathArg,
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
                "Bob <bob@example.org>",
            ],
        })
    ],
};
test_examples!(sq_pki_path, EXAMPLES);

#[derive(clap::Args, Debug)]
pub struct PathArg {
    /// A path consists of one or more certificates (designated by
    /// their fingerprint or Key ID) and ending in the User ID that is
    /// being authenticated.
    #[arg(value_names=["FINGERPRINT|KEYID", "USERID"])]
    elements: Vec<String>,
}

const PATH_DESC: &str = "\
A path consists of one or more certificates (identified by their
respective fingerprint or Key ID) and a User ID.";

impl PathArg {
    fn check(&self) -> Result<()> {
        if self.elements.len() < 2 {
            Err(anyhow::anyhow!(
"\
The following required arguments were not provided:
  {}<USERID>

{}

Usage: sq pki path <FINGERPRINT|KEYID>... <USERID>

For more information try '--help'",
                if self.elements.len() == 0 {
                    "<FINGERPRINT|KEYID>\n  "
                } else {
                    ""
                },
                PATH_DESC))
        } else {
            Ok(())
        }
    }

    pub fn certs(&self) -> Result<Vec<KeyHandle>> {
        self.check()?;

        // Skip the last one.  That's the User ID.
        self.elements[0..self.elements.len() - 1]
            .iter()
            .map(|e| {
                e.parse()
                    .map_err(|err| {
                        anyhow::anyhow!(
"Invalid value {:?} for '<FINGERPRINT|KEYID>': {}

{}

For more information try '--help'",
                            e, err, PATH_DESC)
                    })
            })
            .collect::<Result<Vec<KeyHandle>>>()
    }

    pub fn userid(&self) -> Result<UserID> {
        self.check()?;

        let userid = self.elements.last().expect("just checked");
        Ok(UserID::from(userid.as_bytes()))
    }
}
