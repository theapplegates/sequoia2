//! Command-line parser for `sq pki`.

use std::ops::Deref;

use clap::Parser;

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;
use openpgp::Result;
use openpgp::packet::UserID;

use crate::cli::types::TrustAmount;

pub mod certify;
pub mod link;

use crate::cli::examples;
use examples::Action;
use examples::Setup;
use examples::Actions;
use examples::Example;

#[derive(Debug, Parser)]
#[clap(
    name = "pki",
    about = "Authenticate certs using the Web of Trust",
    long_about =
"Authenticate certs using the Web of Trust

The \"Web of Trust\" is a decentralized trust model popularized by PGP.
It is a superset of X.509, which is a hierarchical trust model, and is
the most popular trust model on the public internet today.  As used on
the public internet, however, X.509 relies on a handful of global
certification authorities (CAs) who often undermine its security.

The Web of Trust is more nuanced than X.509.  Using the Web of Trust,
require multiple, independent paths to authenticate a binding by only
partially trusting CAs.  This prevents a single bad actor from
compromising their security.  And those who have stronger security
requirements can use the Web of Trust in a completely decentralized
manner where only the individuals they select – who are not
necessarily institutions – act as trusted introducers.
",
    subcommand_required = true,
    arg_required_else_help = true,
    )]
pub struct Command {
    #[command(subcommand)]
    pub subcommand: Subcommands,
}

#[derive(clap::Subcommand, Debug)]
pub enum Subcommands {
    Authenticate(AuthenticateCommand),
    Lookup(LookupCommand),
    Identify(IdentifyCommand),
    Certify(certify::Command),
    Link(link::Command),
    List(ListCommand),
    Path(PathCommand),
}

const AUTHENTICATE_EXAMPLES: Actions = Actions {
    actions: &[
        // Link Alice's certificate.
        Action::Setup(Setup {
            command: &[
                "sq", "pki", "link", "add",
                "EB28F26E2739A4870ECC47726F0073F60FD0CBF0", "--all",
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
test_examples!(sq_pki_authenticate, AUTHENTICATE_EXAMPLES);

/// Authenticate a binding.
///
/// Authenticate a binding (a certificate and User ID) by looking
/// for a path from the trust roots to the specified binding in
/// the Web of Trust.  Because certifications may express
/// uncertainty (i.e., certifications may be marked as conveying
/// only partial or marginal trust), multiple paths may be needed.
///
/// If a binding could be authenticated to the specified level (by
/// default: fully authenticated, i.e., a trust amount of 120),
/// then the exit status is 0.  Otherwise the exit status is 1.
///
/// If any valid paths to the binding are found, they are printed
/// on stdout whether they are sufficient to authenticate the
/// binding or not.
#[derive(Parser, Debug)]
#[clap(
    name = "authenticate",
    after_help = AUTHENTICATE_EXAMPLES,
)]
pub struct AuthenticateCommand {
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

const LOOKUP_EXAMPLES: Actions = Actions {
    actions: &[
        // Link Alice's certificate.
        Action::Setup(Setup {
            command: &[
                "sq", "pki", "link", "add",
                "EB28F26E2739A4870ECC47726F0073F60FD0CBF0", "--all",
            ],
        }),
        Action::Example(Example {
            comment: "\
Lookup certificates that can be authenticated for the given user ID.",
            command: &[
                "sq", "pki", "lookup", "Alice <alice@example.org>"
            ],
        }),
        Action::Example(Example {
            comment: "\
Lookup certificates that have a user ID with the specified email \
address, and that user ID can be authenticated.",
            command: &[
                "sq", "pki", "lookup", "--email", "alice@example.org",
            ],
        }),
    ]
};
test_examples!(sq_pki_lookup, LOOKUP_EXAMPLES);

/// Lookup the certificates associated with a User ID.
///
/// Identifies authenticated bindings (User ID and certificate
/// pairs) where the User ID matches the specified User ID.
///
/// If a binding could be authenticated to the specified level (by
/// default: fully authenticated, i.e., a trust amount of 120),
/// then the exit status is 0.  Otherwise the exit status is 1.
///
/// If a binding could be partially authenticated (i.e., its trust
/// amount is greater than 0), then the binding is displayed, even
/// if the trust is below the specified threshold.
#[derive(Parser, Debug)]
#[clap(
    name = "lookup",
    after_help = LOOKUP_EXAMPLES,
)]
pub struct LookupCommand {
    #[command(flatten)]
    pub email: EmailArg,

    #[command(flatten)]
    pub gossip: GossipArg,

    #[command(flatten)]
    pub certification_network: CertificationNetworkArg,

    #[command(flatten)]
    pub trust_amount: RequiredTrustAmountArg,

    #[command(flatten)]
    pub userid: UserIDArg,
}

const IDENTIFY_EXAMPLES: Actions = Actions {
    actions: &[
        // Link Alice's certificate.
        Action::Setup(Setup {
            command: &[
                "sq", "pki", "link", "add",
                "EB28F26E2739A4870ECC47726F0073F60FD0CBF0", "--all",
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
test_examples!(sq_pki_identify, IDENTIFY_EXAMPLES);

/// Identify a certificate.
///
/// Identify a certificate by finding authenticated bindings (User
/// ID and certificate pairs).
///
/// If a binding could be authenticated to the specified level (by
/// default: fully authenticated, i.e., a trust amount of 120),
/// then the exit status is 0.  Otherwise the exit status is 1.
///
/// If a binding could be partially authenticated (i.e., its trust
/// amount is greater than 0), then the binding is displayed, even
/// if the trust is below the specified threshold.
#[derive(Parser, Debug)]
#[clap(
    name = "identify",
    after_help = IDENTIFY_EXAMPLES,
)]
pub struct IdentifyCommand {
    #[command(flatten)]
    pub gossip: GossipArg,

    #[command(flatten)]
    pub certification_network: CertificationNetworkArg,

    #[command(flatten)]
    pub trust_amount: RequiredTrustAmountArg,

    #[command(flatten)]
    pub cert: CertArg,
}

const LIST_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Setup(Setup {
            command: &[
                "sq", "pki", "link", "add",
                "EB28F26E2739A4870ECC47726F0073F60FD0CBF0", "--all",
            ],
        }),
        Action::Example(Example {
            comment: "\
List all bindings for user IDs containing an email address from \
example.org, and that can be authenticated.",
            command: &[
                "sq", "pki", "list", "@example.org",
            ],
        })
    ]
};
test_examples!(sq_pki_list, LIST_EXAMPLES);

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
    after_help = LIST_EXAMPLES,
)]
pub struct ListCommand {
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

const PATH_EXAMPLES: Actions = Actions {
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
test_examples!(sq_pki_path, PATH_EXAMPLES);

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
    after_help = PATH_EXAMPLES,
)]
pub struct PathCommand {
    #[command(flatten)]
    pub gossip: GossipArg,

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

#[derive(clap::Args, Debug)]
pub struct CertArg {
    /// The fingerprint or Key ID of the certificate to authenticate.
    #[arg(value_name="FINGERPRINT|KEYID")]
    cert: KeyHandle
}

impl Deref for CertArg {
    type Target = KeyHandle;

    fn deref(&self) -> &Self::Target {
        &self.cert
    }
}

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

#[derive(clap::Args, Debug)]
pub struct UserIDArg {
    /// The User ID to authenticate.
    ///
    /// This is case sensitive, and must be the whole User ID, not
    /// just a substring or an email address.
    pub userid: UserID,
}

impl Deref for UserIDArg {
    type Target = UserID;

    fn deref(&self) -> &Self::Target {
        &self.userid
    }
}

#[derive(clap::Args, Debug)]
pub struct EmailArg {
    /// Changes the USERID parameter to match User IDs with the
    /// specified email address.
    ///
    /// Interprets the USERID parameter as an email address, which
    /// is then used to select User IDs with that email address.
    ///
    /// Unlike when comparing User IDs, email addresses are first
    /// normalized by the domain to ASCII using IDNA2008 Punycode
    /// conversion, and then converting the resulting email
    /// address to lowercase using the empty locale.
    ///
    /// If multiple User IDs match, they are each considered in
    /// turn, and this function returns success if at least one of
    /// those User IDs can be authenticated.  Note: The paths to
    /// the different User IDs are not combined.
    #[arg(long)]
    pub email: bool,
}

impl Deref for EmailArg {
    type Target = bool;

    fn deref(&self) -> &Self::Target {
        &self.email
    }
}

#[derive(clap::Args, Debug)]
pub struct GossipArg {
    /// Treats all certificates as unreliable trust roots.
    ///
    /// This option is useful for figuring out what others think about
    /// a certificate (i.e., gossip or hearsay).  In other words, this
    /// finds arbitrary paths to a particular certificate.
    ///
    /// Gossip is useful in helping to identify alternative ways to
    /// authenticate a certificate.  For instance, imagine Ed wants to
    /// authenticate Laura's certificate, but asking her directly is
    /// inconvenient.  Ed discovers that Micah has certified Laura's
    /// certificate, but Ed hasn't yet authenticated Micah's
    /// certificate.  If Ed is willing to rely on Micah as a trusted
    /// introducer, and authenticating Micah's certificate is easier
    /// than authenticating Laura's certificate, then Ed has learned
    /// about an easier way to authenticate Laura's certificate.
    #[arg(long)]
    pub gossip: bool,
}

impl Deref for GossipArg {
    type Target = bool;

    fn deref(&self) -> &Self::Target {
        &self.gossip
    }
}

#[derive(clap::Args, Debug)]
pub struct CertificationNetworkArg {
    /// Treats the network as a certification network.
    ///
    /// Normally, `sq pki` treats the Web of Trust network as an
    /// authentication network where a certification only means that
    /// the binding is correct, not that the target should be treated
    /// as a trusted introducer.  In a certification network, the
    /// targets of certifications are treated as trusted introducers
    /// with infinite depth, and any regular expressions are ignored.
    /// Note: The trust amount remains unchanged.  This is how most
    /// so-called PGP path-finding algorithms work.
    #[arg(long)]
    pub certification_network: bool,
}

impl Deref for CertificationNetworkArg {
    type Target = bool;

    fn deref(&self) -> &Self::Target {
        &self.certification_network
    }
}

#[derive(clap::Args, Debug)]
pub struct RequiredTrustAmountArg {
    /// The required amount of trust.
    ///
    /// 120 indicates full authentication; values less than 120
    /// indicate partial authentication.  When
    /// `--certification-network` is passed, this defaults to 1200,
    /// i.e., `sq pki` tries to find 10 paths.
    #[arg(short='a', long="amount", value_name = "AMOUNT")]
    pub trust_amount: Option<TrustAmount<usize>>,
}

impl Deref for RequiredTrustAmountArg {
    type Target = Option<TrustAmount<usize>>;

    fn deref(&self) -> &Self::Target {
        &self.trust_amount
    }
}
