//! Command-line parser for `sq pki vouch certify`.

use clap::Parser;

use crate::cli::THIRD_PARTY_CERTIFICATION_VALIDITY_DURATION;
use crate::cli::THIRD_PARTY_CERTIFICATION_VALIDITY_IN_YEARS;

use crate::cli::types::ClapData;
use crate::cli::types::Expiration;
use crate::cli::types::ExpirationArg;
use crate::cli::types::FileOrStdout;
use crate::cli::types::TrustAmount;
use crate::cli::types::UserIDDesignators;
use crate::cli::types::cert_designator::{self, *};
use crate::cli::types::userid_designator;

use crate::cli::examples::*;

const CERTIFY_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Setup(Setup {
            command: &[
                "sq", "key", "import",
                "alice-secret.pgp",
            ],
        }),
        Action::Example(Example {
            comment: "\
Alice certifies that Bob controls 3F68CB84CE537C9A and bob@example.org.",
            command: &[
                "sq", "pki", "vouch", "certify",
                "--certifier=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--cert=511257EBBF077B7AEDAE5D093F68CB84CE537C9A",
                "--email=bob@example.org",
            ],
        }),

        Action::Example(Example {
            comment: "\
Alice certifies that Bob controls 3F68CB84CE537C9A and bob@bobs.lair.net, \
which is not a self-signed user ID.",
            command: &[
                "sq", "pki", "vouch", "certify",
                "--certifier=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--cert=511257EBBF077B7AEDAE5D093F68CB84CE537C9A",
                "--add-email=bob@bobs.lair.net",
            ],
        }),
    ],
};
test_examples!(sq_pki_vouch_certify, CERTIFY_EXAMPLES);

#[derive(Parser, Debug)]
#[clap(
    name = "certify",
    about = "Certify a User ID for a Certificate",
    long_about = format!(
"Certify a User ID for a Certificate

Using a certification a keyholder may vouch for the fact that another \
certificate legitimately belongs to a user id.  In the context of \
emails this means that the same entity controls the key and the email \
address.  These kind of certifications form the basis for the Web of \
Trust.

This command emits the certificate with the new certification.  The \
updated certificate has to be distributed, preferably by sending it to \
the certificate holder for approval.  See also `sq key approvals`.

By default a certification expires after {} years. \
Using the `--expiration` argument specific validity periods may be defined. \
It allows for providing a point in time for validity to end or a validity \
duration.

`sq pki vouch certify` respects the reference time set by the top-level \
`--time` argument.  It sets the certification's creation time to the \
reference time.
",
        THIRD_PARTY_CERTIFICATION_VALIDITY_IN_YEARS,
    ),
    after_help = CERTIFY_EXAMPLES,
)]
#[clap(mut_arg("expiration", |arg| {
    arg.default_value(Expiration::from_duration(THIRD_PARTY_CERTIFICATION_VALIDITY_DURATION))
}))]
pub struct Command {
    #[command(flatten)]
    pub certifier: CertDesignators<CertUserIDEmailFileArgs,
                                   CertifierPrefix,
                                   OneValue,
                                   CertifierDoc>,

    #[command(flatten)]
    pub cert: CertDesignators<
        cert_designator::CertFileArgs,
        cert_designator::CertPrefix,
        cert_designator::OneValue>,

    #[command(flatten)]
    pub userids: UserIDDesignators<
        userid_designator::ExistingAndAddArgs>,

    #[clap(
        long = "amount",
        value_name = "AMOUNT",
        default_value = "full",
        help = "Set the amount of trust",
        long_help =
            "Set the amount of trust.  Values between 1 and 120 are meaningful. \
            120 means fully trusted.  Values less than 120 indicate the degree \
            of trust.  60 is usually used for partially trusted.",
    )]
    pub amount: TrustAmount<u8>,

    #[command(flatten)]
    pub expiration: ExpirationArg,

    #[clap(
        long = "local",
        help = "Make the certification a local certification",
        long_help =
            "Make the certification a local \
            certification.  Normally, local \
            certifications are not exported.",
    )]
    pub local: bool,
    #[clap(
        long = "non-revocable",
        help = "Mark the certification as being non-revocable",
        long_help =
            "Mark the certification as being non-revocable. \
            That is, you cannot later revoke this \
            certification.  This should normally only \
            be used with an expiration.",
    )]
    pub non_revocable: bool,

    #[clap(
        long,
        value_names = &["NAME", "VALUE"],
        number_of_values = 2,
        help = "Add a notation to the certification.",
        long_help = "Add a notation to the certification.  \
            A user-defined notation's name must be of the form \
            `name@a.domain.you.control.org`. If the notation's name starts \
            with a !, then the notation is marked as being critical.  If a \
            consumer of a signature doesn't understand a critical notation, \
            then it will ignore the signature.  The notation is marked as \
            being human readable."
    )]
    pub notation: Vec<String>,

    #[clap(
        help = FileOrStdout::HELP_OPTIONAL,
        long,
        value_name = FileOrStdout::VALUE_NAME,
    )]
    pub output: Option<FileOrStdout>,
    #[clap(
        long,
        help = "Emit binary data",
    )]
    pub binary: bool,
}
