//! Command-line parser for `sq pki vouch list`.

use clap::Parser;

use crate::cli::types::CertDesignators;
use crate::cli::types::cert_designator;

use crate::cli::examples::*;

const LIST_EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "key", "import",
            "alice-secret.pgp",
        ]).build(),

        // Alice certifies that Bob controls
        // 511257EBBF077B7AEDAE5D093F68CB84CE537C9A and
        // bob@example.org.
        Action::setup().command(&[
            "sq", "pki", "vouch", "add",
            "--certifier=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--cert=511257EBBF077B7AEDAE5D093F68CB84CE537C9A",
            "--email=bob@example.org",
        ]).build(),

        Action::example().comment(
            "List certifications made by Alice.",
        ).command(&[
            "sq", "pki", "vouch", "list",
            "--certifier=EB28F26E2739A4870ECC47726F0073F60FD0CBF0"
        ]).build(),

        Action::example().comment(
            "List certifications made by Alice for Bob's certificate.",
        ).command(&[
            "sq", "pki", "vouch", "list",
            "--certifier=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--cert=511257EBBF077B7AEDAE5D093F68CB84CE537C9A",
        ]).build(),
    ],
};
test_examples!(sq_pki_vouch_list, LIST_EXAMPLES);

#[derive(Parser, Debug)]
#[clap(
    name = "list",
    about = "List certifications made by a certificate",
    long_about = "\
List certifications made by a certificate

This command lists the most recent active and valid certification for \
a binding, if any.  An active certification is one that was made prior \
to the reference time, and has not expired.  A certification is valid \
if it is well formed, and accepted by the current cryptographic policy.

Note: this command will list certifications with a trust amount of \
zero.

Because certifications are associated with the certificated \
certificate and not the certifier's certificate, this list is likely \
to be incomplete.

Stable since 1.2.0.
",
    after_help = LIST_EXAMPLES,
)]
pub struct Command {
    #[command(flatten)]
    pub certifier: CertDesignators<cert_designator::CertUserIDEmailFileSelfSpecialArgs,
                                   cert_designator::CertifierPrefix,
                                   cert_designator::OneValue>,

    #[command(flatten)]
    pub certs: CertDesignators<cert_designator::CertUserIDEmailDomainGrepArgs,
                               cert_designator::CertPrefix,
                               cert_designator::OptionalValue>,

    /// A pattern to select the bindings to authenticate
    ///
    /// The pattern is treated as a UTF-8 encoded string and a
    /// case insensitive substring search (using the current
    /// locale) is performed against each User ID.  If a User ID
    /// is not valid UTF-8, the binding is ignored.
    #[clap(
        conflicts_with_all = &["cert", "cert-userid", "cert-email",
                               "cert-domain", "cert-grep"],
    )]
    pub pattern: Option<String>,
}
