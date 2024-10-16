//! Command-line parser for `sq pki link`.

use clap::{ArgGroup, Parser, Subcommand};

use crate::cli::examples::*;
use crate::cli::types::CertDesignators;
use crate::cli::types::cert_designator;
use crate::cli::types::UserIDDesignators;
use crate::cli::types::userid_designator;
use crate::cli::types::Expiration;
use crate::cli::types::TrustAmount;

#[derive(Parser, Debug)]
#[clap(
    name = "link",
    about = "Manage authenticated certificate and User ID links",
    long_about =
"Manage authenticated certificate and User ID links

Link a certificate and User ID is one way of making `sq` consider a \
binding to be authentic.  Another way is to use `sq pki certify` to \
certify the binding with an explicitly configured trust root.  The \
linking functionality is often easier to work with, and the \
information is private by default.

Authenticated bindings can be used to designate a certificate using a \
symbolic name.  For instance, using `sq encrypt`'s \
`--for-userid` and `--for-email` options, a user can \
designate a certificate using a User ID or an email address that is \
authenticated for that certificate.

`sq` also uses authenticated certificates to authenticate other \
data.  For instance, `sq verify` considers signatures made by an \
authenticated certificate to be authentic.

Users can create a link using `sq pki link add`.  That link can later be \
retracted using `sq pki link retract`.  A certificate can also be \
accepted as a trusted introducer by passing the `--ca` option to \
`sq pki link add`.

`sq` implements linking using non-exportable certifications, and an \
implicit trust root.  An OpenPGP certificate directory, the default \
certificate store used by `sq`, includes a local trust root, which \
is stored under the `trust-root` special name.  When the user \
instructs `sq` to accept a binding, `sq` uses the local trust root \
to create a non-exportable certification, which it stores in the \
certificate directory.  In this way, operations that use the Web of \
Trust to authenticate a binding automatically use links.

When a user retracts a link, `sq` creates a new, non-exportable \
certification with zero trust.  This certification suppresses the \
previous link.
",
after_help = LINK_EXAMPLES,
    subcommand_required = true,
    arg_required_else_help = true,
)]
pub struct Command {
    #[clap(subcommand)]
    pub subcommand: Subcommands,
}


const LINK_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Example(Example {
            comment: "\
Link the certificate EB28F26E2739A4870ECC47726F0073F60FD0CBF0 \
with the email address alice@example.org.",
            command: &[
                "sq", "pki", "link", "add",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--email=alice@example.org",
            ],
        }),

        Action::Example(Example {
            comment: "\
Then, temporarily accept the certificate \
EB28F26E2739A4870ECC47726F0073F60FD0CBF0 with all of its self-signed \
user IDs for a week.",
            command: &[
                "sq", "pki", "link", "add",
                "--expiration=1w",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--all",
            ],
        }),

        Action::Example(Example {
            comment: "\
Accept the certificate EB28F26E2739A4870ECC47726F0073F60FD0CBF0 \
with all of its self-signed user IDs as a trusted certification \
authority constrained to the domain example.org.  That is, the \
certificate is considered a trusted introducer for example.org.",
            command: &[
                "sq", "pki", "link", "add",
                "--ca=example.org",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--all",
            ],
        }),

        Action::Example(Example {
            comment: "List all links.",
            command: &[
                "sq", "pki", "link", "list",
            ],
        }),

        Action::Example(Example {
            comment: "\
Retract the acceptance of certificate EB28F26E2739A4870ECC47726F0073F60FD0CBF0 \
and any associated user IDs.  This effectively invalidates all links.",
            command: &[
                "sq", "pki", "link", "retract",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            ],
        }),
    ],
};
test_examples!(sq_pki_link, LINK_EXAMPLES);

#[derive(Debug, Subcommand)]
pub enum Subcommands {
    Add(AddCommand),
    Retract(RetractCommand),
    List(ListCommand),
}

#[derive(Parser, Debug)]
#[clap(
    name = "add",
    about = "Link a certificate and a User ID",
    long_about =
"Link a certificate and a User ID

This cause `sq` to considers the certificate and User ID binding to be \
authentic.

A certificate can also be accepted as a certification authority, which \
is also known as a trusted introducer, by using the `--ca` or \
`--depth` option.

A link can be retracted using `sq pki link retract`.

This command is similar to `sq pki certify`, but the certifications it \
makes are done using the certificate directory's trust root, not an \
arbitrary key.  Further, the certificates are marked as \
non-exportable.  The former makes it easier to manage certifications, \
especially when the user's certification key is offline.  And the \
latter improves the user's privacy, by reducing the chance that parts \
of the user's social graph is leaked when a certificate is shared.

By default a link never expires. \
Using the `--expiration` argument specific validity periods may be defined. \
It allows for providing a point in time for validity to end or a validity \
duration.

`sq pki link` respects the reference time set by the top-level `--time` \
argument. It sets the link's creation time to the reference time.
",
    after_help = ADD_EXAMPLES,
)]
#[clap(group(ArgGroup::new("expiration-group")
             .args(&["expiration", "temporary"])))]
pub struct AddCommand {
    #[command(flatten)]
    pub cert: CertDesignators<
        cert_designator::CertArg,
        cert_designator::CertPrefix,
        cert_designator::OneValue>,

    #[command(flatten)]
    pub userids: UserIDDesignators<
        userid_designator::MaybeSelfSignedUserIDEmailAllArgs>,

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

    #[clap(
        long = "depth",
        value_name = "TRUST_DEPTH",
        help = "Set the trust depth",
        long_help =
            "Set the trust depth (sometimes referred to as the trust level).  \
            0 means a normal certification of <CERTIFICATE, USERID>.  \
            1 means CERTIFICATE is also a trusted introducer, 2 means \
            CERTIFICATE is a meta-trusted introducer, etc.",
    )]
    pub depth: Option<u8>,
    #[clap(
        long = "ca",
        value_name = "*|DOMAIN",
        help = "Mark the certificate as a certification authority for a domain",
        long_help =
            "Mark the certificate as a certification authority for a  \
             domain.  Use `*` to make the certificate a certification
             authority for any User ID.

             A certification authority is also referred to as a trusted \
             introducer.  This command is equivalent to making the trust \
             depth unconstrained, i.e., setting the depth to 255.  See \
             `--depth` for more information.",
    )]
    pub ca: Vec<String>,
    #[clap(
        long = "regex",
        value_name = "REGEX",
        help = "Add a regular expression to constrain \
            what a trusted introducer can certify",
        long_help =
            "Add a regular expression to constrain \
            what a trusted introducer can certify.  \
            The regular expression must match \
            the certified User ID in all intermediate \
            introducers, and the certified certificate. \
            Multiple regular expressions may be \
            specified.  In that case, at least \
            one must match.",
    )]
    pub regex: Vec<String>,

    #[clap(
        long = "temporary",
        conflicts_with_all = &[ "amount" ],
        help = "Temporarily accepts the binding",
        long_help =
            "Temporarily accepts the binding.  Creates a fully
            trust link between a certificate and one or more
            User IDs for a week.  After that, the link is
            automatically downgraded to a partially trusted link
            (trust = 40).",
    )]
    pub temporary: bool,
    #[clap(
        long = "expiration",
        value_name = "EXPIRATION",
        default_value_t =
            Expiration::Never,
        help =
            "Define EXPIRATION for the acceptance as ISO 8601 formatted string or \
            custom duration.",
        long_help =
            "Define EXPIRATION for the acceptance as ISO 8601 formatted string or \
            custom duration. \
            If an ISO 8601 formatted string is provided, the validity period \
            reaches from the reference time (may be set using `--time`) to \
            the provided time. \
            Custom durations starting from the reference time may be set using \
            `N[ymwds]`, for N years, months, weeks, days, or seconds. \
            The special keyword `never` sets an unlimited expiry.",
    )]
    pub expiration: Expiration,

    #[clap(
        long = "recreate",
        help = "Recreate signature even if the parameters did not change",
        long_help = "\
Recreate signature even if the parameters did not change

If the link parameters did not change, and thus creating a signature \
should not be necessary, we omit the operation.  This flag can be given \
to force the signature to be re-created anyway.",
    )]
    pub recreate: bool,

    #[clap(
        long,
        value_names = &["NAME", "VALUE"],
        number_of_values = 2,
        help = "Add a notation to the certification.",
        long_help = "Add a notation to the certification.  \
            A user-defined notation's name must be of the form \
            `name@a.domain.you.control.org`. If the notation's name starts \
            with a `!`, then the notation is marked as being critical.  If a \
            consumer of a signature doesn't understand a critical notation, \
            then it will ignore the signature.  The notation is marked as \
            being human readable."
    )]
    pub notation: Vec<String>,
}

const ADD_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Example(Example {
            comment: "\
Link the certificate EB28F26E2739A4870ECC47726F0073F60FD0CBF0 \
with the email address alice@example.org.",
            command: &[
                "sq", "pki", "link", "add",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--email=alice@example.org",
            ],
        }),

        Action::Example(Example {
            comment: "\
First, examine the certificate EB28F26E2739A4870ECC47726F0073F60FD0CBF0.",
            command: &[
                "sq", "inspect",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            ],
        }),

        Action::Example(Example {
            comment: "\
Then, temporarily accept the certificate \
EB28F26E2739A4870ECC47726F0073F60FD0CBF0 with all of its self-signed \
user IDs for a week.",
            command: &[
                "sq", "pki", "link", "add",
                "--expiration=1w",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--all",
            ],
        }),

        Action::Example(Example {
            comment: "\
Once satisfied, permanently accept the certificate \
EB28F26E2739A4870ECC47726F0073F60FD0CBF0 with all of its self-signed \
user IDs.",
            command: &[
                "sq", "pki", "link", "add",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--all",
            ],
        }),

        Action::Example(Example {
            comment: "\
Accept the certificate EB28F26E2739A4870ECC47726F0073F60FD0CBF0 \
with all of its self-signed user IDs as a trusted certification \
authority.  That is, the certificate is considered a trust root.",
            command: &[
                "sq", "pki", "link", "add",
                "--ca=*",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--all",
            ],
        }),

        Action::Example(Example {
            comment: "\
Accept the certificate EB28F26E2739A4870ECC47726F0073F60FD0CBF0 \
with all of its self-signed user IDs as a trusted certification \
authority constrained to the domain example.org.  That is, the \
certificate is considered a trusted introducer for example.org.",
            command: &[
                "sq", "pki", "link", "add",
                "--ca=example.org",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--all",
            ],
        }),

        Action::Example(Example {
            comment: "\
Accept the certificate EB28F26E2739A4870ECC47726F0073F60FD0CBF0 \
with all of its self-signed user IDs as a partially trusted \
certification authority.",
            command: &[
                "sq", "pki", "link", "add",
                "--ca=*",
                "--amount=60",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--all",
            ],
        }),
    ],
};
test_examples!(sq_pki_link_add, ADD_EXAMPLES);

#[derive(Parser, Debug)]
#[clap(
    name = "retract",
    about = "Retract links",
    long_about =
"Retract links

This command retracts links that were previously created using `sq \
pki link add`.  See that subcommand's documentation for more details. \
Note: this is called `retract` and not `remove`, because the \
certifications are not removed.  Instead a new certification is added, \
which says that the binding has not been authenticated.

`sq pki link retract` respects the reference time set by the top-level \
`--time` argument.  This causes a link to be retracted as of a \
particular time instead of the current time.
",
    after_help = RETRACT_EXAMPLES,
)]
pub struct RetractCommand {
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
        long = "recreate",
        help = "Recreate signature even if the parameters did not change",
        long_help = "\
Recreate signature even if the parameters did not change

If the link parameters did not change, and thus creating a signature \
should not be necessary, we omit the operation.  This flag can be given \
to force the signature to be re-created anyway.",
    )]
    pub recreate: bool,

    #[command(flatten)]
    pub cert: CertDesignators<
        cert_designator::CertArg,
        cert_designator::CertPrefix,
        cert_designator::OneValue>,

    #[command(flatten)]
    pub userids: UserIDDesignators<
        userid_designator::UserIDEmailArgs,
        userid_designator::OptionalValue>,
}

const RETRACT_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Example(Example {
            comment: "\
Link the certificate EB28F26E2739A4870ECC47726F0073F60FD0CBF0 \
with the email address alice@example.org.",
            command: &[
                "sq", "pki", "link", "add",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--email=alice@example.org",
            ],
        }),

        Action::Example(Example {
            comment: "\
Retract the acceptance of certificate EB28F26E2739A4870ECC47726F0073F60FD0CBF0 \
and the email address alice@example.org.",
            command: &[
                "sq", "pki", "link", "retract",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--email=alice@example.org",
            ],
        }),

        Action::Example(Example {
            comment: "\
Retract the acceptance of certificate EB28F26E2739A4870ECC47726F0073F60FD0CBF0 \
and any associated user IDs.  This effectively invalidates all links.",
            command: &[
                "sq", "pki", "link", "retract",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            ],
        }),
    ],
};
test_examples!(sq_pki_link_retract, RETRACT_EXAMPLES);

#[derive(Parser, Debug)]
#[clap(
    name = "list",
    about = "List links",
    long_about =
"List links

This command lists all bindings that are linked or whose link has been \
retracted.
",
    after_help = LIST_EXAMPLES,
)]
pub struct ListCommand {
    #[clap(
        long = "ca",
        required = false,
        help = "Only lists bindings linked as CAs.",
        long_help = "Only lists bindings linked as CAs.  That is, only list \
                     a link if its trust depth is greater than 0.",
    )]
    pub ca: bool,
}

const LIST_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Example(Example {
            comment: "\
Link the certificate EB28F26E2739A4870ECC47726F0073F60FD0CBF0 \
with the email address alice@example.org.",
            command: &[
                "sq", "pki", "link", "add",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
                "--email=alice@example.org",
            ],
        }),

        Action::Example(Example {
            comment: "List all links.",
            command: &[
                "sq", "pki", "link", "list",
            ],
        }),
    ],
};
test_examples!(sq_pki_link_list, LIST_EXAMPLES);
