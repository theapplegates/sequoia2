use clap::{ArgGroup, Parser, Subcommand};

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;

#[derive(Parser, Debug)]
#[clap(
    name = "link",
    about = "Manages authenticated certificate and User ID links",
    long_about =
"Manages authenticated certificate and User ID links

Link a certificate and User ID is one way of making \"sq\" consider a
binding to be authentic.  Another way is to use \"sq certify\" to
certify the binding with an explicitly configured trust root.  The
linking functionality is often easier to work with, and the
information is private by default.

Authenticated bindings can be used to designate a certificate using a
symbolic name.  For instance, using \"sq encrypt\"'s
\"--recipient-userid\" and \"--recipient-email\" options, a user can
designate a certificate using a User ID or an email address that is
authenticated for that certificate.

\"sq\" also uses authenticated certificates to authenticate other
data.  For instance, \"sq verify\" considers signatures made by an
authenticated certificate to be authentic.

Users can create a link using \"sq link add\".  That link can later be
retracted using \"sq link retract\".  A certificate can also be
accepted as a trusted introducer by passing the \"--ca\" option to
\"sq link add\".

\"sq\" implements linking using non-exportable certifications, and an
implicit trust root.  An OpenPGP certificate directory, the default
certificate store used by \"sq\", includes a local trust root, which
is stored under the \"trust-root\" special name.  When the user
instructs \"sq\" to accept a binding, \"sq\" uses the local trust root
to create a non-exportable certification, which it stores in the
certificate directory.  In this way, operations that use the web of
trust to authenticate a binding automatically use links.

When a user retracts a link, \"sq\" creates a new, non-exportable
certification with zero trust.  This certification suppresses the
previous link.
",
after_help = "EXAMPLES:

# Link 0123456789ABCDEF and User ID \"<romeo@example.org>\".
$ sq link add 0123456789ABCDEF \"<romeo@example.org>\"

# Link the certificate 0123456789ABCDEF with its current set of
# self-signed User IDs as a trusted introducer for example.org.
$ sq link add --ca example.org 0123456789ABCDEF

# Link the certificate 0123456789ABCDEF with its current set of
# self-signed User IDs as a trusted introducer.
$ sq link add --ca '*' 0123456789ABCDEF

# Retract the link between 0123456789ABCDEF and \"<romeo@example.org>\".
$ sq link retract 0123456789ABCDEF \"<romeo@example.org>\"

# Retract all links associated with 0123456789ABCDEF.
$ sq link retract 0123456789ABCDEF
",
    subcommand_required = true,
    arg_required_else_help = true,
)]
pub struct Command {
    #[clap(subcommand)]
    pub subcommand: Subcommands,
}

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
"Link a certificate and a User ID.  This cause \"sq\" to considers
the certificate and User ID binding to be authentic.

A certificate can also be accepted as a certification authority, which
is also known as a trusted introducer, by using the \"--ca\" or
\"--depth\" option.

A link can be retracted using \"sq link retract\".

This command is similar to \"sq certify\", but the certifications it
makes are done using the certificate directory's trust root, not an
arbitrary key.  Further, the certificates are marked as
non-exportable.  The former makes it easier to manage certifications,
especially when the user's certification key is offline.  And the
latter improves the user's privacy, by reducing the chance that parts
of the user's social graph is leaked when a certificate is shared.
",
    after_help =
"EXAMPLES:

# The user links 0123456789ABCDEF and the User ID
# \"<romeo@example.org>\".
$ sq link add 0123456789ABCDEF \"<romeo@example.org>\"

# The user examines 0123456789ABCDEF and then accepts the certificate
# 0123456789ABCDEF with its current set of self-signed User IDs.
$ sq export --cert 0123456789ABCDEF | sq inspect
...
$ sq link add 0123456789ABCDEF

# The user links the certificate and its current self-signed User
# IDs for a week.
$ sq link add --expires-in 1w 0123456789ABCDEF

# The user accepts the certificate, and its current self-signed User
# IDs as a certification authority.  That is, the certificate is
# considered a trust root.
$ sq link add --ca '*' 0123456789ABCDEF

# The user accepts the certificate and its current self-signed User
# IDs as a partially trusted certification authority.
$ sq link add --ca --amount 60 0123456789ABCDEF

# The user retracts their acceptance of 0123456789ABCDEF and any
# associated User IDs.  This effectively invalidates any links.
$ sq link retract 0123456789ABCDEF
",
)]
#[clap(group(ArgGroup::new("expiration-group").args(&["expires", "expires_in"])))]
pub struct AddCommand {
    #[clap(
        short = 'd',
        long = "depth",
        value_name = "TRUST_DEPTH",
        help = "Sets the trust depth",
        long_help =
            "Sets the trust depth (sometimes referred to as the trust level).  \
            0 means a normal certification of <CERTIFICATE, USERID>.  \
            1 means CERTIFICATE is also a trusted introducer, 2 means \
            CERTIFICATE is a meta-trusted introducer, etc.",
    )]
    pub depth: Option<u8>,
    #[clap(
        long = "ca",
        value_name = "*|DOMAIN",
        help = "Marks the certificate as a certification authority for a domain",
        long_help =
            "Marks the certificate as a certification authority for a  \
             domain.  Use * to make the certificate a certification for \
             any User ID.  \
             \
             A certification authority is also referred to as a trusted \
             introducer.  This command is equivalent to making the trust \
             depth unconstrained, i.e., setting the depth to 255.  See \
             \"--depth\" for more information.",
    )]
    pub ca: Vec<String>,
    #[clap(
        short = 'a',
        long = "amount",
        value_name = "TRUST_AMOUNT",
        default_value = "120",
        help = "Sets the amount of trust",
        long_help =
            "Sets the amount of trust.  Values between 1 and 120 are meaningful. \
            120 means fully trusted.  Values less than 120 indicate the degree \
            of trust.  60 is usually used for partially trusted.",
    )]
    pub amount: u8,
    #[clap(
        short = 'r',
        long = "regex",
        value_name = "REGEX",
        help = "Adds a regular expression to constrain \
            what a trusted introducer can certify",
        long_help =
            "Adds a regular expression to constrain \
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
        long,
        value_names = &["NAME", "VALUE"],
        number_of_values = 2,
        help = "Adds a notation to the certification.",
        long_help = "Adds a notation to the certification.  \
            A user-defined notation's name must be of the form \
            \"name@a.domain.you.control.org\". If the notation's name starts \
            with a !, then the notation is marked as being critical.  If a \
            consumer of a signature doesn't understand a critical notation, \
            then it will ignore the signature.  The notation is marked as \
            being human readable."
    )]
    pub notation: Vec<String>,
    #[clap(
        long = "expires",
        value_name = "TIME",
        help = "Makes the acceptance expire at TIME (as ISO 8601)",
        long_help =
            "Makes the acceptance expire at TIME (as ISO 8601). \
             Use \"never\" (the default), to indicate the acceptance does \
             not expire.",
    )]
    pub expires: Option<String>,
    #[clap(
        long = "expires-in",
        value_name = "DURATION",
        // Catch negative numbers.
        allow_hyphen_values = true,
        help = "Makes the acceptance expire after DURATION \
            (as N[ymwds]) [default: 5y]",
        long_help =
            "Makes the certification expire after DURATION. \
            Either \"N[ymwds]\", for N years, months, \
            weeks, days, seconds, or \"never\".  [default: 5y]",
    )]
    pub expires_in: Option<String>,
    #[clap(
        value_name = "FINGERPRINT|KEYID",
        required = true,
        help = "The certificate to accept.",
    )]
    pub certificate: KeyHandle,

    #[clap(
        long = "userid",
        value_name = "USERID",
        required = false,
        help = "A User ID to link to the certificate.",
        long_help = "A User ID to link to the certificate.  This must match \
                     a self-signed User ID.  To link a User ID to the \
                     certificate that does not have a self-signature, use \
                     \"--petname\".  If no User IDs, email addresses, or \
                     petnames are provided, then all User IDs that have a \
                     valid self-signature according to the policy are \
                     linked.",
    )]
    pub userid: Vec<String>,
    #[clap(
        long = "email",
        value_name = "EMAIL",
        required = false,
        help = "An email address to link to the certificate.",
        long_help = "An email address to link to the certificate.  The email \
                     address must match the email address of a \
                     self-signed User ID.  To link an email address to the \
                     certificate that does not appear in a self-signed \
                     User ID, use \"--petname\".  If the specified email \
                     appears in multiple self-signed User IDs, then all of \
                     them are linked.  If no User IDs, email addresses, or \
                     petnames are provided, then all User IDs that have a \
                     valid self-signature according to the policy are \
                     linked.",
    )]
    pub email: Vec<String>,
    #[clap(
        long = "petname",
        value_name = "PETNAME",
        required = false,
        help = "A User ID to link to the certificate.",
        long_help = "A User ID to link to the certificate.  Unlike \"--userid\", \
                     this does not need to match a self-signed User ID.  Bare \
                     email address are automatically wrapped in angle brackets. \
                     That is if \"alice@example.org\" is provided, it is \
                     silently converted to \"<alice@example.org>\".  If no \
                     User IDs, email addresses, or petnames are provided, then \
                     all User IDs that have a valid self-signature according \
                     to the policy are linked.",
    )]
    pub petname: Vec<String>,

    #[clap(
        value_name = "USERID|EMAIL",
        required = false,
        help = "A User ID or email address to accept.",
        long_help = "A User ID or email address to link to the certificate.  \
                     This must match a self-signed User ID.  To link a User ID \
                     to the certificate that does not have a self-signature, \
                     use \"--petname\".  Scripts should prefer to use \
                     \"--email\" or \"--userid\", as \"sq\" does not need to \
                     guess if a value is a User ID or an email address. \
                     If no User IDs, email addresses, or petnames are provided, \
                     then all User IDs that have a valid self-signature \
                     according to the policy are linked.",
    )]
    pub pattern: Vec<String>,
}

#[derive(Parser, Debug)]
#[clap(
    name = "retract",
    about = "Retracts links",
    long_about =
"Retracts links.

This command retracts links that were previously created using \"sq
link add\".  See that subcommand's documentation for more details.
Note: this is called \"retract\" and not \"remove\", because the
certifications are not removed.  Instead a new certification is added,
which says that the binding has not been authenticated.

\"sq link retract\" respects the reference time set by the top-level
\"--time\" argument.  This causes a link to be retracted as of a
particular time instead of the current time.
",
)]
pub struct RetractCommand {
    #[clap(
        long,
        value_names = &["NAME", "VALUE"],
        number_of_values = 2,
        help = "Adds a notation to the certification.",
        long_help = "Adds a notation to the certification.  \
            A user-defined notation's name must be of the form \
            \"name@a.domain.you.control.org\". If the notation's name starts \
            with a !, then the notation is marked as being critical.  If a \
            consumer of a signature doesn't understand a critical notation, \
            then it will ignore the signature.  The notation is marked as \
            being human readable."
    )]
    pub notation: Vec<String>,
    #[clap(
        value_name = "FINGERPRINT|KEYID",
        required = true,
        help = "The certificate whose acceptance is being retracted.",
    )]
    pub certificate: KeyHandle,


    #[clap(
        long = "userid",
        value_name = "USERID",
        required = false,
        help = "A User ID to unlink from the certificate.",
        long_help = "A User ID to unlink from the certificate.  This must match \
                     a known User ID, although it need not be linked.",
    )]
    pub userid: Vec<String>,
    #[clap(
        long = "email",
        value_name = "email",
        required = false,
        help = "An email address to unlink from the certificate.",
        long_help = "An email address to unlink from the certificate.  The email \
                     address must match a User ID with the email, although, \
                     it need not be linked.",
    )]
    pub email: Vec<String>,

    #[clap(
        value_name = "USERID|EMAIL",
        required = false,
        help = "A User ID or email address to unlink from the certificate.",
        long_help = "A User ID or email address to unlink from the certificate.  \
                     This must match a known User ID.  Scripts should prefer to \
                     use \"--email\" or \"--userid\", as \"sq\" does not need to \
                     guess if a value is a User ID or an email address. \
                     If no User IDs, or email addresses are provided, \
                     then all known User IDs are unlinked.",
    )]
    pub pattern: Vec<String>,
}

#[derive(Parser, Debug)]
#[clap(
    name = "list",
    about = "Lists links",
    long_about =
"Lists links.

This command lists all bindings that are linked or whose link has been
retracted.
",
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
