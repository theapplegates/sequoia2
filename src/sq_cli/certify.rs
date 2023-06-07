use std::path::PathBuf;

use clap::Parser;

use crate::sq_cli::THIRD_PARTY_CERTIFICATION_VALIDITY_DURATION;
use crate::sq_cli::THIRD_PARTY_CERTIFICATION_VALIDITY_IN_YEARS;

use super::types::ClapData;
use super::types::Expiry;
use super::types::FileOrStdout;

#[derive(Parser, Debug)]
#[clap(
    name = "certify",
    about = "Certifies a User ID for a Certificate",
    long_about = format!(
"Certifies a User ID for a Certificate

Using a certification a keyholder may vouch for the fact that another
certificate legitimately belongs to a user id.  In the context of
emails this means that the same entity controls the key and the email
address.  These kind of certifications form the basis for the Web Of
Trust.

This command emits the certificate with the new certification.  The
updated certificate has to be distributed, preferably by sending it to
the certificate holder for attestation.  See also \"sq key
attest-certification\".

By default a certification expires after {} years.
Using the \"--expiry=EXPIRY\" argument specific validity periods may be defined.
It allows for providing a point in time for validity to end or a validity
duration.

\"sq certify\" respects the reference time set by the top-level
\"--time\" argument.  It sets the certification's creation time to the
reference time.
",
        THIRD_PARTY_CERTIFICATION_VALIDITY_IN_YEARS,
    ),
    after_help =
"EXAMPLES:

# Juliet certifies that Romeo controls romeo.pgp and romeo@example.org
$ sq certify juliet.pgp romeo.pgp \"<romeo@example.org>\"

# Certify the User ID \"Ada\", and set the certification time to July
# 21, 2013 at midnight UTC:
$ sq certify --time 20130721 neal.pgp ada.pgp Ada
",
)]
pub struct Command {
    #[clap(
        default_value_t = FileOrStdout::default(),
        help = FileOrStdout::HELP,
        long,
        short,
        value_name = FileOrStdout::VALUE_NAME,
    )]
    pub output: FileOrStdout,
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,
    #[clap(
        short = 'd',
        long = "depth",
        value_name = "TRUST_DEPTH",
        default_value = "0",
        help = "Sets the trust depth",
        long_help =
            "Sets the trust depth (sometimes referred to as the trust level).  \
            0 means a normal certification of <CERTIFICATE, USERID>.  \
            1 means CERTIFICATE is also a trusted introducer, 2 means \
            CERTIFICATE is a meta-trusted introducer, etc.",
    )]
    pub depth: u8,
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
    //TODO: use usize, not String
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
        short = 'l',
        long = "local",
        help = "Makes the certification a local certification",
        long_help =
            "Makes the certification a local \
            certification.  Normally, local \
            certifications are not exported.",
    )]
    pub local: bool,
    #[clap(
        long = "non-revocable",
        help = "Marks the certification as being non-revocable",
        long_help =
            "Marks the certification as being non-revocable. \
            That is, you cannot later revoke this \
            certification.  This should normally only \
            be used with an expiration.",
    )]
    pub non_revocable: bool,
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
        long = "expiry",
        value_name = "EXPIRY",
        default_value_t =
            Expiry::Duration(THIRD_PARTY_CERTIFICATION_VALIDITY_DURATION),
        help =
            "Defines EXPIRY for the certification as ISO 8601 formatted string or \
            custom duration.",
        long_help =
            "Defines EXPIRY for the certification as ISO 8601 formatted string or \
            custom duration. \
            If an ISO 8601 formatted string is provided, the validity period \
            reaches from the reference time (may be set using \"--time\") to \
            the provided time. \
            Custom durations starting from the reference time may be set using \
            \"N[ymwds]\", for N years, months, weeks, days, or seconds. \
            The special keyword \"never\" sets an unlimited expiry.",
    )]
    pub expiry: Expiry,
    #[clap(
        long = "allow-not-alive-certifier",
        help = "Don't fail if the certificate making the \
                certification is not alive.",
        long_help =
            "Allows the key to make a certification even if \
             the current time is prior to its creation time \
             or the current time is at or after its expiration \
             time.",
    )]
    pub allow_not_alive_certifier: bool,
    #[clap(
        long = "allow-revoked-certifier",
        help = "Don't fail if the certificate making the \
                certification is revoked.",
    )]
    pub allow_revoked_certifier: bool,
    #[clap(
        long = "private-key-store",
        value_name = "KEY_STORE",
        help = "Provides parameters for private key store",
    )]
    pub private_key_store: Option<String>,
    #[clap(
        value_name = "CERTIFIER-KEY",
        required = true,
        index = 1,
        help = "Creates the certification using CERTIFIER-KEY.",
    )]
    pub certifier: PathBuf,
    #[clap(
        value_name = "CERTIFICATE",
        required = true,
        index = 2,
        help = "Certifies CERTIFICATE.",
    )]
    pub certificate: String,
    #[clap(
        value_name = "USERID",
        required = true,
        index = 3,
        help = "Certifies USERID for CERTIFICATE.",
    )]
    pub userid: String,
}
