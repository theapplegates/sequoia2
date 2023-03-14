use clap::Parser;

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;

#[derive(Parser, Debug)]
#[clap(
    name = "export",
    about = "Exports certificates from the local certificate store",
    long_about =
"Exports certificates from the local certificate store

If multiple predicates are specified a certificate is returned if
at least one of them matches.

This does not check the authenticity of the certificates in anyway.
Before using the certificates, be sure to validate and authenticate
them.

When matching on subkeys or User IDs, the component must have a valid
self signature according to the policy.  This is not the case when
matching the certificate's key handle using `--cert` or when exporting
all certificates.

Fails if search criteria are specified and none of them matches any
certificates.  Note: this means if the certificate store is empty and
no search criteria are specified, then this will return success.",
    after_help =
"EXAMPLES:

# Exports all certificates.
$ sq export > all.pgp

# Exports certificates with a matching User ID packet.  The binding
# signatures are checked, but the User IDs are not authenticated.
# Note: this check is case sensitive.
$ sq export --userid 'Alice <alice@example.org>'

# Exports certificates with a User ID containing the email address.
# The binding signatures are checked, but the User IDs are not
# authenticated.  Note: this check is case insensitive.
$ sq export --email 'alice@example.org'

# Exports certificates where the certificate (i.e., the primary key)
# has the specified Key ID.
$ sq export --cert 1234567812345678

# Exports certificates where the primary key or a subkey matches the
# specified Key ID.
$ sq export --key 1234567812345678

# Exports certificates that contain a User ID with *either* (not
# both!) email address.  Note: this check is case insensitive.
$ sq export --email alice@example.org --email bob@example.org
",
)]
pub struct Command {
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,

    #[clap(
        long = "cert",
        value_name = "FINGERPRINT|KEYID",
        multiple_occurrences = true,
        help = "Returns certificates that \
                have the specified fingerprint or key ID",
    )]
    pub cert: Vec<KeyHandle>,

    #[clap(
        long = "key",
        value_name = "FINGERPRINT|KEYID",
        multiple_occurrences = true,
        help = "Returns certificates where the primary key or \
                a subkey has the specified fingerprint or key ID",
    )]
    pub key: Vec<KeyHandle>,

    #[clap(
        long = "userid",
        value_name = "USERID",
        multiple_occurrences = true,
        help = "Returns certificates that have a User ID that \
                matches exactly, including case",
    )]
    pub userid: Vec<String>,

    #[clap(
        long = "grep",
        value_name = "PATTERN",
        multiple_occurrences = true,
        help = "Returns certificates that have a User ID that \
                contains the string, case insensitively",
    )]
    pub grep: Vec<String>,

    #[clap(
        long = "email",
        value_name = "EMAIL",
        multiple_occurrences = true,
        help = "Returns certificates that have a User ID with \
                the specified email address, case insensitively",
    )]
    pub email: Vec<String>,

    #[clap(
        long = "domain",
        value_name = "DOMAIN",
        multiple_occurrences = true,
        help = "Returns certificates that have a User ID with \
                an email address from the specified domain",
    )]
    pub domain: Vec<String>,
}
