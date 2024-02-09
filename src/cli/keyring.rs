//! Command-line parser for `sq keyring`.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;

use super::types::ClapData;
use super::types::FileOrStdin;
use super::types::FileOrStdout;

#[derive(Parser, Debug)]
#[clap(
    name = "keyring",
    about = "Manages collections of keys or certs",
    long_about =
"Manages collections of keys or certs

Collections of keys or certificates (also known as \"keyrings\" when
they contain secret key material, and \"certrings\" when they don't) are
any number of concatenated certificates.  This subcommand provides
tools to list, split, merge, and filter keyrings.

Note: In the documentation of this subcommand, we sometimes use the
terms keys and certs interchangeably.
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
    List(ListCommand),
    Split(SplitCommand),
    Merge(MergeCommand),
    Filter(FilterCommand),
}

#[derive(Debug, Args)]
#[clap(
    about = "Joins keys into a keyring applying a filter",
    long_about =
"Joins keys into a keyring applying a filter

This can be used to filter keys based on given predicates,
e.g. whether they have a user id containing an email address with a
certain domain.  Additionally, the keys can be pruned to only include
components matching the predicates.

If no filters are supplied, everything matches.

If multiple predicates are given, they are or'ed, i.e. a key matches
if any of the predicates match.  To require all predicates to match,
chain multiple invocations of this command.  See EXAMPLES for
inspiration.
",
    after_help =
"EXAMPLES:

# Converts a key to a cert (i.e., remove any secret key material)
$ sq keyring filter --to-cert cat juliet.pgp

# Gets the keys with a user id on example.org
$ sq keyring filter --domain example.org keys.pgp

# Gets the keys with a user id on example.org or example.net
$ sq keyring filter --domain example.org --domain example.net \\
     keys.pgp

# Gets the keys with a user id with the name Juliet
$ sq keyring filter --name Juliet keys.pgp

# Gets the keys with a user id with the name Juliet on example.org
$ sq keyring filter --domain example.org keys.pgp | \\
  sq keyring filter --name Juliet

# Gets the keys with a user id on example.org, pruning other userids
$ sq keyring filter --domain example.org --prune-certs certs.pgp
",
)]
pub struct FilterCommand {
    #[clap(value_name = "FILE", help = "Reads from FILE or stdin if omitted")]
    pub input: Vec<PathBuf>,
    #[clap(
        default_value_t = FileOrStdout::default(),
        help = FileOrStdout::HELP_OPTIONAL,
        long,
        short,
        value_name = FileOrStdout::VALUE_NAME,
    )]
    pub output: FileOrStdout,
    #[clap(
        long = "userid",
        value_name = "USERID",
        help = "Matches on USERID",
        long_help = "Case-sensitively matches on the \
                user id, requiring an exact match.",
    )]
    pub userid: Vec<String>,
    #[clap(
        long = "name",
        value_name = "NAME",
        help = "Matches on NAME",
        long_help = "Parses user ids into name and email \
            and case-sensitively matches on the \
            name, requiring an exact match.",
    )]
    pub name: Vec<String>,
    #[clap(
        long = "email",
        value_name = "ADDRESS",
        help = "Matches on email ADDRESS",
        long_help = "Parses user ids into name and email \
            address and case-sensitively matches \
            on the email address, requiring an exact match.",
    )]
    pub email: Vec<String>,
    #[clap(
        long = "domain",
        value_name = "FQDN",
        help = "Matches on email domain FQDN",
        long_help =
            "Parses user ids into name and email \
            address and case-sensitively matches \
            on the domain of the email address, \
            requiring an exact match.",
    )]
    pub domain: Vec<String>,
    #[clap(
        long = "handle",
        value_name = "FINGERPRINT|KEYID",
        help = "Matches on (sub)key fingerprints and key ids",
        long_help =
            "Matches on both primary keys and subkeys, \
            including those certificates that match the \
            given fingerprint or key id.",
    )]
    pub handle: Vec<KeyHandle>,
    #[clap(
        short = 'P',
        long = "prune-certs",
        help = "Removes certificate components not matching the filter",
    )]
    pub prune_certs: bool,
    #[clap(
        short = 'B',
        long = "binary",
        help = "Emits binary data",
    )]
    pub binary: bool,
    #[clap(
        long = "to-cert",
        help = "Converts any keys in the input to \
            certificates.  Converting a key to a \
            certificate removes secret key material \
            from the key thereby turning it into \
            a certificate.",
    )]
    pub to_certificate: bool,
}

#[derive(Debug, Args)]
#[clap(
    about = "Merges keys or keyrings into a single keyring",
    long_about =
"Merges keys or keyrings into a single keyring

Multiple
versions of the same certificate are merged together.  Where data is
replaced (e.g., secret key material), data from the later certificate
is preferred.
",
    after_help =
"EXAMPLES:

# Merge certificate updates
$ sq keyring merge certs.pgp romeo-updates.pgp
",
)]
pub struct MergeCommand {
    #[clap(value_name = "FILE", help = "Reads from FILE or stdin if omitted")]
    pub input: Vec<PathBuf>,
    #[clap(
        default_value_t = FileOrStdout::default(),
        help = FileOrStdout::HELP_OPTIONAL,
        long,
        short,
        value_name = FileOrStdout::VALUE_NAME,
    )]
    pub output: FileOrStdout,
    #[clap(
        short = 'B',
        long = "binary",
        help = "Emits binary data",
    )]
    pub binary: bool,
}

#[derive(Debug, Args)]
#[clap(
    about = "Lists keys in a keyring",
    long_about =
"Lists keys in a keyring

Prints the fingerprint as well as the primary userid for every
certificate encountered in the keyring.
",
    after_help =
"EXAMPLES:

# List all certs
$ sq keyring list certs.pgp

# List all certs with a userid on example.org
$ sq keyring filter --domain example.org certs.pgp \\
     | sq keyring list
",
)]
pub struct ListCommand {
    #[clap(
        default_value_t = FileOrStdin::default(),
        help = FileOrStdin::HELP_OPTIONAL,
        value_name = FileOrStdin::VALUE_NAME,
    )]
    pub input: FileOrStdin,
    #[clap(
        long = "all-userids",
        help = "Lists all user ids",
        long_help = "Lists all user ids, even those that are \
            expired, revoked, or not valid under the \
            standard policy.",
    )]
    pub all_userids: bool,
}

#[derive(Debug, Args)]
#[clap(
    about = "Splits a keyring into individual keys",
    long_about =
"Splits a keyring into individual keys

Splitting up a keyring into individual keys helps with curating a
keyring.

The converse operation is `sq keyring merge`.
",
    after_help =
"EXAMPLES:

# Split all certs
$ sq keyring split certs.pgp

# Split all certs, merging them first to avoid duplicates
$ sq keyring merge certs.pgp | sq keyring split
",
)]
pub struct SplitCommand {
    #[clap(
        default_value_t = FileOrStdin::default(),
        help = FileOrStdin::HELP_OPTIONAL,
        value_name = FileOrStdin::VALUE_NAME,
    )]
    pub input: FileOrStdin,
    #[clap(
        short = 'p',
        long = "prefix",
        value_name = "PREFIX",
        help = "Writes to files with PREFIX \
            [defaults: `FILE-` if FILE is set, or `output-` if read from stdin]",
    )]
    pub prefix: Option<String>,
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,
}
