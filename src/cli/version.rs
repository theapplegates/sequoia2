//! Command-line parser for `sq inspect`.

use clap::Parser;

#[derive(Parser, Debug)]
#[clap(
    name = "version",
    about = "Detailed version and output version information",
    long_about =
"Detailed version and output version information

With no further options, this command lists the version of `sq`, the
version of the underlying OpenPGP implementation `sequoia-openpgp`,
and which cryptographic library is used.

This command can also be used to query the output format versions for
the machine-readable output of various subcommands, and the default
output format versions.

",
)]
pub struct Command {
    /// List the default output version.
    #[clap(
        long,
        conflicts_with = "output_versions",
    )]
    pub default_output_version: bool,

    /// List all the supported output versions.
    #[clap(
        long,
        conflicts_with = "default_output_version",
    )]
    pub output_versions: bool,
}
