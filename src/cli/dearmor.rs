use clap::Parser;

use super::types::ClapData;
use super::types::FileOrStdin;
use super::types::FileOrStdout;

#[derive(Parser, Debug)]
#[clap(
    name = "dearmor",
    about = "Converts ASCII to binary",
    long_about =
"Converts ASCII to binary

To make encrypted data easier to handle and transport, OpenPGP data
can be transformed to an ASCII representation called ASCII Armor.  sq
transparently handles armored data, but this subcommand can be used to
explicitly convert existing ASCII-encoded OpenPGP data to its binary
representation.

The converse operation is \"sq armor\".
",
    after_help =
"EXAMPLES:

# Convert a ASCII certificate to binary
$ sq dearmor ascii-juliet.pgp

# Convert a ASCII message to binary
$ sq dearmor ascii-message.pgp
",
    )]
pub struct Command {
    #[clap(
        default_value_t = FileOrStdin::default(),
        help = FileOrStdin::HELP_OPTIONAL,
        value_name = FileOrStdin::VALUE_NAME,
    )]
    pub input: FileOrStdin,
    #[clap(
        default_value_t = FileOrStdout::default(),
        help = FileOrStdout::HELP_OPTIONAL,
        long,
        short,
        value_name = FileOrStdout::VALUE_NAME,
    )]
    pub output: FileOrStdout,
}
