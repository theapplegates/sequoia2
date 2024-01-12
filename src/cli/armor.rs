use clap::Parser;

use super::types::ArmorKind;
use super::types::ClapData;
use super::types::FileOrStdin;
use super::types::FileOrStdout;

// TODO?: Option<_> conflicts with default value
// TODO: use indoc to transparently (de-)indent static strings
#[derive(Parser, Debug)]
#[clap(
    name = "armor",
    about = "Converts binary to ASCII",
    long_about =
"Converts binary to ASCII

To make encrypted data easier to handle and transport, OpenPGP data
can be transformed to an ASCII representation called ASCII Armor.  sq
emits armored data by default, but this subcommand can be used to
convert existing OpenPGP data to its ASCII-encoded representation.

The converse operation is `sq dearmor`.
",
    after_help =
"EXAMPLES:

# Convert a binary certificate to ASCII
$ sq armor binary-juliet.pgp

# Convert a binary message to ASCII
$ sq armor binary-message.pgp
"
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
    #[clap(
        long = "label",
        value_name = "LABEL",
        help = "Selects the kind of armor header",
        default_value_t = ArmorKind::Auto,
        value_enum
    )]
    pub kind: ArmorKind,
}
