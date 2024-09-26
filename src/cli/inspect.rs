//! Command-line parser for `sq inspect`.

use clap::Parser;

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;

use super::types::ClapData;
use super::types::FileOrStdin;

use crate::cli::examples;
use examples::Action;
use examples::Actions;
use examples::Example;

const INSPECT_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Example(Example {
            comment: "\
Inspect a certificate.",
            command: &[
                "sq", "inspect", "juliet.pgp",
            ],
        }),
        Action::Example(Example {
            comment: "\
Show how the certificate looked on July 21, 2013.",
            command: &[
                "sq", "inspect", "--time", "20130721", "juliet.pgp",
            ],
        }),
        Action::Example(Example {
            comment: "\
Inspect an encrypted message.",
            command: &[
                "sq", "inspect", "message.pgp",
            ],
        }),
        Action::Example(Example {
            comment: "\
Inspect a detached signature.",
            command: &[
                "sq", "inspect", "document.sig",
            ],
        }),
    ]
};
test_examples!(sq_inspect, INSPECT_EXAMPLES);

#[derive(Parser, Debug)]
#[clap(
    name = "inspect",
    about = "Inspect data, like file(1)",
    long_about =
"Inspect data, like file(1)

It is often difficult to tell from cursory inspection using cat(1) or
file(1) what kind of OpenPGP one is looking at.  This subcommand
inspects the data and provides a meaningful human-readable description
of it.

`sq inspect` respects the reference time set by the top-level
`--time` argument.  It uses the reference time when determining what
binding signatures are active.
",
    after_help = INSPECT_EXAMPLES,
)]
pub struct Command {
    #[clap(
        default_value_t = FileOrStdin::default(),
        help = FileOrStdin::HELP_OPTIONAL,
        value_name = FileOrStdin::VALUE_NAME,
    )]
    pub input: FileOrStdin,
    #[clap(
        long = "cert",
        value_name = "FINGERPRINT|KEYID",
        conflicts_with = "input",
        help = "Read the specified certificate from the certificate store",
    )]
    pub cert: Vec<KeyHandle>,

    #[clap(
        long = "certifications",
        help = "Print third-party certifications",
    )]
    pub certifications: bool,

    #[clap(
        long = "dump-bad-signatures",
        help = "Dump signatures that are definitively bad",
    )]
    pub dump_bad_signatures: bool,
}
