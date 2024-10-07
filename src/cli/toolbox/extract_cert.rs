use clap::Args;

use crate::cli::examples::*;
use crate::cli::types::ClapData;
use crate::cli::types::FileOrStdin;
use crate::cli::types::FileOrStdout;

#[derive(Debug, Args)]
#[clap(
    name = "extract-cert",
    about = "Convert a key to a cert",
    long_about =
"Convert a key to a cert

After generating a key, use this command to get the certificate \
corresponding to the key.  The key must be kept secure, while the \
certificate should be handed out to correspondents, e.g. by uploading \
it to a key server.
",
    after_help = EXAMPLES,
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
        value_name = FileOrStdout::VALUE_NAME,
    )]
    pub output: FileOrStdout,
    #[clap(
        long,
        help = "Emit binary data",
    )]
    pub binary: bool,
}

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::Example(Example {
            comment: "\
Extract Alice's cert from her secret key material.",
            command: &[
                "sq", "toolbox", "extract-cert",
                "alice-secret.pgp",
            ],
        }),
    ],
};
test_examples!(sq_toolbox_extract_cert, EXAMPLES);
