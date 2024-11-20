//! Command-line parser for `sq key import`.

use std::path::PathBuf;

use clap::Args;

use crate::cli::examples::*;

#[derive(Debug, Args)]
#[clap(
    about = "Import keys into the key store",
    after_help = IMPORT_EXAMPLES,
)]
pub struct Command {
    #[clap(
        value_name = "KEY_FILE",
        help = "Import the keys in KEY_FILE",
    )]
    pub file: Vec<PathBuf>,
}

const IMPORT_EXAMPLES: Actions = Actions {
    actions: &[
        Action::Example(Example {
            comment: "\
Import the keys into the key store.",
            command: &[
                "sq", "key", "import", "alice-secret.pgp",
            ],
        }),
    ]
};
test_examples!(sq_key_import, IMPORT_EXAMPLES);
