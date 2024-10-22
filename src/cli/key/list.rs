//! Command-line parser for `sq key list`.

use clap::Args;

use crate::cli::examples::*;

#[derive(Debug, Args)]
#[clap(
    about = "List keys managed by the key store",
    after_help = EXAMPLES,
)]
pub struct Command {
}

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::Example(Example {
            comment: "\
List the keys managed by the keystore server.",
            command: &[
                "sq", "key", "list",
            ],
        }),
    ]
};
test_examples!(sq_key_list, EXAMPLES);
