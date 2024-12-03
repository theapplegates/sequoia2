//! Command-line parser for `sq config inspect policy`.

use clap::Args;

use crate::cli::examples::*;

#[derive(Debug, Args)]
#[clap(
    name = "policy",
    about = "Inspect the cryptographic policy",
    long_about = "\
Inspect the cryptographic policy

Prints the cryptographic policy in the format that Sequoia uses to \
configure acceptance, rejection, and cutoff times for cryptographic \
algorithms.

See https://docs.rs/sequoia-policy-config/
",
    after_help = EXAMPLES,
)]
pub struct Command {
}

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::example()
            .comment("Inspect the cryptographic policy.")
            .command(&[
                "sq", "config", "inspect", "policy",
            ])
            .build(),
    ],
};
test_examples!(sq_config_inspect_policy, EXAMPLES);
