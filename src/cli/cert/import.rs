use std::path::PathBuf;

use clap::Parser;

use crate::cli::examples;
use examples::Action;
use examples::Actions;
use examples::Example;

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::Example(Example {
            comment: "Import a certificate.",
            command: &[
                "sq", "cert", "import", "juliet.pgp",
            ],
        }),
    ]
};

test_examples!(sq_cert_import, EXAMPLES);

#[derive(Parser, Debug)]
#[clap(
    name = "import",
    about = "Import certificates into the local certificate store",
    long_about =
"Import certificates into the local certificate store
",
    after_help = EXAMPLES,
)]
pub struct Command {
    #[clap(value_name = "FILE", help = "Read from FILE or stdin if omitted")]
    pub input: Vec<PathBuf>,
}
