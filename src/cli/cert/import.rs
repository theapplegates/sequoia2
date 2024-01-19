use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[clap(
    name = "import",
    about = "Imports certificates into the local certificate store",
    long_about =
"Imports certificates into the local certificate store
",
    after_help =
"EXAMPLES:

# Imports a certificate.
$ sq cert import < juliet.pgp
",
)]
pub struct Command {
    #[clap(value_name = "FILE", help = "Reads from FILE or stdin if omitted")]
    pub input: Vec<PathBuf>,
}
