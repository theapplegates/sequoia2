//! Command-line parser for `sq download`.

use clap::Parser;

use crate::cli::examples;
use examples::Action;
use examples::Actions;
use examples::Example;
use examples::Setup;

use super::types::ClapData;
use super::types::cert_designator::*;
use crate::cli::types::FileOrStdout;

const EXAMPLES: Actions = Actions {
    actions: &[
        Action::Setup(Setup {
            command: &[
                "sq", "cert", "import", "debian/debian-cd-signing-key.pgp",
            ],
        }),
        Action::Example(Example {
            comment: "\
Verify the Debian 12 checksum file.",
            command: &[
                "sq", "download",
                "--url=file://debian/SHA512SUMS",
                "--signature=file://debian/SHA512SUMS.sign",
                "--signer=DF9B9C49EAA9298432589D76DA87E80D6294BE9B",
            ],
        }),
    ]
};
test_examples!(sq_download, EXAMPLES);

#[derive(Parser, Debug)]
#[clap(
    name = "download",
    about = "Download and authenticate the data",
    long_about =
"Download and authenticates the data.

This command downloads the data from the specified URL, checks the
signature, and then authenticates the signer.  If the signer cannot be
authenticated, the data is deleted, if possible.
",
    after_help = EXAMPLES,
)]
pub struct Command {
    #[clap(
        long = "url",
        value_name = "URL",
        help = "The data to download",
    )]
    pub url: String,

    #[clap(
        long = "signature",
        value_name = "URL",
        help = "URL of the signature",
        long_help = "\
URL of the signature.

Use this when the signature is detached from the data.

If no signature is specified, then the signature is assumed to be \
inline.
",
    )]
    pub signature: Option<String>,

    #[command(flatten)]
    pub signers: CertDesignators<CertFileArgs,
                                 SignerPrefix,
                                 OptionalValue,
                                 ToVerifyDoc>,

    #[clap(
        long = "signatures",
        value_name = "N",
        default_value_t = 1,
        help = "Set the threshold of valid signatures to N",
        long_help = "Set the threshold of valid signatures to N. \
                     If this threshold is not reached, the message \
                     will not be considered verified."
    )]
    pub signatures: usize,

    #[clap(
        help = FileOrStdout::HELP_OPTIONAL,
        long,
        value_name = FileOrStdout::VALUE_NAME,
        default_value = "-",
    )]
    pub output: FileOrStdout,
}
