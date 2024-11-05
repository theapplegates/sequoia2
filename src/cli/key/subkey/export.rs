use clap::Args;

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;

use crate::cli::examples;
use examples::Action;
use examples::Actions;
use examples::Example;
use examples::Setup;

use crate::cli::types::ClapData;
use crate::cli::types::FileOrStdout;

#[derive(Debug, Args)]
#[clap(
    about = "Export keys from the key store",
    long_about = "
Export secret key material from the secret key store.

Exports the secret key material.  Note that even if secret key \
material is available, it may not be exportable.  For instance, secret \
key material stored on a hardware security module usually cannot be \
exported from the device.

If you want to export all secret key material associated with a \
certificate, use `sq key export`.
",
    after_help = EXAMPLES,
)]
pub struct Command {
    #[clap(
        long,
        value_name = "FINGERPRINT|KEYID",
        required = true,
        help = "\
Export the secret key material for the specified key, and its certificate",
        long_help = "\
Export the specified key.

The entire certificate is exported, but only the specified key's \
secret key material is exported.  An error is returned if the secret \
key material for the specified key is not available.",
    )]
    pub key: Vec<KeyHandle>,

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
        Action::Setup(Setup {
            command: &[
                "sq", "key", "import", "alice-secret.pgp",
            ],
        }),
        Action::Example(Example {
            comment: "\
Export Alice's signing-capable and encryption-capable subkeys, but not \
her primary key or her authentication-capable subkey.",
            command: &[
                "sq", "key", "subkey", "export",
                "--key=42020B87D51877E5AF8D272124F3955B0B8DECC8",
                "--key=74DCDEAF17D9B995679EB52BA6E65EA2C8497728",
            ],
        }),
    ]
};
test_examples!(sq_subkey_key_export, EXAMPLES);
