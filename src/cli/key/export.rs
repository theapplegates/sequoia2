//! Command-line parser for `sq key list`.

use clap::Args;

use sequoia_openpgp::KeyHandle;

use crate::cli::examples::*;

#[derive(Debug, Args)]
#[clap(
    about = "Export keys from the key store",
    long_about = "
Export keys from the key store.

Exports the secret key material associated with a certificate.  Note \
that even if secret key material is available, it may not be \
exportable.  For instance, secret key material stored on a hardware \
security module usually cannot be exported from the device.

If you only want to export a particular key and not all keys associate \
with a certificate, use `sq key subkey export`.
",
    after_help = EXAMPLES,
)]
pub struct Command {
    #[clap(
        long,
        value_name = "FINGERPRINT|KEYID",
        required = true,
        help = "Export the specified certificate with its secret key material",
        long_help = "\
Export the specified certificate with its secret key material.

Iterate over the specified certificate's primary key and subkeys and \
export any keys with secret key material.  An error is returned if \
the certificate does not contain any secret key material.",
    )]
    pub cert: Vec<KeyHandle>,
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
Export Alice's certificate with all available secret key material.",
            command: &[
                "sq", "key", "export",
                "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            ],
        }),
    ]
};
test_examples!(sq_key_export, EXAMPLES);
