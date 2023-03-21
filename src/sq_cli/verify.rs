use clap::Parser;

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;

use crate::sq_cli::types::IoArgs;

#[derive(Parser, Debug)]
#[clap(
    name = "verify",
    about = "Verifies signed messages or detached signatures",
    long_about = "Verifies signed messages or detached signatures

When verifying signed messages, the message is written to stdout or
the file given to --output.

When a detached message is verified, no output is produced.  Detached
signatures are often used to sign software packages.

Verification is only successful if there is no bad signature, and the
number of successfully verified signatures reaches the threshold
configured with the \"--signatures\" parameter.  If the verification
fails, the program terminates with an exit status indicating failure.
In addition to that, the last 25 MiB of the message are withheld,
i.e. if the message is smaller than 25 MiB, no output is produced, and
if it is larger, then the output will be truncated.

A signature is considered to have been authenticated if the signer can
be authenticated.  If the signer is provided via \"--signer-file\",
then the signer is considered authenticated.  Otherwise, the signer is
looked up and authenticated using the web of trust.  If at least one
User ID can be fully authenticated, then the signature is considered
to have been authenticated.  If the signature includes a Signer User
ID subpacket, then only that User ID is considered.  Note: the User ID
need not be self signed.

The converse operation is \"sq sign\".

If you are looking for a standalone program to verify detached
signatures, consider using sequoia-sqv.

\"sq verify\" respects the reference time set by the top-level
\"--time\" argument.  When set, it verifies the message as of the
reference time instead of the current time.
",
    after_help =
"EXAMPLES:

# Verify a signed message
$ sq verify --signer-file juliet.pgp signed-message.pgp

# Verify a detached message
$ sq verify --signer-file juliet.pgp --detached message.sig message.txt

# Verify a message as of June 9, 2011 at midnight UTC:
$ sq verify --time 20130721 msg.pgp
",
    )]
pub struct Command {
    #[clap(flatten)]
    pub io: IoArgs,
    #[clap(
        long = "detached",
        value_name = "SIG",
        help = "Verifies a detached signature"
    )]
    pub detached: Option<String>,
    #[clap(
        short = 'n',
        long = "signatures",
        value_name = "N",
        default_value_t = 1,
        help = "Sets the threshold of valid signatures to N",
        long_help = "Sets the threshold of valid signatures to N. \
                            If this threshold is not reached, the message \
                            will not be considered verified."
    )]
    pub signatures: usize,
    #[clap(
        long = "signer-file",
        value_name = "CERT_FILE",
        help = "Verifies signatures using the certificate in CERT_FILE",
    )]
    // TODO: Should at least one sender_file be required? Verification does not make sense
    // without one, does it?
    // TODO Use PathBuf instead of String. Path representation is platform dependent, so Rust's
    // utf-8 Strings are not quite appropriate.
    // TODO: And adapt load_certs in sq.rs
    pub sender_file: Vec<String>,
    #[clap(
        long = "signer-cert",
        value_name = "FINGERPRINT|KEYID",
        help = "Verifies signatures using the specified certificate",
        long_help = "\
Verifies signatures using the specified certificate.  This reads the
certificate from the certificate store, and considers it to be
authenticated.  When this option is not provided, the certificate is
still read from the certificate store, if it exists, but it is not
considered authenticated."
    )]
    pub sender_certs: Vec<KeyHandle>,
}

