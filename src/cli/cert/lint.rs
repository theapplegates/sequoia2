//! Command-line parser for `sq cert lint`.

use clap::Args;

use crate::cli::types::ClapData;
use crate::cli::types::FileOrStdin;
use crate::cli::types::FileOrStdout;

/// Checks for and optionally repairs OpenPGP certificates that use
/// SHA-1.
#[derive(Debug, Args)]
#[clap(
    about = "Check certificates for issues",
    long_about = "Check certificates for issues

`sq cert lint` checks the supplied certificates for the following
SHA-1-related issues:

  - Whether a certificate revocation uses SHA-1.

  - Whether the current self signature for a non-revoked User ID uses
    SHA-1.

  - Whether the current subkey binding signature for a non-revoked,
    live subkey uses SHA-1.

  - Whether a primary key binding signature (\"backsig\") for a
    non-revoked, live subkey uses SHA-1.

Diagnostics are printed to stderr.  At the end, some statistics are
shown.  This is useful when examining a keyring.  If `--fix` is
specified and at least one issue could be fixed, the fixed
certificates are printed to stdout.

This tool does not currently support smart cards.  But, if only the
subkeys are on a smart card, this tool may still be able to partially
repair the certificate.  In particular, it will be able to fix any
issues with User ID self signatures and subkey binding signatures for
encryption-capable subkeys, but it will not be able to generate new
primary key binding signatures for any signing-capable subkeys.
",
    after_help =
"EXIT STATUS:

If `--fix` is not specified:
  2  if any issues were found,
  1  if not issues were found, but there were errors reading the input,
  0  if there were no issues.

If `--fix` is specified:
  3  if any issues could not be fixed,
  1  if not issues were found, but there were errors reading the input,
  0  if all issues were fixed or there were no issues.

EXAMPLES:

# To gather statistics, simply run:
$ sq cert lint keyring.pgp

# To fix a key:
$ gpg --export-secret-keys FPR \\
    | sq cert lint --fix -p passw0rd -p password123 \\
    | gpg --import

# To get a list of keys with issues:
$ sq cert lint --list-keys keyring.pgp \\
    | while read FPR; do something; done
"
)]
pub struct Command {
    /// Quiet; does not output any diagnostics.
    #[arg(short, long)]
    pub quiet: bool,

    /// Attempts to fix certificates, when possible.
    #[arg(short = 'F', long)]
    pub fix: bool,

    /// When fixing a certificate, the fixed certificate is exported
    /// without any secret key material.  Using this switch causes any
    /// secret key material to also be exported.
    #[arg(short, long)]
    pub export_secret_keys: bool,

    /// If set, outputs a list of fingerprints, one per line, of
    /// certificates that have issues.  This output is intended for
    /// use by scripts.
    ///
    /// This option implies `--quiet`. If you also specify `--fix`,
    /// errors will still be printed to stderr, and fixed certificates
    /// will still be emitted to stdout.
    #[arg(short='k', long)]
    pub list_keys: bool,

    #[clap(
        help = FileOrStdin::HELP_OPTIONAL,
        value_name = FileOrStdin::VALUE_NAME,
        required = true,
    )]
    pub inputs: Vec<FileOrStdin>,

    #[clap(
        default_value_t = FileOrStdout::default(),
        help = FileOrStdout::HELP_OPTIONAL,
        long,
        short,
        value_name = FileOrStdout::VALUE_NAME,
    )]
    pub output: FileOrStdout,
    #[clap(
        short = 'B',
        long = "binary",
        help = "Emit binary data",
    )]
    pub binary: bool,
}
