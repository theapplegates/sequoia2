//! Detailed version and output version information.

use crate::{
    Sq,
    Result,
    cli::version,
    output,
};

pub fn dispatch(_sq: Sq, c: version::Command)
    -> Result<()>
{
    if c.default_output_version {
        wprintln!("{}", output::DEFAULT_OUTPUT_VERSION);
    } else if c.output_versions {
        for v in output::OUTPUT_VERSIONS {
            wprintln!("{}", v);
        }
    } else {
        wprintln!("sq {}", env!("CARGO_PKG_VERSION"));
        wprintln!("using sequoia-openpgp {}", sequoia_openpgp::VERSION);
        wprintln!("with cryptographic backend {}",
                  sequoia_openpgp::crypto::backend());
    }

    Ok(())
}
