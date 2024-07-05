//! Changes key expiration.

use crate::Sq;
use crate::cli;
use crate::common::key::delete;
use crate::Result;

pub fn dispatch(sq: Sq, command: cli::key::DeleteCommand)
                -> Result<()>
{
    let handle = if let Some(file) = command.cert_file {
        assert!(command.cert.is_none());
        file.into()
    } else if let Some(kh) = command.cert {
        kh.into()
    } else {
        panic!("clap enforces --cert or --cert-file is set");
    };

    delete::delete(sq, handle, Vec::new(), command.output, command.binary)
}
