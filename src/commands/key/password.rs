//! Changes a key's password.

use crate::Sq;
use crate::cli;
use crate::common::key::password;
use crate::Result;

pub fn dispatch(sq: Sq, command: cli::key::PasswordCommand)
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

    password::password(sq, handle,
                       command.clear_password,
                       command.new_password_file.as_deref(),
                       command.output, command.binary)
}
