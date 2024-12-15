//! Collection of functions to provide a unified user experience.

use anyhow::Result;

use sequoia_openpgp::{
    self as openpgp,
    packet::UserID,
};

use crate::{
    Sq,
};

pub use crate::output::sanitize::Safe;

/// Emits a certificate header.
pub fn emit_cert(o: &mut dyn std::io::Write, sq: &Sq, cert: &openpgp::Cert)
                 -> Result<()>
{
    emit_cert_userid_str(o, cert, &sq.best_userid(cert, true).to_string())
}

/// Emits a certificate header.
pub fn emit_cert_userid(o: &mut dyn std::io::Write,
                        cert: &openpgp::Cert,
                        userid: &UserID)
                        -> Result<()>
{
    emit_cert_userid_str(o, cert, &String::from_utf8_lossy(userid.value()))
}

/// Emits a certificate header.
pub fn emit_cert_userid_str(o: &mut dyn std::io::Write,
                            cert: &openpgp::Cert,
                            userid: &str)
                            -> Result<()>
{
    wwriteln!(stream = o,
              initial_indent = " - ┌ ", subsequent_indent = "   │ ",
              "{}", cert.fingerprint());
    wwriteln!(stream = o,
              initial_indent = "   └ ",
              "{}", Safe(userid));
    Ok(())
}
