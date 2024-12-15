//! Safely displays various data types from untrusted sources.

use std::fmt;

use sequoia_openpgp::{
    packet::UserID,
};

/// Safely displays values.
///
/// This type MUST be used to display attacker controlled strings,
/// such as user IDs, notation data, and reasons for revocations.
pub struct Safe<T>(pub T);

impl fmt::Display for Safe<&UserID> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = String::from_utf8_lossy(self.0.value());
        write!(f, "{}", Safe(s.as_ref()))
    }
}

impl fmt::Display for Safe<&str> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // XXX: Better detect dodgy strings and better sanitize them.
        // I bet there is a crate for that.  For now, this is better
        // than the status quo, and it encodes intent.
        if self.0.chars().any(char::is_control) {
            write!(f, "{:?}", self.0)
        } else {
            write!(f, "{}", self.0)
        }
    }
}

impl fmt::Display for Safe<&[u8]> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Safe(String::from_utf8_lossy(&self.0[..])).fmt(f)
    }
}

impl fmt::Display for Safe<std::borrow::Cow<'_, str>> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Safe(&self.0[..]).fmt(f)
    }
}

impl fmt::Display for Safe<&String> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Safe(&self.0[..]).fmt(f)
    }
}

impl fmt::Display for Safe<String> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Safe(&self.0[..]).fmt(f)
    }
}
