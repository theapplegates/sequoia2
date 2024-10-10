use anyhow::Result;

use openpgp::packet::UserID;
use openpgp::policy::NullPolicy;
use sequoia_openpgp as openpgp;

use sequoia_wot as wot;

use crate::output::sanitize::Safe;

pub mod file;

mod revoke;
pub use revoke::get_secret_signer;
pub use revoke::RevocationOutput;

pub mod key;

pub mod password;
pub mod pki;
pub mod userid;

pub const NULL_POLICY: &NullPolicy = &NullPolicy::new();

/// Something like a User ID.
///
/// This is used to avoid unnecessary allocations.
enum UserIDLike {
    UserID(UserID),
    String(String),
    Unknown,
}

/// The preferred user ID for a certificate.
///
/// This can be smartly truncated using the precision formatting
/// parameter, e.g.:
///
/// ```text
/// format!("{:.70}", userid);
/// ```
pub struct PreferredUserID {
    userid: UserIDLike,
    trust_amount: usize,
}

impl std::fmt::Display for PreferredUserID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>)
        -> Result<(), std::fmt::Error>
    {
        let userid_;
        let userid = match self.userid {
            UserIDLike::Unknown => {
                return write!(f, "<unknown>");
            }
            UserIDLike::UserID(ref userid) => {
                userid_ = String::from_utf8_lossy(userid.value());
                &userid_[..]
            }
            UserIDLike::String(ref userid) => {
                &userid[..]
            }
        };

        let userid = Safe(userid).to_string();

        let suffix_;
        let suffix = if self.trust_amount == 0 {
            "(UNAUTHENTICATED)"
        } else if self.trust_amount < wot::FULLY_TRUSTED {
            suffix_ = format!("(partially authenticated, {}/{})",
                              self.trust_amount, wot::FULLY_TRUSTED);
            &suffix_[..]
        } else {
            "(authenticated)"
        };

        // We always keep the suffix and at least 16 characters of the user ID.
        const MIN_USERID: usize = 16;

        if let Some(width) = f.precision() {
            let space_for_userid = width.saturating_sub(1 + suffix.len()).max(MIN_USERID);
            if userid.chars().count() > space_for_userid {
                return write!(f, "{}… {}",
                              userid.chars().take(MIN_USERID).collect::<String>(),
                              suffix);
            }
        }

        write!(f, "{} {}", userid, suffix)
    }
}

impl PreferredUserID {
    /// Returns a new `PreferredUserID`.
    pub fn from_userid<U>(userid: U, trust_amount: usize) -> Self
    where U: Into<UserID>
    {
        Self {
            userid: UserIDLike::UserID(userid.into()),
            trust_amount,
        }
    }

    /// Returns a new `PreferredUserID`.
    pub fn from_string<S>(userid: S, trust_amount: usize) -> Self
    where S: Into<String>
    {
        Self {
            userid: UserIDLike::String(userid.into()),
            trust_amount,
        }
    }

    /// Returns a new "unknown" `PreferredUserID`.
    pub fn unknown() -> Self {
        Self {
            userid: UserIDLike::Unknown,
            trust_amount: 0,
        }
    }

    /// Returns the trust amount.
    pub fn trust_amount(&self) -> usize {
        self.trust_amount
    }
}
