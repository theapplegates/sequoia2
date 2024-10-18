use std::time::SystemTime;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Fingerprint;
use openpgp::Result;
use openpgp::cert::amalgamation::ValidAmalgamation;
use openpgp::packet::UserID;
use openpgp::types::RevocationStatus;

use sequoia_cert_store as cert_store;
use cert_store::Store;

use sequoia_wot as wot;
use wot::Path;

use crate::Sq;
use crate::commands::pki::output::OutputType;
use crate::Time;

/// The concise human-readable specific implementation of an
/// OutputNetwork
pub struct ConciseHumanReadableOutputNetwork<'a, 'store, 'rstore> {
    sq: &'a Sq<'store, 'rstore>,
    required_amount: usize,
    current_cert: Option<Cert>,
    bindings_shown: usize,
}

impl<'a, 'store, 'rstore> ConciseHumanReadableOutputNetwork<'a, 'store, 'rstore> {
    /// Creates a new ConciseHumanReadableOutputNetwork
    pub fn new(sq: &'a Sq<'store, 'rstore>,
               required_amount: usize)
        -> Self
    {
        Self {
            sq,
            required_amount,
            current_cert: None,
            bindings_shown: 0,
        }
    }
}

impl OutputType for ConciseHumanReadableOutputNetwork<'_, '_, '_> {
    fn add_paths(
        &mut self,
        _paths: Vec<(Path, usize)>,
        fingerprint: &Fingerprint,
        userid: &UserID,
        aggregated_amount: usize,
    ) -> Result<()> {
        let first_shown = self.current_cert.is_none();

        let current_fingerprint =
            self.current_cert.as_ref().map(|cert| cert.fingerprint());
        let show_cert = if current_fingerprint.as_ref() != Some(fingerprint) {
            let cert = if let Ok(store) = self.sq.cert_store_or_else() {
                store.lookup_by_cert_fpr(fingerprint)
                    .and_then(|lazy_cert| {
                        Ok(lazy_cert.to_cert()?.clone())
                    })
                    .ok()
            } else {
                None
            };
            self.current_cert = cert;
            true
        } else {
            false
        };

        let vc = self.current_cert.as_ref().and_then(|cert| {
            cert.with_policy(self.sq.policy, self.sq.time)
                .ok()
        });

        if show_cert {
            let expired = vc
                .as_ref()
                .map(|vc| {
                    if let Some(t) = vc.primary_key().key_expiration_time() {
                        if t < SystemTime::now() {
                            format!(" expired on {}",
                                    Time::try_from(t)
                                    .expect("is an OpenPGP timestamp"))
                        } else {
                            format!(" will expire on {}",
                                    Time::try_from(t)
                                    .expect("is an OpenPGP timestamp"))
                        }
                    } else {
                        "".to_string()
                    }
                })
                .unwrap_or("".to_string());

            if ! first_shown {
                wprintln!();
            }

            wprintln!("{}{}", fingerprint, expired);
        }

        let revoked = vc
            .as_ref()
            .and_then(|vc| {
                vc.userids()
                    .filter_map(|u| {
                        if u.userid() != userid {
                            return None;
                        }

                        if let RevocationStatus::Revoked(_) = u.revocation_status() {
                            Some(())
                        } else {
                            None
                        }
                    })
                    .next()
            });

        wprintln!(initial_indent = "  ", "[ {} ] {}",
                  if revoked.is_some() {
                      "revoked".to_string()
                  } else if aggregated_amount >= self.required_amount {
                      "   ✓   ".to_string()
                  } else {
                      format!("{:3}/120", aggregated_amount)
                  },
                  String::from_utf8_lossy(userid.value()));

        self.bindings_shown += 1;

        Ok(())
    }

    /// Write the HumanReadableOutputNetwork to output
    ///
    /// This function does in fact nothing as we are printing directly in
    /// add_paths().
    fn finalize(&mut self) -> Result<()> {
        if self.bindings_shown == 0 {
            return Ok(());
        }

        let cert =
            self.current_cert.as_ref().expect("have at least one");

        self.sq.hint(format_args!(
            "To view why a user ID is considered valid, pass \
             `--show-paths`.\n\
             \n\
             To see more details about a certificate, for example {}, run:",
            cert.fingerprint()))
            .sq().arg("inspect")
            .arg_value("--cert", cert.fingerprint())
            .done();

        Ok(())
    }
}
