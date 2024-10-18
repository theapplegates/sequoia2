use std::{
    fmt::Write,
    time::SystemTime,
};

use anyhow::Error;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Fingerprint;
use openpgp::KeyHandle;
use openpgp::Result;
use openpgp::cert::amalgamation::ValidAmalgamation;
use openpgp::packet::UserID;
use openpgp::types::RevocationStatus;

use sequoia_cert_store as cert_store;
use cert_store::Store;

use sequoia_wot as wot;
use wot::Path;
use wot::PathLints;
use wot::FULLY_TRUSTED;
use wot::PARTIALLY_TRUSTED;

use crate::Convert;
use crate::Sq;
use crate::commands::pki::output::OutputType;
use crate::output::wrapping::NBSP;
use crate::Time;
use crate::error_chain;

/// Prints a Path Error
pub fn print_path_error(err: Error) {
    wprintln!(initial_indent = "└   ", "Checking path: {}", err);
}

/// Prints information of a Path for a target UserID associated with a KeyHandle
pub fn print_path_header(
    target_kh: &KeyHandle,
    target_userid: &UserID,
    amount: usize,
    required_amount: usize,
) {
    wprintln!(
        initial_indent="",
        subsequent_indent="    ",
        "[{}] {} {}: {} authenticated ({}%)",
        if amount >= required_amount {
            "✓"
        } else {
            " "
        },
        target_kh,
        String::from_utf8_lossy(target_userid.value()),
        if amount >= 2 * FULLY_TRUSTED {
            "doubly"
        } else if amount >= FULLY_TRUSTED {
            "fully"
        } else if amount >= PARTIALLY_TRUSTED {
            "partially"
        } else if amount > 0 {
            "marginally"
        } else {
            "not"
        },
        (amount * 100) / FULLY_TRUSTED
    );
}

/// Prints information on a Path for a UserID
pub fn print_path(path: &PathLints, target_userid: &UserID, prefix: &str)
                  -> Result<()>
{
    let certification_count = path.certifications().count();
    wprintln!(indent=prefix,
              "◯ {}{}",
              path.root().key_handle(),
              if certification_count == 0 {
                  format!(" {:?}", String::from_utf8_lossy(target_userid.value()))
              } else if let Some(userid) = path.root().primary_userid() {
                  format!(" ({:?})", String::from_utf8_lossy(userid.value()))
              } else {
                  format!("")
              });

    for (last, (cert, certification)) in path
        .certs()
        .zip(path.certifications())
        .enumerate()
        .map(|(j, c)| {
            if j + 1 == certification_count {
                (true, c)
            } else {
                (false, c)
            }
        })
    {
        let mut line = String::new();
        if let Some(certification) = certification.certification() {
            if certification.amount() < FULLY_TRUSTED {
                write!(&mut line,
                   "partially certified (amount: {}{}of{}120)",
                    certification.amount(), NBSP, NBSP,
                )?;
            } else {
                write!(&mut line, "certified")?;
            }

            if last {
                write!(&mut line, " the following binding")?;
            } else {
                write!(&mut line, " the following certificate")?;
            }

            write!(&mut line,
                " on {}",
                chrono::DateTime::<chrono::Utc>::from(
                    certification.creation_time()
                )
                .format("%Y-%m-%d")
            )?;
            if let Some(e) = certification.expiration_time() {
                write!(&mut line,
                    " (expiry: {})",
                    chrono::DateTime::<chrono::Utc>::from(e).format("%Y-%m-%d")
                )?;
            }
            if certification.depth() > 0.into() {
                write!(&mut line, " as a")?;
                if certification.amount() != FULLY_TRUSTED {
                    write!(&mut line,
                        " partially trusted ({}{}of{}120)",
                        certification.amount(), NBSP, NBSP,
                    )?;
                } else {
                    write!(&mut line, " fully trusted")?;
                }
                if certification.depth() == 1.into() {
                    write!(&mut line, " introducer (depth: {})",
                           certification.depth())?;
                } else {
                    write!(&mut line,
                        " meta-introducer (depth: {})",
                        certification.depth()
                    )?;
                }
            }
        } else {
            write!(&mut line, " No adequate certification found.")?;
        }

        wprintln!(indent=prefix, "│");
        wprintln!(indent=format!("{}│   ", prefix), "{}", line);
        wprintln!(indent=prefix, "│");

        for err in cert.errors().iter().chain(cert.lints()) {
            for (i, msg) in error_chain(err).into_iter().enumerate() {
                wprintln!(
                    indent=format!(
                        "{}│   {}", prefix, if i == 0 { "" } else { "  " }),
                    "{}", msg);
            }
        }
        for err in certification.errors().iter().chain(certification.lints()) {
            for (i, msg) in error_chain(err).into_iter().enumerate() {
                wprintln!(
                    indent=format!(
                        "{}│   {}", prefix, if i == 0 { "" } else { "  " }),
                    "{}", msg);
            }
        }

        wprintln!(
            initial_indent=format!("{}{} ", prefix,
                                   if last { "└" } else { "├" }),
            subsequent_indent=format!("{}{} ", prefix,
                                   if last { " " } else { "│" }),
            "{}{}",
            certification.target(),
            if last {
                format!(" {:?}", String::from_utf8_lossy(target_userid.value()))
            } else if let Some(userid) =
                certification.target_cert().and_then(|c| c.primary_userid())
            {
                format!(" ({:?})", String::from_utf8_lossy(userid.value()))
            } else {
                "".into()
            }
        );

        if last {
            let target = path.certs().last().expect("have one");
            for err in target.errors().iter().chain(target.lints()) {
                for (i, msg) in error_chain(err).into_iter().enumerate() {
                    wprintln!(
                        indent=format!(
                            "{}│   {}", prefix, if i == 0 { "" } else { "  " }),
                        "{}", msg);
                }
            }
        }
    }

    wprintln!("");
    Ok(())
}

/// The concise human-readable specific implementation of an
/// OutputNetwork
pub struct ConciseHumanReadableOutputNetwork<'a, 'store, 'rstore> {
    sq: &'a Sq<'store, 'rstore>,
    paths: bool,
    gossip: bool,
    required_amount: usize,
    current_cert: Option<Cert>,
    bindings_shown: usize,
}

impl<'a, 'store, 'rstore> ConciseHumanReadableOutputNetwork<'a, 'store, 'rstore> {
    /// Creates a new ConciseHumanReadableOutputNetwork
    pub fn new(sq: &'a Sq<'store, 'rstore>,
               required_amount: usize, paths: bool, gossip: bool)
        -> Self
    {
        Self {
            sq,
            paths,
            gossip,
            required_amount,
            current_cert: None,
            bindings_shown: 0,
        }
    }
}

impl OutputType for ConciseHumanReadableOutputNetwork<'_, '_, '_> {
    fn add_paths(
        &mut self,
        paths: Vec<(Path, usize)>,
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
            let expiration_info = vc
                .as_ref()
                .and_then(|vc| {
                    if let Some(t) = vc.primary_key().key_expiration_time() {
                        if t < SystemTime::now() {
                            Some(format!("expired on {}",
                                         Time::try_from(t)
                                         .expect("is an OpenPGP timestamp")))
                        } else {
                            Some(format!("will expire on {}",
                                         Time::try_from(t)
                                         .expect("is an OpenPGP timestamp")))
                        }
                    } else {
                        None
                    }
                });

            if ! first_shown {
                wprintln!();
            }

            wprintln!(initial_indent = " - ", "{}", fingerprint);
            wprintln!(initial_indent = "   - ", "created {}",
                      self.current_cert.as_ref()
                      .expect("show_cert is true, there is a current cert")
                      .primary_key().key().creation_time().convert());
            if let Some(info) = expiration_info {
                wprintln!(initial_indent = "   - ", "{}", info);
            }
            wprintln!();
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

        wprintln!(initial_indent = "   - ", "[ {} ] {}",
                  if revoked.is_some() {
                      "revoked".to_string()
                  } else if aggregated_amount >= self.required_amount {
                      "   ✓   ".to_string()
                  } else {
                      format!("{:3}/120", aggregated_amount)
                  },
                  String::from_utf8_lossy(userid.value()));

        if self.paths {
            wprintln!();

            for (i, (path, amount)) in paths.iter()
                .filter(|(p, _)|
                        // Filter out self-signatures.
                        p.root().fingerprint() != p.target().fingerprint()
                        || p.len() != 2)
                .enumerate()
            {
                if !self.gossip && paths.len() > 1 {
                    wprintln!(
                        initial_indent="     ",
                        "Path #{}{}of{}{}, trust amount {}:",
                        i + 1, NBSP, NBSP,
                        paths.len(),
                        amount
                    );
                }

                print_path(&path.into(), userid, "     ")?;
            }
        }

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

        if ! self.paths {
            self.sq.hint(format_args!(
                "To view why a user ID is considered valid, pass \
                 `--show-paths`."));
        }

        self.sq.hint(format_args!(
            "To see more details about a certificate, for example {}, run:",
            cert.fingerprint()))
            .sq().arg("inspect")
            .arg_value("--cert", cert.fingerprint())
            .done();

        Ok(())
    }
}
