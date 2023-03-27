use anyhow::Error;

use openpgp::packet::UserID;
use openpgp::Fingerprint;
use openpgp::KeyHandle;
use openpgp::Result;
use sequoia_openpgp as openpgp;

use sequoia_wot as wot;
use wot::Path;
use wot::PathLints;
use wot::FULLY_TRUSTED;
use wot::PARTIALLY_TRUSTED;

use crate::error_chain;
use crate::commands::wot::output::OutputType;

/// Prints a Path Error
pub fn print_path_error(err: Error) {
    println!("└   Checking path: {}", err);
}

/// Prints information of a Path for a target UserID associated with a KeyHandle
pub fn print_path_header(
    target_kh: &KeyHandle,
    target_userid: &UserID,
    amount: usize,
    required_amount: usize,
) {
    println!(
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
pub fn print_path(path: &PathLints, target_userid: &UserID, prefix: &str) {
    let certification_count = path.certifications().count();

    print!("{}◯ {}", prefix, path.root().key_handle());
    if certification_count == 0 {
        print!(" {:?}", String::from_utf8_lossy(target_userid.value()));
    } else if let Some(userid) = path.root().primary_userid() {
        print!(" ({:?})", String::from_utf8_lossy(userid.value()));
    }
    println!("");

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
        print!("{}│  ", prefix);
        if let Some(certification) = certification.certification() {
            if certification.amount() < FULLY_TRUSTED {
                print!(
                    " partially certified (amount: {} of 120)",
                    certification.amount()
                );
            } else {
                print!(" certified");
            }

            if last {
                print!(" the following binding");
            } else {
                print!(" the following certificate");
            }

            print!(
                " on {}",
                chrono::DateTime::<chrono::Utc>::from(
                    certification.creation_time()
                )
                .format("%Y-%m-%d")
            );
            if let Some(e) = certification.expiration_time() {
                print!(
                    " (expiry: {})",
                    chrono::DateTime::<chrono::Utc>::from(e).format("%Y-%m-%d")
                );
            }
            if certification.depth() > 0.into() {
                print!(" as a");
                if certification.amount() != FULLY_TRUSTED {
                    print!(
                        " partially trusted ({} of 120)",
                        certification.amount()
                    );
                } else {
                    print!(" fully trusted");
                }
                if certification.depth() == 1.into() {
                    print!(" introducer (depth: {})", certification.depth());
                } else {
                    print!(
                        " meta-introducer (depth: {})",
                        certification.depth()
                    );
                }
            }
        } else {
            print!(" No adequate certification found.");
        }
        println!("");

        for err in cert.errors().iter().chain(cert.lints()) {
            for (i, msg) in error_chain(err).into_iter().enumerate() {
                println!(
                    "{}│   {}{}",
                    prefix,
                    if i == 0 { "" } else { "  " },
                    msg
                );
            }
        }
        for err in certification.errors().iter().chain(certification.lints()) {
            for (i, msg) in error_chain(err).into_iter().enumerate() {
                println!(
                    "{}│   {}{}",
                    prefix,
                    if i == 0 { "" } else { "  " },
                    msg
                );
            }
        }

        print!(
            "{}{} {}",
            prefix,
            if last { "└" } else { "├" },
            certification.target()
        );

        if last {
            print!(" {:?}", String::from_utf8_lossy(target_userid.value()));
        } else {
            if let Some(userid) =
                certification.target_cert().and_then(|c| c.primary_userid())
            {
                print!(" ({:?})", String::from_utf8_lossy(userid.value()));
            }
        }
        println!("");

        if last {
            let target = path.certs().last().expect("have one");
            for err in target.errors().iter().chain(target.lints()) {
                for (i, msg) in error_chain(err).into_iter().enumerate() {
                    println!(
                        "{}    {}{}",
                        prefix,
                        if i == 0 { "" } else { "  " },
                        msg
                    );
                }
            }
        }
    }

    println!("");
}

/// The human-readable specific implementation of an OutputNetwork
///
/// HumanReadableOutputNetwork tracks the target trust amount for the network
/// and whether it displays "gossip".
pub struct HumanReadableOutputNetwork {
    gossip: bool,
    required_amount: usize,
}

impl HumanReadableOutputNetwork {
    /// Create a new HumanReadableOutputNetwork
    pub fn new(required_amount: usize, gossip: bool) -> Self {
        Self {
            required_amount,
            gossip,
        }
    }
}

impl OutputType for HumanReadableOutputNetwork {
    /// Add paths to the OutputNetwork and display them directly
    fn add_paths(
        &mut self,
        paths: Vec<(Path, usize)>,
        fingerprint: &Fingerprint,
        userid: &UserID,
        aggregated_amount: usize,
    ) -> Result<()> {
        let kh = KeyHandle::from(fingerprint);
        if !self.gossip {
            print_path_header(
                &kh,
                userid,
                aggregated_amount,
                self.required_amount,
            );
        }
        for (i, (path, amount)) in paths.iter().enumerate() {
            let prefix = if self.gossip {
                print_path_header(
                    &kh,
                    userid,
                    aggregated_amount,
                    self.required_amount,
                );
                "  "
            } else {
                if !self.gossip && paths.len() > 1 {
                    println!(
                        "  Path #{} of {}, trust amount {}:",
                        i + 1,
                        paths.len(),
                        amount
                    );
                    "    "
                } else {
                    "  "
                }
            };

            print_path(&path.into(), userid, prefix)
        }
        Ok(())
    }

    /// Write the HumanReadableOutputNetwork to output
    ///
    /// This function does in fact nothing as we are printing directly in
    /// add_paths().
    fn finalize(&mut self) -> Result<()> {
        Ok(())
    }
}
