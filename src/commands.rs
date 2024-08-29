use std::collections::{HashMap, HashSet, btree_map::{BTreeMap, Entry}};
use std::time::SystemTime;

use sequoia_openpgp as openpgp;
use openpgp::cert::prelude::*;
use openpgp::{Cert, Fingerprint, KeyID, Result};
use openpgp::packet::prelude::*;
use openpgp::parse::stream::*;
use openpgp::policy::HashAlgoSecurity;
use openpgp::policy::Policy;
use openpgp::types::{
    AEADAlgorithm,
    SymmetricAlgorithm,
};

use sequoia_cert_store as cert_store;
use cert_store::Store;

use sequoia_wot::store::Store as _;

use crate::Sq;

use crate::cli::encrypt::CompressionMode;
use crate::cli::types::FileOrStdout;
use crate::cli::{SqCommand, SqSubcommands};

pub mod autocrypt;
pub mod cert;
pub mod decrypt;
pub mod encrypt;
pub mod sign;
pub mod inspect;
pub mod key;
pub mod network;
pub mod pki;
pub mod toolbox;
pub mod verify;
pub mod version;

/// Dispatches the top-level subcommand.
pub fn dispatch(sq: Sq, command: SqCommand) -> Result<()>
{
    match command.subcommand {
        SqSubcommands::Encrypt(command) =>
            encrypt::dispatch(sq, command),
        SqSubcommands::Decrypt(command) =>
            decrypt::dispatch(sq, command),
        SqSubcommands::Sign(command) =>
            sign::dispatch(sq, command),
        SqSubcommands::Verify(command) =>
            verify::dispatch(sq, command),

        SqSubcommands::Inspect(command) =>
            inspect::dispatch(sq, command),

        SqSubcommands::Cert(command) =>
            cert::dispatch(sq, command),
        SqSubcommands::Key(command) =>
            key::dispatch(sq, command),

        SqSubcommands::Pki(command) =>
            pki::dispatch(sq, command),

        SqSubcommands::Autocrypt(command) =>
            autocrypt::dispatch(sq, &command),
        SqSubcommands::Network(command) =>
            network::dispatch(sq, command),
        SqSubcommands::Toolbox(command) =>
            toolbox::dispatch(sq, command),

        SqSubcommands::Version(command) =>
            version::dispatch(sq, command),
    }
}

/// Returns the active certification, if any, for the specified bindings.
///
/// The certificate is looked up in the certificate store.
///
/// Note: if `n` User IDs are provided, then the returned vector has
/// `n` elements.
fn active_certification(sq: &Sq,
                        cert: &Fingerprint, userids: Vec<UserID>,
                        issuer: &Key<openpgp::packet::key::PublicParts,
                                     openpgp::packet::key::UnspecifiedRole>)
    -> Vec<(UserID, Option<Signature>)>
{
    // Look up the cert and find the certifications for the specified
    // User ID, if any.
    let lc = sq.cert_store_or_else()
        .and_then(|cert_store| cert_store.lookup_by_cert_fpr(cert));
    let lc = match lc {
        Ok(lc) => lc,
        Err(_) => {
            return userids.into_iter().map(|userid| (userid, None)).collect();
        }
    };
    let cert = match lc.to_cert() {
        Ok(cert) => cert,
        Err(_) => {
            return userids.into_iter().map(|userid| (userid, None)).collect();
        }
    };

    let issuer_kh = issuer.key_handle();

    userids.into_iter().map(|userid| {
        let ua = match cert.userids()
            .filter(|ua| ua.userid() == &userid).next()
        {
            Some(ua) => ua,
            None => return (userid, None),
        };

        // Get certifications that:
        //
        //  - Have a creation time,
        //  - Are not younger than the reference time,
        //  - Are not expired,
        //  - Alias the issuer, and
        //  - Satisfy the policy.
        let mut certifications = ua.bundle().certifications2()
            .filter(|sig| {
                if let Some(ct) = sig.signature_creation_time() {
                    ct <= sq.time
                        && sig.signature_validity_period()
                        .map(|vp| {
                            sq.time < ct + vp
                        })
                        .unwrap_or(true)
                        && sig.get_issuers().iter().any(|i| i.aliases(&issuer_kh))
                        && sq.policy.signature(
                            sig, HashAlgoSecurity::CollisionResistance).is_ok()
                } else {
                    false
                }
            })
            .collect::<Vec<&Signature>>();

        // Sort so the newest signature is first.
        certifications.sort_unstable_by(|a, b| {
            a.signature_creation_time().unwrap()
                .cmp(&b.signature_creation_time().unwrap())
                .reverse()
                .then(a.mpis().cmp(&b.mpis()))
        });

        // Return the first valid signature, which is the most recent one
        // that is no younger than sq.time.
        let pk = ua.cert().primary_key().key();
        let certification = certifications.into_iter()
            .filter_map(|sig| {
                let sig = sig.clone();
                if sig.verify_userid_binding(issuer, pk, &userid).is_ok() {
                    Some(sig)
                } else {
                    None
                }
            })
            .next();
        (userid, certification)
    }).collect()
}

// Returns the smallest valid certificate.
//
// Given a certificate, returns the smallest valid certificate that is
// still technically valid according to RFC 4880 and popular OpenPGP
// implementations.
//
// In particular, this function extracts the primary key, and a User
// ID with its active binding signature.  If there is no valid User
// ID, it returns the active direct key signature.  If no User ID is
// specified, or the specified User ID does not occur, then the
// primary User ID is used and the specified User ID is added without
// a binding signature.
#[allow(dead_code)]
pub fn cert_stub(cert: Cert,
                 policy: &dyn Policy,
                 timestamp: Option<SystemTime>,
                 userid: Option<&UserID>)
    -> Result<Cert>
{
    let vc = cert.with_policy(policy, timestamp)?;

    let mut packets = Vec::with_capacity(4);
    packets.push(Packet::from(vc.primary_key().key().clone()));

    let mut found = false;
    if let Some(userid) = userid {
        for u in vc.userids() {
            if u.userid() == userid {
                found = true;
                packets.push(Packet::from(userid.clone()));
                packets.push(Packet::from(u.binding_signature().clone()));
            }
        }
    }
    if ! found {
        // We didn't find the required User ID or no User ID was
        // specified.  Emit the primary User ID.  If there is none,
        // emit the direct key signature.
        if let Ok(uid) = vc.primary_userid() {
            packets.push(Packet::from(uid.userid().clone()));
            packets.push(Packet::from(uid.binding_signature().clone()));
        } else {
            packets.push(
                Packet::from(vc.primary_key().binding_signature().clone()));
        }

        // And include the specified User ID as the very last packet.
        // This is convenient when we append a revocation certificate
        // as the revocation certificate is at the right place.
        if let Some(userid) = userid {
            packets.push(Packet::from(userid.clone()));
        }
    }

    Ok(Cert::from_packets(packets.into_iter())?)
}

pub struct VHelper<'c, 'store, 'rstore>
    where 'store: 'rstore
{
    #[allow(dead_code)]
    sq: &'c Sq<'store, 'rstore>,
    signatures: usize,
    certs: Option<Vec<Cert>>,
    labels: HashMap<KeyID, String>,
    trusted: HashSet<KeyID>,

    /// Tracks the inner-most encryption container encountered.
    sym_algo: Option<SymmetricAlgorithm>,
    /// Tracks the inner-most encryption container encountered.
    aead_algo: Option<AEADAlgorithm>,

    // Tracks the signatures encountered.
    good_signatures: usize,
    good_checksums: usize,
    unknown_checksums: usize,
    bad_signatures: usize,
    bad_checksums: usize,
    broken_signatures: usize,
    quiet: bool,
}

impl<'c, 'store, 'rstore> VHelper<'c, 'store, 'rstore> {
    fn new(sq: &'c Sq<'store, 'rstore>, signatures: usize,
           certs: Vec<Cert>)
           -> Self {
        VHelper {
            sq: sq,
            signatures,
            certs: Some(certs),
            labels: HashMap::new(),
            trusted: HashSet::new(),
            sym_algo: None,
            aead_algo: None,
            good_signatures: 0,
            good_checksums: 0,
            unknown_checksums: 0,
            bad_signatures: 0,
            bad_checksums: 0,
            broken_signatures: 0,
            quiet: false,
        }
    }

    /// Enables or disables quiet operation.
    ///
    /// In quiet operation, only errors are emitted.
    pub fn quiet(&mut self, v: bool) {
        self.quiet = v;
    }

    fn print_status(&self) {
        fn p(s: &mut String, what: &str, quantity: usize) {
            if quantity > 0 {
                use std::fmt::Write;
                use crate::output::pluralize::Pluralize;
                let dirty = ! s.is_empty();
                write!(s, "{}{}",
                       if dirty { ", " } else { "" },
                       quantity.of(what))
                    .expect("writing to a string is infallible");
            }
        }

        let mut status = String::new();
        p(&mut status, "good signature", self.good_signatures);
        p(&mut status, "unauthenticated checksum", self.good_checksums);
        p(&mut status, "unknown checksum", self.unknown_checksums);
        p(&mut status, "bad signature", self.bad_signatures);
        p(&mut status, "bad checksum", self.bad_checksums);
        p(&mut status, "broken signatures", self.broken_signatures);
        if ! status.is_empty() {
            wprintln!("{}.", status);
        }
    }

    fn print_sigs(&mut self, results: &[VerificationResult]) {
        make_qprintln!(self.quiet);
        use crate::commands::pki::output::print_path;
        use crate::print_error_chain;

        let reference_time = self.sq.time;

        use self::VerificationError::*;
        for result in results {
            let (sig, ka) = match result {
                Ok(GoodChecksum { sig, ka, .. }) => (sig, ka),
                Err(MalformedSignature { error, .. }) => {
                    wprintln!("Malformed signature:");
                    print_error_chain(error);
                    self.broken_signatures += 1;
                    continue;
                },
                Err(MissingKey { sig, .. }) => {
                    let issuer = sig.get_issuers().get(0)
                        .expect("missing key checksum has an issuer")
                        .to_string();
                    let what = match sig.level() {
                        0 => "checksum".into(),
                        n => format!("level {} notarizing checksum", n),
                    };
                    wprintln!("No cert to check {} from {}", what, issuer);
                    wprintln!("Consider running `sq network fetch {}`.", issuer);
                    self.unknown_checksums += 1;
                    continue;
                },
                Err(UnboundKey { cert, error, .. }) => {
                    wprintln!("Signing key on {} is not bound:",
                              cert.fingerprint());
                    print_error_chain(error);
                    self.bad_checksums += 1;
                    continue;
                },
                Err(BadKey { ka, error, .. }) => {
                    wprintln!("Signing key on {} is bad:",
                              ka.cert().fingerprint());
                    print_error_chain(error);
                    self.bad_checksums += 1;
                    continue;
                },
                Err(BadSignature { sig, ka, error }) => {
                    let issuer = ka.fingerprint().to_string();
                    let what = match sig.level() {
                        0 => "checksum".into(),
                        n => format!("level {} notarizing checksum", n),
                    };
                    wprintln!("Error verifying {} from {}:",
                              what, issuer);
                    print_error_chain(error);
                    self.bad_checksums += 1;
                    continue;
                }
            };

            let cert = ka.cert();
            let cert_fpr = cert.fingerprint();
            let issuer = ka.key().keyid();
            let mut signer_userid = ka.cert().primary_userid()
                .map(|ua| String::from_utf8_lossy(ua.value()).to_string())
                .unwrap_or_else(|_| "<unknown>".to_string());

            // Direct trust.
            let mut trusted = self.trusted.contains(&issuer);
            let mut prefix = "";
            let trust_roots = self.sq.trust_roots();
            if ! trusted && ! trust_roots.is_empty() {
                prefix = "  ";

                // Web of trust.
                qprintln!("Authenticating {} ({:?}) using the web of trust:",
                          cert_fpr, signer_userid);

                if let Ok(Some(cert_store)) = self.sq.cert_store() {
                    // Build the network.
                    let cert_store = sequoia_wot::store::CertStore::from_store(
                        cert_store, self.sq.policy, reference_time);

                    let userids = if let Some(userid) = sig.signers_user_id() {
                        let userid = UserID::from(userid);
                        wprintln!(indent=prefix,
                                  "Signature was made by {}",
                                  String::from_utf8_lossy(userid.value()));
                        vec![ userid ]
                    } else {
                        cert_store.certified_userids_of(&cert_fpr)
                    };

                    if userids.is_empty() {
                        wprintln!(indent=prefix,
                                  "{} cannot be authenticated.  \
                                   It has no User IDs",
                                  cert_fpr);
                    } else {
                        let n = sequoia_wot::NetworkBuilder::rooted(
                            &cert_store, &*trust_roots).build();

                        let authenticated_userids
                            = userids.into_iter().filter(|userid| {
                                let userid_str =
                                    String::from_utf8_lossy(userid.value());

                                let paths = n.authenticate(
                                    userid, cert.fingerprint(),
                                    // XXX: Make this user squrable.
                                    sequoia_wot::FULLY_TRUSTED);

                                let amount = paths.amount();
                                let authenticated = if amount >= sequoia_wot::FULLY_TRUSTED {
                                    wprintln!(indent=prefix,
                                              "Fully authenticated \
                                               ({} of {}) {}, {}",
                                              amount,
                                              sequoia_wot::FULLY_TRUSTED,
                                              cert_fpr,
                                              userid_str);
                                    true
                                } else if amount > 0 {
                                    wprintln!(indent=prefix,
                                              "Partially authenticated \
                                               ({} of {}) {}, {:?} ",
                                              amount,
                                              sequoia_wot::FULLY_TRUSTED,
                                              cert_fpr,
                                              userid_str);
                                    false
                                } else {
                                    wprintln!(indent=prefix,
                                              "{}: {:?} is unauthenticated \
                                               and may be an impersonation!",
                                              cert_fpr,
                                              userid_str);
                                    false
                                };

                                for (i, (path, amount)) in paths.iter().enumerate() {
                                    let prefix = if paths.len() > 1 {
                                        qprintln!("{}  Path #{} of {}, \
                                                  trust amount {}:",
                                                 prefix,
                                                 i + 1, paths.len(), amount);
                                        format!("{}    ", prefix)
                                    } else {
                                        format!("{}  ", prefix)
                                    };

                                    if ! self.quiet {
                                        let _ =
                                            print_path(&path.into(), userid,
                                                       &prefix);
                                    }
                                }

                                authenticated
                            })
                            .collect::<Vec<UserID>>();

                        if authenticated_userids.is_empty() {
                            trusted = false;
                        } else {
                            trusted = true;
                            signer_userid = String::from_utf8_lossy(
                                authenticated_userids[0].value()).to_string();
                        }
                    }
                } else {
                    qprintln!("Skipping, certificate store has been disabled");
                }
            }

            let issuer_str = issuer.to_string();
            let label = self.labels.get(&issuer).unwrap_or(&issuer_str);

            let level = sig.level();
            match (level == 0, trusted) {
                (true,  true)  => {
                    wprintln!(indent=prefix,
                              "Good signature from {} ({:?})",
                              label, signer_userid);
                }
                (false, true)  => {
                    wprintln!(indent=prefix,
                              "Good level {} notarization from {} ({:?})",
                              level, label, signer_userid);
                }
                (true,  false) => {
                    wprintln!(indent=prefix,
                              "Unauthenticated checksum from {} ({:?})",
                              label, signer_userid);
                    eprintln!();
                    wprintln!(indent=prefix,
                              "After checking that {} belongs to {:?}, \
                               you can authenticate the binding using:",
                              issuer_str, signer_userid);
                    eprintln!();
                    eprintln!("{}  $ sq pki link add {} {:?}",
                              prefix, issuer_str, signer_userid);
                }
                (false, false) => {
                    wprintln!(indent=prefix,
                              "Unauthenticated level {} notarizing \
                               checksum from {} ({:?})",
                              level, label, signer_userid);
                    eprintln!();
                    wprintln!(indent=prefix,
                              "After checking that {} belongs to {:?}, \
                               you can authenticate the binding using:",
                              issuer_str, signer_userid);
                    eprintln!();
                    eprintln!("{}  $ sq pki link add {} {:?}",
                              prefix, issuer_str, signer_userid);
                }
            };

            if trusted {
                self.good_signatures += 1;
            } else {
                self.good_checksums += 1;
            }

            qprintln!("");
        }
    }
}

impl<'c, 'store, 'rstore> VerificationHelper for VHelper<'c, 'store, 'rstore>
    where 'store: 'rstore
{
    fn get_certs(&mut self, ids: &[openpgp::KeyHandle]) -> Result<Vec<Cert>> {
        let mut certs = BTreeMap::new();

        for c in self.certs.take().unwrap() {
            match certs.entry(c.fingerprint()) {
                Entry::Vacant(e) => {
                    e.insert(c);
                },
                Entry::Occupied(mut e) => {
                    let merged = e.get().clone().merge_public(c)?;
                    e.insert(merged);
                },
            }
        }

        // Get all keys.
        let seen: HashSet<_> = certs.values()
            .flat_map(|cert| {
                cert.keys().map(|ka| ka.key().fingerprint().into())
            }).collect();

        // Explicitly provided keys are trusted.
        self.trusted = seen;

        // Look up the ids in the certificate store.

        // Avoid initializing the certificate store if we don't actually
        // need to.
        if ! ids.is_empty() {
            if let Ok(Some(cert_store)) = self.sq.cert_store() {
                for id in ids.iter() {
                    for c in cert_store.lookup_by_cert_or_subkey(id)
                        .unwrap_or_default()
                    {
                        let c = c.to_cert()?.clone();
                        match certs.entry(c.fingerprint()) {
                            Entry::Vacant(e) => {
                                e.insert(c);
                            },
                            Entry::Occupied(mut e) => {
                                let merged = e.get().clone().merge_public(c)?;
                                e.insert(merged);
                            },
                        }
                    }
                }
            }
        }

        Ok(certs.into_values().collect())
    }

    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        make_qprintln!(self.quiet);
        for layer in structure {
            match layer {
                MessageLayer::Compression { algo } =>
                    qprintln!("Compressed using {}", algo),
                MessageLayer::Encryption { sym_algo, aead_algo } => {
                    self.sym_algo = Some(sym_algo);
                    self.aead_algo = aead_algo;

                    if let Some(aead_algo) = aead_algo {
                        qprintln!("Encrypted and protected using {}/{}",
                                  sym_algo, aead_algo);
                    } else {
                        qprintln!("Encrypted using {}", sym_algo);
                    }
                },
                MessageLayer::SignatureGroup { ref results } =>
                    self.print_sigs(results),
            }
        }

        if self.good_signatures >= self.signatures
            && self.bad_signatures + self.bad_checksums == 0 {
            Ok(())
        } else {
            if ! self.quiet {
                self.print_status();
            }
            Err(anyhow::anyhow!("Verification failed: could not fully \
                                 authenticate any signatures"))
        }
    }
}
