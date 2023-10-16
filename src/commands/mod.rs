use anyhow::Context as _;
use std::borrow::Borrow;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, Write};
use std::time::SystemTime;

use sequoia_net::pks;
use sequoia_openpgp as openpgp;
use openpgp::{
    armor,
};
use openpgp::types::{
    CompressionAlgorithm,
};
use openpgp::cert::prelude::*;
use openpgp::crypto::{self, Password};
use openpgp::{Cert, Fingerprint, KeyID, Result};
use openpgp::packet::prelude::*;
use openpgp::parse::{
    Parse,
    PacketParserResult,
};
use openpgp::parse::stream::*;
use openpgp::policy::HashAlgoSecurity;
use openpgp::serialize::stream::{
    Message, Signer, LiteralWriter, Encryptor, Recipient,
    Compressor,
    padding::Padder,
};
use openpgp::policy::Policy;
use openpgp::types::KeyFlags;
use openpgp::types::RevocationStatus;

use sequoia_cert_store as cert_store;
use cert_store::Store;

use sequoia_wot::store::Store as _;

use crate::sq_cli::types::FileOrStdout;
use crate::{
    Config,
};

use crate::sq_cli::encrypt::CompressionMode;
use crate::sq_cli::encrypt::EncryptionMode;
use crate::sq_cli::packet;

#[cfg(feature = "autocrypt")]
pub mod autocrypt;
pub mod decrypt;
pub mod sign;
pub use self::sign::sign;
pub mod dump;
pub use self::dump::dump;
mod inspect;
pub use self::inspect::inspect;
pub mod key;
pub mod merge_signatures;
pub use self::merge_signatures::merge_signatures;
pub mod keyring;
pub mod import;
pub mod export;
pub mod net;
pub mod certify;
pub mod link;
pub mod wot;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GetKeysOptions {
    AllowNotAlive,
    AllowRevoked,
}

enum KeyType {
    Primary,
    KeyFlags(KeyFlags),
}

/// Returns suitable signing keys from a given list of Certs.
fn get_keys<C>(certs: &[C], p: &dyn Policy,
               private_key_store: Option<&str>,
               timestamp: Option<SystemTime>,
               keytype: KeyType,
               options: Option<&[GetKeysOptions]>)
    -> Result<Vec<(Box<dyn crypto::Signer + Send + Sync>, Option<Password>)>>
    where C: Borrow<Cert>
{
    let mut bad = Vec::new();

    let options = options.unwrap_or(&[][..]);
    let allow_not_alive = options.contains(&GetKeysOptions::AllowNotAlive);
    let allow_revoked = options.contains(&GetKeysOptions::AllowRevoked);

    let mut keys: Vec<(Box<dyn crypto::Signer + Send + Sync>, Option<Password>)> = vec![];
    'next_cert: for tsk in certs {
        let tsk = tsk.borrow();
        let vc = match tsk.with_policy(p, timestamp) {
            Ok(vc) => vc,
            Err(err) => {
                return Err(
                    err.context(format!("Found no suitable key on {}", tsk)));
            }
        };

        let keyiter = match keytype {
            KeyType::Primary => {
                Box::new(
                    std::iter::once(
                        vc.keys()
                            .next()
                            .expect("a valid cert has a primary key")))
                    as Box<dyn Iterator<Item=ValidErasedKeyAmalgamation<openpgp::packet::key::PublicParts>>>
            },
            KeyType::KeyFlags(ref flags) => {
                Box::new(vc.keys().key_flags(flags.clone()))
                    as Box<dyn Iterator<Item=_>>
            },
        };
        for ka in keyiter {
            let bad_ = [
                ! allow_not_alive && matches!(ka.alive(), Err(_)),
                ! allow_revoked && matches!(ka.revocation_status(),
                                            RevocationStatus::Revoked(_)),
                ! ka.pk_algo().is_supported(),
            ];
            if bad_.iter().any(|x| *x) {
                bad.push((ka.fingerprint(), bad_));
                continue;
            }

            let key = ka.key();

            if let Some(secret) = key.optional_secret() {
                let (unencrypted, password) = match secret {
                    SecretKeyMaterial::Encrypted(ref e) => {
                        // try passwords from already existing keys
                        match keys.iter().find(|&(_, password)| {
                            password.is_some()
                                && e.decrypt(
                                    key.pk_algo(),
                                    password.as_ref().unwrap(),
                                )
                                .is_ok()
                        }) {
                            Some((_, password)) => (
                                e.decrypt(
                                    key.pk_algo(),
                                    password.as_ref().unwrap(),
                                )
                                .expect("decryption failed"),
                                Some(password.as_ref().unwrap().clone()),
                            ),
                            None => {
                                let password = Password::from(rpassword::prompt_password(
                                    &format!("Please enter password to decrypt {}/{}: ", tsk, key))
                                .context("Reading password from tty")?);
                                (
                                    e.decrypt(key.pk_algo(), &password)
                                        .expect("decryption failed"),
                                    Some(password),
                                )
                            }
                        }
                    }
                    SecretKeyMaterial::Unencrypted(ref u) => (u.clone(), None),
                };

                keys.push((
                    Box::new(
                        crypto::KeyPair::new(key.clone(), unencrypted).unwrap()
                    ),
                    password,
                ));
                continue 'next_cert;
            } else if let Some(private_key_store) = private_key_store {
                let input_password = rpassword::prompt_password(
                    &format!("Please enter password to key {}/{}: ", tsk, key)).unwrap().into();
                match pks::unlock_signer(private_key_store, key.clone(), &input_password) {
                    Ok(signer) => {
                        keys.push((signer, Some(input_password.clone())));
                        continue 'next_cert;
                    },
                    Err(error) => eprintln!("Could not unlock key: {:?}", error),
                }
            }
        }

        let timestamp = timestamp.map(|t| {
            chrono::DateTime::<chrono::offset::Utc>::from(t)
        });

        let mut context = Vec::new();
        for (fpr, [not_alive, revoked, not_supported]) in bad {
            let id: String = if fpr == tsk.fingerprint() {
                fpr.to_string()
            } else {
                format!("{}/{}", tsk.fingerprint(), fpr)
            };

            let preface = if let Some(t) = timestamp {
                format!("{} was not considered because\n\
                         at the specified time ({}) it was",
                        id, t)
            } else {
                format!("{} was not considered because\nit is", fpr)
            };

            let mut reasons = Vec::new();
            if not_alive {
                reasons.push("not alive");
            }
            if revoked {
                reasons.push("revoked");
            }
            if not_supported {
                reasons.push("not supported");
            }

            context.push(format!("{}: {}",
                                 preface, reasons.join(", ")));
        }

        if context.is_empty() {
            return Err(anyhow::anyhow!(
                format!("Found no suitable key on {}", tsk)));
        } else {
            let context = context.join("\n");
            return Err(
                anyhow::anyhow!(
                    format!("Found no suitable key on {}", tsk))
                    .context(context));
        }
    }

    Ok(keys)
}

/// Returns the primary keys from a given list of Certs.
///
/// This returns one key for each Cert.  If a Cert doesn't have an
/// appropriate key, then this returns an error.
fn get_primary_keys<C>(certs: &[C], p: &dyn Policy,
                       private_key_store: Option<&str>,
                       timestamp: Option<SystemTime>,
                       options: Option<&[GetKeysOptions]>)
    -> Result<Vec<(Box<dyn crypto::Signer + Send + Sync>, Option<Password>)>>
    where C: std::borrow::Borrow<Cert>
{
    get_keys(certs, p, private_key_store, timestamp,
             KeyType::Primary, options)
}

/// Returns suitable signing keys from a given list of Certs.
///
/// This returns one key for each Cert.  If a Cert doesn't have an
/// appropriate key, then this returns an error.
fn get_signing_keys<C>(certs: &[C], p: &dyn Policy,
                       private_key_store: Option<&str>,
                       timestamp: Option<SystemTime>,
                       options: Option<&[GetKeysOptions]>)
    -> Result<Vec<(Box<dyn crypto::Signer + Send + Sync>, Option<Password>)>>
    where C: Borrow<Cert>
{
    get_keys(certs, p, private_key_store, timestamp,
             KeyType::KeyFlags(KeyFlags::empty().set_signing()),
             options)
}

/// Returns suitable certification keys from a given list of Certs.
///
/// This returns one key for each Cert.  If a Cert doesn't have an
/// appropriate key, then this returns an error.
pub fn get_certification_keys<C>(certs: &[C], p: &dyn Policy,
                             private_key_store: Option<&str>,
                             timestamp: Option<SystemTime>,
                             options: Option<&[GetKeysOptions]>)
    -> Result<Vec<(Box<dyn crypto::Signer + Send + Sync>, Option<Password>)>>
    where C: std::borrow::Borrow<Cert>
{
    get_keys(certs, p, private_key_store, timestamp,
             KeyType::KeyFlags(KeyFlags::empty().set_certification()),
             options)
}

/// Returns the active certification, if any, for the specified bindings.
///
/// The certificate is looked up in the certificate store.
///
/// Note: if `n` User IDs are provided, then the returned vector has
/// `n` elements.
fn active_certification(config: &Config,
                        cert: &Fingerprint, userids: Vec<UserID>,
                        issuer: &Key<openpgp::packet::key::PublicParts,
                                     openpgp::packet::key::UnspecifiedRole>)
    -> Vec<(UserID, Option<Signature>)>
{
    // Look up the cert and find the certifications for the specified
    // User ID, if any.
    let lc = config.cert_store_or_else()
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
        let mut certifications = ua.bundle().certifications()
            .iter()
            .filter(|sig| {
                if let Some(ct) = sig.signature_creation_time() {
                    ct <= config.time
                        && sig.signature_validity_period()
                        .map(|vp| {
                            config.time < ct + vp
                        })
                        .unwrap_or(true)
                        && sig.get_issuers().iter().any(|i| i.aliases(&issuer_kh))
                        && config.policy.signature(
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
        // that is no younger than config.time.
        let pk = ua.cert().primary_key().key();
        let certification = certifications.into_iter()
            .filter_map(|sig| {
                let mut sig = sig.clone();
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

pub struct EncryptOpts<'a> {
    pub policy: &'a dyn Policy,
    pub private_key_store: Option<&'a str>,
    pub input: &'a mut dyn io::Read,
    pub message: Message<'a>,
    pub npasswords: usize,
    pub recipients: &'a [openpgp::Cert],
    pub signers: Vec<openpgp::Cert>,
    pub mode: EncryptionMode,
    pub compression: CompressionMode,
    pub time: Option<SystemTime>,
    pub use_expired_subkey: bool,
}

pub fn encrypt(opts: EncryptOpts) -> Result<()> {
    let mut passwords: Vec<crypto::Password> = Vec::with_capacity(opts.npasswords);
    for n in 0..opts.npasswords {
        let nprompt = format!("Enter password {}: ", n + 1);
        passwords.push(rpassword::prompt_password(
            if opts.npasswords > 1 {
                &nprompt
            } else {
                "Enter password: "
            })?.into());
    }

    if opts.recipients.len() + passwords.len() == 0 {
        return Err(anyhow::anyhow!(
            "Neither recipient nor password given"));
    }

    let mode = match opts.mode {
        EncryptionMode::Rest => {
            KeyFlags::empty().set_storage_encryption()
        }
        EncryptionMode::Transport => {
            KeyFlags::empty().set_transport_encryption()
        }
        EncryptionMode::All => KeyFlags::empty()
            .set_storage_encryption()
            .set_transport_encryption(),
    };

    let mut signers = get_signing_keys(
        &opts.signers, opts.policy, opts.private_key_store, opts.time, None)?;

    // Build a vector of recipients to hand to Encryptor.
    let mut recipient_subkeys: Vec<Recipient> = Vec::new();
    for cert in opts.recipients.iter() {
        let mut count = 0;
        for key in cert.keys().with_policy(opts.policy, opts.time).alive().revoked(false)
            .key_flags(&mode).supported().map(|ka| ka.key())
        {
            recipient_subkeys.push(key.into());
            count += 1;
        }
        if count == 0 {
            let mut expired_keys = Vec::new();
            for ka in cert.keys().with_policy(opts.policy, opts.time).revoked(false)
                .key_flags(&mode).supported()
            {
                let key = ka.key();
                expired_keys.push(
                    (ka.binding_signature().key_expiration_time(key)
                         .expect("Key must have an expiration time"),
                     key));
            }
            expired_keys.sort_by_key(|(expiration_time, _)| *expiration_time);

            if let Some((expiration_time, key)) = expired_keys.last() {
                if opts.use_expired_subkey {
                    recipient_subkeys.push((*key).into());
                } else {
                    use chrono::{DateTime, offset::Utc};
                    return Err(anyhow::anyhow!(
                        "The last suitable encryption key of cert {} expired \
                         on {}\n\
                         Hint: Use --use-expired-subkey to use it anyway.",
                        cert,
                        DateTime::<Utc>::from(*expiration_time)));
                }
            } else {
                return Err(anyhow::anyhow!(
                    "Cert {} has no suitable encryption key", cert));
            }
        }
    }

    // We want to encrypt a literal data packet.
    let encryptor =
        Encryptor::for_recipients(opts.message, recipient_subkeys)
        .add_passwords(passwords);

    let mut sink = encryptor.build()
        .context("Failed to create encryptor")?;

    match opts.compression {
        CompressionMode::None => (),
        CompressionMode::Pad => sink = Padder::new(sink).build()?,
        CompressionMode::Zip => sink =
            Compressor::new(sink).algo(CompressionAlgorithm::Zip).build()?,
        CompressionMode::Zlib => sink =
            Compressor::new(sink).algo(CompressionAlgorithm::Zlib).build()?,
        CompressionMode::Bzip2 => sink =
            Compressor::new(sink).algo(CompressionAlgorithm::BZip2).build()?,
    }

    // Optionally sign message.
    if ! signers.is_empty() {
        let mut signer = Signer::new(sink, signers.pop().unwrap().0);
        for s in signers {
            signer = signer.add_signer(s.0);
            if let Some(time) = opts.time {
                signer = signer.creation_time(time);
            }
        }
        for r in opts.recipients.iter() {
            signer = signer.add_intended_recipient(r);
        }
        sink = signer.build()?;
    }

    let mut literal_writer = LiteralWriter::new(sink).build()
        .context("Failed to create literal writer")?;

    // Finally, copy stdin to our writer stack to encrypt the data.
    io::copy(opts.input, &mut literal_writer)
        .context("Failed to encrypt")?;

    literal_writer.finalize()
        .context("Failed to encrypt")?;

    Ok(())
}

struct VHelper<'a, 'store> {
    #[allow(dead_code)]
    config: &'a Config<'store>,
    signatures: usize,
    certs: Option<Vec<Cert>>,
    labels: HashMap<KeyID, String>,
    trusted: HashSet<KeyID>,
    good_signatures: usize,
    good_checksums: usize,
    unknown_checksums: usize,
    bad_signatures: usize,
    bad_checksums: usize,
    broken_signatures: usize,
}

impl<'a, 'store> VHelper<'a, 'store> {
    fn new(config: &'a Config<'store>, signatures: usize,
           certs: Vec<Cert>)
           -> Self {
        VHelper {
            config: config,
            signatures,
            certs: Some(certs),
            labels: HashMap::new(),
            trusted: HashSet::new(),
            good_signatures: 0,
            good_checksums: 0,
            unknown_checksums: 0,
            bad_signatures: 0,
            bad_checksums: 0,
            broken_signatures: 0,
        }
    }

    fn print_status(&self) {
        fn p(dirty: &mut bool, what: &str, quantity: usize) {
            if quantity > 0 {
                eprint!("{}{} {}{}",
                        if *dirty { ", " } else { "" },
                        quantity, what,
                        if quantity == 1 { "" } else { "s" });
                *dirty = true;
            }
        }

        let mut dirty = false;
        p(&mut dirty, "good signature", self.good_signatures);
        p(&mut dirty, "unauthenticated checksum", self.good_checksums);
        p(&mut dirty, "unknown checksum", self.unknown_checksums);
        p(&mut dirty, "bad signature", self.bad_signatures);
        p(&mut dirty, "bad checksum", self.bad_checksums);
        p(&mut dirty, "broken signatures", self.broken_signatures);
        if dirty {
            eprintln!(".");
        }
    }

    fn print_sigs(&mut self, results: &[VerificationResult]) {
        use crate::commands::wot::output::print_path;
        use crate::print_error_chain;

        let reference_time = self.config.time;

        use self::VerificationError::*;
        for result in results {
            let (sig, ka) = match result {
                Ok(GoodChecksum { sig, ka, .. }) => (sig, ka),
                Err(MalformedSignature { error, .. }) => {
                    eprintln!("Malformed signature:");
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
                    eprintln!("No key to check {} from {}", what, issuer);
                    self.unknown_checksums += 1;
                    continue;
                },
                Err(UnboundKey { cert, error, .. }) => {
                    eprintln!("Signing key on {} is not bound:",
                              cert.fingerprint());
                    print_error_chain(error);
                    self.bad_checksums += 1;
                    continue;
                },
                Err(BadKey { ka, error, .. }) => {
                    eprintln!("Signing key on {} is bad:",
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
                    eprintln!("Error verifying {} from {}:",
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
            let trust_roots = self.config.trust_roots();
            if ! trusted && ! trust_roots.is_empty() {
                prefix = "  ";

                // Web of trust.
                eprintln!("Authenticating {} ({:?}) using the web of trust:",
                          cert_fpr, signer_userid);

                if let Ok(Some(cert_store)) = self.config.cert_store() {
                    // Build the network.
                    let cert_store = sequoia_wot::store::CertStore::from_store(
                        cert_store, &self.config.policy, reference_time);

                    let userids = if let Some(userid) = sig.signers_user_id() {
                        let userid = UserID::from(userid);
                        eprintln!("{}Signature was made by {}",
                                  prefix,
                                  String::from_utf8_lossy(userid.value()));
                        vec![ userid ]
                    } else {
                        cert_store.certified_userids_of(&cert_fpr)
                    };

                    if userids.is_empty() {
                        eprintln!("{}{} cannot be authenticated.  \
                                   It has no User IDs",
                                  prefix, cert_fpr);
                    } else if let Ok(n) = sequoia_wot::Network::new(&cert_store) {
                        let mut q = sequoia_wot::QueryBuilder::new(&n);
                        q.roots(sequoia_wot::Roots::new(trust_roots.into_iter()));
                        let q = q.build();

                        let authenticated_userids
                            = userids.into_iter().filter(|userid| {
                                let userid_str =
                                    String::from_utf8_lossy(userid.value());

                                let paths = q.authenticate(
                                    userid, cert.fingerprint(),
                                    // XXX: Make this user configurable.
                                    sequoia_wot::FULLY_TRUSTED);

                                let amount = paths.amount();
                                let authenticated = if amount >= sequoia_wot::FULLY_TRUSTED {
                                    eprintln!("{}Fully authenticated \
                                               ({} of {}) {}, {}",
                                              prefix,
                                              amount,
                                              sequoia_wot::FULLY_TRUSTED,
                                              cert_fpr,
                                              userid_str);
                                    true
                                } else if amount > 0 {
                                    eprintln!("{}Partially authenticated \
                                               ({} of {}) {}, {:?} ",
                                              prefix,
                                              amount,
                                              sequoia_wot::FULLY_TRUSTED,
                                              cert_fpr,
                                              userid_str);
                                    false
                                } else {
                                    eprintln!("{}{}: {:?} is unauthenticated \
                                               and may be an impersonation!",
                                              prefix,
                                              cert_fpr,
                                              userid_str);
                                    false
                                };

                                for (i, (path, amount)) in paths.iter().enumerate() {
                                    let prefix = if paths.len() > 1 {
                                        eprintln!("{}  Path #{} of {}, \
                                                  trust amount {}:",
                                                 prefix,
                                                 i + 1, paths.len(), amount);
                                        format!("{}    ", prefix)
                                    } else {
                                        format!("{}  ", prefix)
                                    };

                                    print_path(&path.into(), userid, &prefix)
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
                    } else {
                        eprintln!("Failed to build web of trust network.");
                    }
                } else {
                    eprintln!("Skipping, certificate store has been disabled");
                }
            }

            let issuer_str = issuer.to_string();
            let label = self.labels.get(&issuer).unwrap_or(&issuer_str);

            let level = sig.level();
            match (level == 0, trusted) {
                (true,  true)  => {
                    eprintln!("{}Good signature from {} ({:?})",
                              prefix, label, signer_userid);
                }
                (false, true)  => {
                    eprintln!("{}Good level {} notarization from {} ({:?})",
                              prefix, level, label, signer_userid);
                }
                (true,  false) => {
                    eprintln!("{}Unauthenticated checksum from {} ({:?})",
                              prefix, label, signer_userid);
                    eprintln!("{}  After checking that {} belongs to {:?}, \
                               you can authenticate the binding using \
                               'sq link add {} {:?}'.",
                              prefix, issuer_str, signer_userid,
                              issuer_str, signer_userid);
                }
                (false, false) => {
                    eprintln!("{}Unauthenticated level {} notarizing \
                               checksum from {} ({:?})",
                              prefix, level, label, signer_userid);
                    eprintln!("{}  After checking that {} belongs to {:?}, \
                               you can authenticate the binding using \
                               'sq link add {} {:?}'.",
                              prefix, issuer_str, signer_userid,
                              issuer_str, signer_userid);
                }
            };

            if trusted {
                self.good_signatures += 1;
            } else {
                self.good_checksums += 1;
            }

            eprintln!("");
        }
    }
}

impl<'a, 'store> VerificationHelper for VHelper<'a, 'store> {
    fn get_certs(&mut self, ids: &[openpgp::KeyHandle]) -> Result<Vec<Cert>> {
        let mut certs = self.certs.take().unwrap();
        // Get all keys.
        let seen: HashSet<_> = certs.iter()
            .flat_map(|cert| {
                cert.keys().map(|ka| ka.key().fingerprint().into())
            }).collect();

        // Explicitly provided keys are trusted.
        self.trusted = seen;

        // Look up the ids in the certificate store.

        // Avoid initializing the certificate store if we don't actually
        // need to.
        if ! ids.is_empty() {
            if let Ok(Some(cert_store)) = self.config.cert_store() {
                for id in ids.iter() {
                    if let Ok(c) = cert_store.lookup_by_key(id) {
                        certs.extend(
                            c.into_iter().filter_map(|c| c.as_cert().ok()));
                    }
                }
            }
        }

        Ok(certs)
    }

    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        for layer in structure {
            match layer {
                MessageLayer::Compression { algo } =>
                    eprintln!("Compressed using {}", algo),
                MessageLayer::Encryption { sym_algo, aead_algo } =>
                    if let Some(aead_algo) = aead_algo {
                        eprintln!("Encrypted and protected using {}/{}",
                                  sym_algo, aead_algo);
                    } else {
                        eprintln!("Encrypted using {}", sym_algo);
                    },
                MessageLayer::SignatureGroup { ref results } =>
                    self.print_sigs(results),
            }
        }

        if self.good_signatures >= self.signatures
            && self.bad_signatures + self.bad_checksums == 0 {
            Ok(())
        } else {
            self.print_status();
            Err(anyhow::anyhow!("Verification failed: could not fully \
                                 authenticate any signatures"))
        }
    }
}

pub fn verify(config: Config,
              input: &mut (dyn io::Read + Sync + Send),
              detached: Option<&mut (dyn io::Read + Sync + Send)>,
              output: &mut dyn io::Write,
              signatures: usize, certs: Vec<Cert>)
              -> Result<()> {
    let helper = VHelper::new(&config, signatures, certs);
    let helper = if let Some(dsig) = detached {
        let mut v = DetachedVerifierBuilder::from_reader(dsig)?
            .with_policy(&config.policy, Some(config.time), helper)?;
        v.verify_reader(input)?;
        v.into_helper()
    } else {
        let mut v = VerifierBuilder::from_reader(input)?
            .with_policy(&config.policy, Some(config.time), helper)?;
        io::copy(&mut v, output)?;
        v.into_helper()
    };

    helper.print_status();
    Ok(())
}

pub fn split(input: &mut (dyn io::Read + Sync + Send), prefix: &str)
             -> Result<()> {
    // We (ab)use the mapping feature to create byte-accurate dumps of
    // nested packets.
    let mut ppr =
        openpgp::parse::PacketParserBuilder::from_reader(input)?
        .map(true).build()?;

    // This encodes our position in the tree.
    let mut pos = vec![0];

    while let PacketParserResult::Some(pp) = ppr {
        if let Some(map) = pp.map() {
            let filename = format!(
                "{}{}--{}{:?}", prefix,
                pos.iter().map(|n| format!("{}", n))
                    .collect::<Vec<String>>().join("-"),
                pp.packet.kind().map(|_| "").unwrap_or("Unknown-"),
                pp.packet.tag());
            let mut sink = File::create(filename)
                .context("Failed to create output file")?;

            // Write all the bytes.
            for field in map.iter() {
                sink.write_all(field.as_bytes())?;
            }
        }

        let old_depth = Some(pp.recursion_depth());
        ppr = pp.recurse()?.1;
        let new_depth = ppr.as_ref().map(|pp| pp.recursion_depth()).ok();

        // Update pos.
        match old_depth.cmp(&new_depth) {
            Ordering::Less =>
                pos.push(0),
            Ordering::Equal =>
                *pos.last_mut().unwrap() += 1,
            Ordering::Greater => {
                pos.pop();
            },
        }
    }
    Ok(())
}

/// Joins the given files.
pub fn join(config: Config, c: packet::JoinCommand) -> Result<()> {
    // Either we know what kind of armor we want to produce, or we
    // need to detect it using the first packet we see.
    let kind = c.kind.into();
    let output = c.output;
    let mut sink = if c.binary {
        // No need for any auto-detection.
        Some(output.create_pgp_safe(config.force, true, armor::Kind::File)?)
    } else if let Some(kind) = kind {
        Some(output.create_pgp_safe(config.force, false, kind)?)
    } else {
        None // Defer.
    };

    /// Writes a bit-accurate copy of all top-level packets in PPR to
    /// OUTPUT.
    fn copy<'a, 'b>(config: &Config,
            mut ppr: PacketParserResult,
            output: &'a FileOrStdout,
            sink: &'b mut Option<Message<'a>>)
            -> Result<()> {
        while let PacketParserResult::Some(pp) = ppr {
            if sink.is_none() {
                // Autodetect using the first packet.
                let kind = match pp.packet {
                    Packet::Signature(_) => armor::Kind::Signature,
                    Packet::SecretKey(_) => armor::Kind::SecretKey,
                    Packet::PublicKey(_) => armor::Kind::PublicKey,
                    Packet::PKESK(_) | Packet::SKESK(_) =>
                        armor::Kind::Message,
                    _ => armor::Kind::File,
                };

                *sink = Some(
                    output.create_pgp_safe(config.force, false, kind)?
                );
            }

            // We (ab)use the mapping feature to create byte-accurate
            // copies.
            for field in pp.map().expect("must be mapped").iter() {
                sink.as_mut().expect("initialized at this point")
                    .write_all(field.as_bytes())?;
            }

            ppr = pp.next()?.1;
        }
        Ok(())
    }

    if !c.input.is_empty() {
        for name in c.input {
            let ppr =
                openpgp::parse::PacketParserBuilder::from_file(name)?
                .map(true).build()?;
            copy(&config, ppr, &output, &mut sink)?;
        }
    } else {
        let ppr =
            openpgp::parse::PacketParserBuilder::from_reader(io::stdin())?
            .map(true).build()?;
        copy(&config, ppr, &output, &mut sink)?;
    }

    sink.unwrap().finalize()?;
    Ok(())
}
