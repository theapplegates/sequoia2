use anyhow::Context as _;
use std::collections::HashMap;
use std::io;

use sequoia_openpgp as openpgp;
use openpgp::types::SymmetricAlgorithm;
use openpgp::fmt::hex;
use openpgp::KeyHandle;
use openpgp::crypto::{self, SessionKey, Decryptor};
use openpgp::{Fingerprint, Cert, KeyID, Result};
use openpgp::packet;
use openpgp::packet::prelude::*;
use openpgp::parse::{
    Parse,
    PacketParser,
    PacketParserResult,
};
use openpgp::parse::stream::{
    VerificationHelper, DecryptionHelper, DecryptorBuilder, MessageStructure,
};
use sequoia_openpgp::types::KeyFlags;

use sequoia_cert_store as cert_store;
use cert_store::store::StoreError;

use sequoia_keystore as keystore;

use crate::{
    cli,
    commands::{
        VHelper,
    },
    common::password,
    Sq,
    load_certs,
    load_keys,
};

pub fn dispatch(sq: Sq, command: cli::decrypt::Command) -> Result<()> {
    tracer!(TRACE, "decrypt::dispatch");

    let mut input = command.input.open()?;
    let mut output = command.output.create_safe(sq.force)?;

    let certs = load_certs(
        command.sender_cert_file.iter().map(|s| s.as_ref()),
    )?;
    // Fancy default for --signatures.  If you change this,
    // also change the description in the CLI definition.
    let signatures = command.signatures.unwrap_or_else(|| {
        if certs.is_empty() {
            // No certs are given for verification, use 0 as
            // threshold so we handle only-encrypted messages
            // gracefully.
            0
        } else {
            // At least one cert given, expect at least one
            // valid signature.
            1
        }
    });
    let secrets =
        load_keys(command.secret_key_file.iter().map(|s| s.as_ref()))?;
    let session_keys = command.session_key;
    decrypt(sq, &mut input, &mut output,
            signatures, certs, secrets,
            command.dump_session_key,
            session_keys)?;

    Ok(())
}

pub struct Helper<'c, 'store, 'rstore>
    where 'store: 'rstore
{
    vhelper: VHelper<'c, 'store, 'rstore>,
    secret_keys: HashMap<KeyID, (Cert, Key<key::SecretParts, key::UnspecifiedRole>)>,
    key_identities: HashMap<KeyID, Fingerprint>,
    session_keys: Vec<cli::types::SessionKey>,
    dump_session_key: bool,
}

impl<'c, 'store, 'rstore> std::ops::Deref for Helper<'c, 'store, 'rstore>
    where 'store: 'rstore
{
    type Target = VHelper<'c, 'store, 'rstore>;

    fn deref(&self) -> &Self::Target {
        &self.vhelper
    }
}

impl<'c, 'store, 'rstore> std::ops::DerefMut for Helper<'c, 'store, 'rstore> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.vhelper
    }
}

impl<'c, 'store, 'rstore> Helper<'c, 'store, 'rstore>
    where 'store: 'rstore
{
    pub fn new(sq: &'c Sq<'store, 'rstore>,
               signatures: usize, certs: Vec<Cert>, secrets: Vec<Cert>,
               session_keys: Vec<cli::types::SessionKey>,
               dump_session_key: bool)
               -> Self
    {
        let mut keys: HashMap<KeyID, (Cert, Key<key::SecretParts, key::UnspecifiedRole>)>
            = HashMap::new();
        let mut identities: HashMap<KeyID, Fingerprint> = HashMap::new();
        for tsk in secrets {
            for ka in tsk.keys().secret()
                // XXX: Should use the message's creation time that we do not know.
                .with_policy(sq.policy, None)
                .for_transport_encryption().for_storage_encryption()
            {
                let id: KeyID = ka.key().fingerprint().into();
                let key = ka.key();
                keys.insert(id.clone(), (tsk.clone(), key.clone()));
                identities.insert(id.clone(), tsk.fingerprint());
            }
        }

        Helper {
            vhelper: VHelper::new(sq, signatures, certs),
            secret_keys: keys,
            key_identities: identities,
            session_keys,
            dump_session_key,
        }
    }

    /// Checks if a session key can decrypt the packet parser using
    /// `decrypt`.
    fn try_session_key<D>(&self, keyid: &KeyID,
                          algo: SymmetricAlgorithm, sk: SessionKey,
                          decrypt: &mut D)
        -> Option<Option<Fingerprint>>
        where D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool
    {
        if decrypt(algo, &sk) {
            if self.dump_session_key {
                wprintln!("Session key: {}", hex::encode(&sk));
            }
            Some(self.key_identities.get(keyid).cloned())
        } else {
            None
        }
    }

    /// Tries to decrypt the given PKESK packet with `keypair` and try
    /// to decrypt the packet parser using `decrypt`.
    fn try_decrypt<D>(&self, pkesk: &PKESK,
                      sym_algo: Option<SymmetricAlgorithm>,
                      mut keypair: Box<dyn crypto::Decryptor>,
                      decrypt: &mut D)
                      -> Option<Option<Fingerprint>>
        where D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool
    {
        let keyid = keypair.public().fingerprint().into();
        let (sym_algo, sk) = pkesk.decrypt(&mut *keypair, sym_algo)?;
        self.try_session_key(&keyid, sym_algo, sk, decrypt)
    }
}

impl<'c, 'store, 'rstore> VerificationHelper for Helper<'c, 'store, 'rstore>
    where 'store: 'rstore
{
    fn get_certs(&mut self, ids: &[openpgp::KeyHandle]) -> Result<Vec<Cert>> {
        self.vhelper.get_certs(ids)
    }
    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        self.vhelper.check(structure)
    }
}

impl<'c, 'store, 'rstore> DecryptionHelper for Helper<'c, 'store, 'rstore>
    where 'store: 'rstore
{
    fn decrypt<D>(&mut self, pkesks: &[PKESK], skesks: &[SKESK],
                  sym_algo: Option<SymmetricAlgorithm>,
                  mut decrypt: D) -> openpgp::Result<Option<Fingerprint>>
        where D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool
    {
        make_qprintln!(self.quiet);

        // Before anything else, try the session keys
        for sk in &self.session_keys {
            let decrypted = if let Some(sa) = sk.symmetric_algo {
                decrypt(sa, &sk.session_key)
            } else {
                // We don't know which algorithm to use,
                // try to find one that decrypts the message.
                (1u8..=19)
                    .map(SymmetricAlgorithm::from)
                    .any(|sa| decrypt(sa, &sk.session_key))
            };
            if decrypted {
                qprintln!("Encrypted with Session Key {}",
                          sk.display_sensitive());
                return Ok(None);
            }
        }

        // Now, we try the secret keys that the user supplied on the
        // command line.

        let mut decrypt_key = |slf: &Self, pkesk, cert, key: &Key<_, _>, prompt: bool| {
            slf.vhelper.sq.decrypt_key(Some(cert), key.clone(), prompt, true)
                .ok()
                .and_then(|key| {
                    let keypair = Box::new(key.into_keypair()
                        .expect("decrypted secret key material"));

                    slf.try_decrypt(pkesk, sym_algo, keypair, &mut decrypt)
                })
        };

        // First, we try those keys that we can use without prompting
        // for a password.
        for pkesk in pkesks {
            let keyid = pkesk.recipient();
            if let Some((cert, key)) = self.secret_keys.get(keyid) {
                if let Some(fp) = decrypt_key(self, pkesk, cert, key, false) {
                    return Ok(fp);
                }
            }
        }

        // Second, we try those keys that are encrypted.
        for pkesk in pkesks {
            // Don't ask the user to decrypt a key if we don't support
            // the algorithm.
            if ! pkesk.pk_algo().is_supported() {
                continue;
            }

            let keyid = pkesk.recipient();
            if let Some((cert, key)) = self.secret_keys.get(keyid) {
                if let Some(fp) = decrypt_key(self, pkesk, cert, key, true) {
                    return Ok(fp);
                }
            }
        }

        // Third, we try to decrypt PKESK packets with wildcard
        // recipients using those keys that we can use without
        // prompting for a password.
        for pkesk in pkesks.iter().filter(|p| p.recipient().is_wildcard()) {
            for (cert, key) in self.secret_keys.values() {
                if let Some(fp) = decrypt_key(self, pkesk, cert, key, false) {
                    return Ok(fp);
                }
            }
        }

        // Fourth, we try to decrypt PKESK packets with wildcard
        // recipients using those keys that are encrypted.
        for pkesk in pkesks.iter().filter(|p| p.recipient().is_wildcard()) {
            // Don't ask the user to decrypt a key if we don't support
            // the algorithm.
            if ! pkesk.pk_algo().is_supported() {
                continue;
            }

            for (cert, key) in self.secret_keys.values() {
                if let Some(fp) = decrypt_key(self, pkesk, cert, key, true) {
                    return Ok(fp);
                }
            }
        }

        // Try the key store.
        match self.vhelper.sq.key_store_or_else() {
            Ok(ks) => {
                let mut ks = ks.lock().unwrap();
                match ks.decrypt(&pkesks[..]) {
                    // Success!
                    Ok((_i, fpr, sym_algo, sk)) => {
                        if let Some(fp) =
                            self.try_session_key(
                                &KeyID::from(fpr), sym_algo, sk, &mut decrypt)
                        {
                            return Ok(fp);
                        }
                    }

                    Err(err) => {
                        match err.downcast() {
                            Ok(keystore::Error::InaccessibleDecryptionKey(keys)) => {
                                for key_status in keys.into_iter() {
                                    let pkesk = key_status.pkesk().clone();
                                    let mut key = key_status.into_key();
                                    let keyid = key.keyid();
                                    let userid = self.sq.best_userid_for(
                                        &KeyHandle::from(&keyid), true);

                                    let keypair = loop {
                                        let password = rpassword::prompt_password(
                                            format!(
                                                "Enter password to unlock {}, {}: ",
                                                keyid, userid))?
                                            .into();

                                        if let Ok(()) = key.unlock(password) {
                                            break Box::new(key);
                                        } else {
                                            wprintln!("Bad password.");
                                        }
                                    };

                                    if let Some(fp) = self.try_decrypt(
                                        &pkesk, sym_algo, keypair, &mut decrypt)
                                    {
                                        return Ok(fp);
                                    }
                                }
                            }
                            // Failed to decrypt using the keystore.
                            Ok(_err) => (),
                            Err(_err) => (),
                        }
                    }
                }
            }
            Err(err) => {
                wprintln!("Warning: unable to connect to keystore: {}",
                          err);
            }
        }

        if skesks.is_empty() {
            let recipients = pkesks.iter()
                .filter_map(|p| {
                    let recipient = p.recipient();
                    if recipient.is_wildcard() {
                        None
                    } else {
                        Some(recipient)
                    }
                });
            wprintln!("No key to decrypt message.  The message appears \
                       to be encrypted to:");
            eprintln!();
            for recipient in recipients.into_iter() {
                let certs = self.sq.lookup(
                    std::iter::once(KeyHandle::from(recipient)),
                    Some(KeyFlags::empty()
                         .set_storage_encryption()
                         .set_transport_encryption()),
                    false,
                    true);

                match certs {
                    Ok(certs) => {
                        for cert in certs {
                            eprintln!("  - {}, {}",
                                      cert.fingerprint(),
                                      self.sq.best_userid(&cert, true));
                        }
                    }
                    Err(err) => {
                        if let Some(StoreError::NotFound(_))
                            = err.downcast_ref()
                        {
                            eprintln!("  - {}, certificate not found",
                                      recipient);
                        } else {
                            eprintln!("  - {}, error looking up certificate: {}",
                                      recipient, err);
                        }
                    }
                };
            }
            eprintln!();

            return
                Err(anyhow::anyhow!("No key to decrypt message"));
        }

        // Finally, try to decrypt using the SKESKs.
        let mut first = true;
        loop {
            let password = password::prompt_to_unlock("the message")?;

            for skesk in skesks {
                if let Some(sk) = skesk.decrypt(&password).ok()
                    .and_then(|(algo, sk)| { if decrypt(algo, &sk) { Some(sk) } else { None }})
                {
                    if self.dump_session_key {
                        wprintln!("Session key: {}", hex::encode(&sk));
                    }
                    return Ok(None);
                }
            }

            if password.map(|p| p.is_empty()) {
                break Err(anyhow::anyhow!("Decryption failed."));
            }

            if first {
                wprintln!("Incorrect password.  \
                           Hint: enter empty password to cancel.");
                first = false;
            } else {
                wprintln!("Incorrect password.");
            }
        }
    }
}

// Allow too many arguments now, should be reworked later
#[allow(clippy::too_many_arguments)]
pub fn decrypt(sq: Sq,
               input: &mut (dyn io::Read + Sync + Send),
               output: &mut dyn io::Write,
               signatures: usize, certs: Vec<Cert>, secrets: Vec<Cert>,
               dump_session_key: bool,
               sk: Vec<cli::types::SessionKey>)
               -> Result<()> {
    let helper = Helper::new(&sq, signatures, certs,
                             secrets, sk, dump_session_key);
    let mut decryptor = DecryptorBuilder::from_reader(input)?
        .with_policy(sq.policy, None, helper)
        .context("Decryption failed")?;

    io::copy(&mut decryptor, output).context("Decryption failed")?;

    let helper = decryptor.into_helper();
    helper.vhelper.print_status();
    Ok(())
}

pub fn decrypt_unwrap(sq: Sq,
                      input: &mut (dyn io::Read + Sync + Send),
                      output: &mut dyn io::Write,
                      secrets: Vec<Cert>,
                      session_keys: Vec<cli::types::SessionKey>,
                      dump_session_key: bool)
                      -> Result<()>
{
    let mut helper = Helper::new(&sq, 0, Vec::new(), secrets,
                                 session_keys,
                                 dump_session_key);

    let mut ppr = PacketParser::from_reader(input)?;

    let mut pkesks: Vec<packet::PKESK> = Vec::new();
    let mut skesks: Vec<packet::SKESK> = Vec::new();
    while let PacketParserResult::Some(mut pp) = ppr {
        let sym_algo_hint = if let Packet::AED(ref aed) = pp.packet {
            Some(aed.symmetric_algo())
        } else {
            None
        };

        match pp.packet {
            Packet::SEIP(_) | Packet::AED(_) => {
                {
                    let decrypt = |algo, secret: &SessionKey| {
                        pp.decrypt(algo, secret).is_ok()
                    };
                    helper.decrypt(&pkesks[..], &skesks[..], sym_algo_hint,
                                   decrypt)?;
                }
                if ! pp.processed() {
                    return Err(
                        openpgp::Error::MissingSessionKey(
                            "No session key".into()).into());
                }

                io::copy(&mut pp, output)?;
                return Ok(());
            },
            #[allow(deprecated)]
            Packet::MDC(ref mdc) => if ! mdc.valid() {
                return Err(openpgp::Error::ManipulatedMessage.into());
            },
            _ => (),
        }

        let (p, ppr_tmp) = pp.recurse()?;
        match p {
            Packet::PKESK(pkesk) => pkesks.push(pkesk),
            Packet::SKESK(skesk) => skesks.push(skesk),
            _ => (),
        }
        ppr = ppr_tmp;
    }

    Ok(())
}
