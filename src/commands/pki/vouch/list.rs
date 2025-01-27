use std::cell::Ref;
use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::BTreeSet;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Fingerprint;
use openpgp::KeyHandle;
use openpgp::KeyID;
use openpgp::Packet;
use openpgp::Result;
use openpgp::packet::Signature;
use openpgp::packet::Tag;
use openpgp::packet::UserID;
use openpgp::policy::HashAlgoSecurity;
use openpgp::policy::Policy;
use openpgp::types::KeyFlags;
use openpgp::types::SignatureType;

use sequoia_cert_store as cert_store;
use cert_store::Store;

use crate::Sq;
use crate::cli::pki::vouch::list;
use crate::common::ui;
use crate::sq::TrustThreshold;

const TRACE: bool = false;

enum CertOrKeyHandle {
    Cert(RefCell<Cert>),
    KeyHandle(KeyHandle),
}

impl CertOrKeyHandle {
    fn key_handle(&self) -> KeyHandle {
        match self {
            CertOrKeyHandle::Cert(cert) => cert.borrow().key_handle(),
            CertOrKeyHandle::KeyHandle(kh) => kh.clone(),
        }
    }

    fn cert(&self) -> Option<Ref<Cert>> {
        match self {
            CertOrKeyHandle::Cert(cert) => Some(cert.borrow()),
            CertOrKeyHandle::KeyHandle(_) => None,
        }
    }
}

impl From<RefCell<Cert>> for CertOrKeyHandle {
    fn from(cert: RefCell<Cert>) -> CertOrKeyHandle {
        CertOrKeyHandle::Cert(cert)
    }
}

impl From<&KeyHandle> for CertOrKeyHandle {
    fn from(kh: &KeyHandle) -> CertOrKeyHandle {
        CertOrKeyHandle::KeyHandle(kh.clone())
    }
}

impl From<KeyHandle> for CertOrKeyHandle {
    fn from(kh: KeyHandle) -> CertOrKeyHandle {
        CertOrKeyHandle::KeyHandle(kh)
    }
}

pub fn list(sq: Sq, c: list::Command)
    -> Result<()>
{
    tracer!(TRACE, "pki::vouch::list");

    let cert_store = sq.cert_store_or_else()?;

    // Optional certifier.
    let (certifier, error) =
        sq.resolve_certs(&c.certifier, TrustThreshold::Full)?;
    assert!(certifier.len() <= 1);
    assert!(error.len() <= 1);
    let certifier = certifier.into_iter().next().map(RefCell::new);

    if let Some(error) = error.into_iter().next() {
        return Err(error);
    }

    // Optional target cert.
    let (target_cert, error) = sq.resolve_certs(&c.cert, TrustThreshold::Full)?;
    assert!(target_cert.len() <= 1);
    assert!(error.len() <= 1);
    if let Some(error) = error.into_iter().next() {
        return Err(error);
    }
    let target_cert = target_cert.into_iter().next().map(RefCell::new);

    // Certifier, target cert, target user ID, certification.
    let mut candidates: Vec<(CertOrKeyHandle, RefCell<Cert>, UserID, Signature)>
        = Vec::new();

    if let Some(target_cert) = target_cert {
        // The user wants to know who certified a particular certificate.

        let target_cert_fpr = target_cert.borrow().fingerprint();

        // Get all of the certifications made on the target cert.
        for ua in target_cert.borrow().userids() {
            for certification in ua.certifications() {
                let issuers = certification.get_issuers();

                if let Some(ref certifier) = certifier {
                    // The user wants to know about a specific certifier.

                    let certifier_kh = certifier.borrow().key_handle();

                    if issuers.into_iter().any(|kh| kh.aliases(&certifier_kh)) {
                        candidates.push(
                            (RefCell::clone(certifier).into(),
                             RefCell::clone(&target_cert).into(),
                             ua.userid().clone(),
                             certification.clone()));
                    }
                } else {
                    // The user wants to know about any certifier.

                    // Deduplicate the issuers.
                    let mut fprs: Vec<Fingerprint> = issuers.iter()
                        .filter_map(|kh| {
                            match kh {
                                KeyHandle::Fingerprint(fpr) => {
                                    Some(fpr.clone())
                                },
                                KeyHandle::KeyID(_) => None,
                            }
                        })
                        .collect();
                    fprs.sort();
                    fprs.dedup();

                    let mut keyids: Vec<KeyID> = issuers.into_iter()
                        .filter_map(|kh| {
                            match kh {
                                KeyHandle::Fingerprint(_) => None,
                                KeyHandle::KeyID(keyid) => Some(keyid),
                            }
                        })
                        .collect();
                    keyids.sort();
                    keyids.dedup();

                    // Remove any key IDs that alias a fingerprint.
                    let dedup: BTreeSet<KeyID> = fprs
                        .iter()
                        .map(|fpr| KeyID::from(fpr))
                        .collect();

                    keyids.retain(|keyid| ! dedup.contains(keyid));

                    for kh in fprs.into_iter().map(KeyHandle::from)
                        .chain(keyids.into_iter().map(KeyHandle::from))
                    {
                        if let Ok(certifiers)
                            = sq.lookup(std::iter::once(&kh),
                                        Some(KeyFlags::certification()),
                                        false, true)
                        {
                            for certifier in certifiers.into_iter() {
                                t!("  Possible certification of {}, {:?} by {}, {}",
                                   target_cert_fpr,
                                   String::from_utf8_lossy(ua.userid().value()),
                                   certifier.fingerprint(),
                                   sq.best_userid(&certifier, true));
                                candidates.push(
                                    (RefCell::new(certifier).into(),
                                     RefCell::clone(&target_cert),
                                     ua.userid().clone(),
                                     certification.clone()));
                            }
                        } else {
                            t!("  Possible certification by {}, but we can't \
                                check it as we don't have the certificate",
                               kh);
                            candidates.push(
                                (kh.into(),
                                 RefCell::clone(&target_cert),
                                 ua.userid().clone(),
                                 certification.clone()));
                        }
                    }
                }
            }
        }
    } else if let Some(certifier) = certifier {
        let certifier_fpr = certifier.borrow().fingerprint();
        let certifier_kh = KeyHandle::from(&certifier_fpr);

        // The user wants to know what certificates `certifier`
        // certified.  Since certifications are stored alongside the
        // certified certificate, we have to iterate over all of the
        // certificates in the store.
        //
        // To avoid fully parsing certificates, which is expensive, we
        // first do a lightweight check with the `RawCert`: if the
        // `RawCert` doesn't contain a signature packet with
        // `certifier` as the issuer, then we can skip it.

        // XXX: We're iterating over all certificates in the
        // certificate store.  Consider parallelizing this.
        for cert in cert_store.certs() {
            t!("Considering {}, {}",
               cert.fingerprint(),
               cert.userids().next()
                   .map(|userid| {
                       String::from_utf8_lossy(userid.value()).to_string()
                   })
                   .unwrap_or_else(|| "<no userids>".to_string()));
            if cert.userids().next().is_none() {
                // The certificate has no user IDs.  Thus, it can't
                // have been certified.
                t!("  Skipping: no user IDs.");
                continue;
            }
            if cert.fingerprint() == certifier_fpr {
                // We can't make a third-party certification on
                // ourself; that's a first-party certification!
                t!("  Skipping: is certifier.");
                continue;
            }

            if let Some(cert) = cert.raw_cert() {
                let mut possible_certification = false;
                for raw_packet in cert.packets() {
                    let sig = if raw_packet.tag() == Tag::Signature {
                        match Packet::try_from(raw_packet) {
                            Ok(packet) => {
                                if let Packet::Signature(sig) = packet {
                                    sig
                                } else {
                                    unreachable!();
                                }
                            }
                            Err(err) => {
                                // Invalid packet.
                                t!("  Invalid signature: {}.", err);
                                continue;
                            }
                        }
                    } else {
                        // Not a signature packet.
                        continue;
                    };

                    if ! matches!(
                        sig.typ(),
                        SignatureType::GenericCertification
                            | SignatureType::PersonaCertification
                            | SignatureType::CasualCertification
                            | SignatureType::PositiveCertification)
                    {
                        // Not a certification.
                        continue;
                    }

                    // Check that an issuer packet names the
                    // certifier.
                    let issuers = sig.get_issuers();
                    if issuers.into_iter().any(|issuer| {
                        issuer.aliases(
                            KeyHandle::from(cert.fingerprint()))
                    })
                    {
                        t!("  Have a possible certification");
                        possible_certification = true;
                        break;
                    }
                }

                if ! possible_certification {
                    t!("  Skipping: No certifications found.");
                    continue;
                }
            }

            // Add any certifications to the candidates list.
            match cert.to_cert() {
                Ok(cert) => {
                    let cert_cell: RefCell<Cert> = RefCell::new(cert.clone());
                    let cert = cert_cell.borrow();
                    for ua in cert.userids() {
                        for certification in ua.certifications() {
                            let issuers = certification.get_issuers();
                            if issuers.into_iter().any(|issuer| {
                                issuer.aliases(&certifier_kh)
                            })
                            {
                                t!("  Possible certification of {}, {:?}",
                                   cert.fingerprint(),
                                   String::from_utf8_lossy(ua.userid().value()));
                                candidates.push(
                                    (RefCell::clone(&certifier).into(),
                                     RefCell::clone(&cert_cell).into(),
                                     ua.userid().clone(),
                                     certification.clone()));
                            }
                        }
                    }
                }
                Err(err) => {
                    // Silently ignore the parse error.
                    t!("Error parsing {}: {}", cert.fingerprint(), err);
                    continue;
                }
            }
        }
    } else {
        // The user must supply either --certifier or --cert (or
        // both).
        return Err(clap::Error::raw(
            clap::error::ErrorKind::MissingRequiredArgument,
            "Either a certifier (using, e.g., --certifier) \
             or a target certificate (using, e.g., --cert) \
             must be supplied").into());
    }

    let o = &mut std::io::stdout();

    t!("Have {} possible certifications", candidates.len());
    candidates.sort_by(
        |(a_certifier, a_cert, a_userid, a_certification),
         (b_certifier, b_cert, b_userid, b_certification)|
        {
            match (a_certifier.key_handle(), b_certifier.key_handle()) {
                (KeyHandle::Fingerprint(a), KeyHandle::Fingerprint(b)) => {
                    a.cmp(&b)
                }
                (KeyHandle::Fingerprint(_), KeyHandle::KeyID(_)) => {
                    Ordering::Greater
                }
                (KeyHandle::KeyID(_), KeyHandle::Fingerprint(_)) => {
                    Ordering::Less
                }
                (KeyHandle::KeyID(a), KeyHandle::KeyID(b)) => {
                    a.cmp(&b)
                }
            }
                .then_with(|| {
                    a_cert.borrow().fingerprint()
                        .cmp(&b_cert.borrow().fingerprint())
                })
                .then_with(|| {
                    a_userid.cmp(&b_userid)
                })
                .then_with(|| {
                    a_certification.signature_creation_time().cmp(
                        &b_certification.signature_creation_time())
                        // Newest first.
                        .reverse()
                })
                .then_with(|| {
                    // Break ties deterministically using the MPIs.
                    a_certification.mpis().cmp(
                        &b_certification.mpis())
                })
        });

    let mut first = true;
    let mut current_certifier = None;
    for (certifier, cert, userid, certification) in candidates.into_iter() {
        let cert = cert.borrow();

        let invalid = if let Some(certifier) = certifier.cert() {
            if let Err(err) = certification.verify_userid_binding(
                certifier.primary_key().key(),
                cert.primary_key().key(),
                &userid)
            {
                // Invalid signature.
                t!("Certification by {} on {}, {} is invalid: {}",
                   certifier.key_handle(),
                   cert.fingerprint(),
                   String::from_utf8_lossy(userid.value()),
                   err);

                Some(err)
            } else {
                // Check the policy.
                if let Err(err) = sq.policy.signature(
                    &certification,
                    HashAlgoSecurity::CollisionResistance)
                {
                    Some(err)
                } else {
                    None
                }
            }
        } else {
            Some(anyhow::anyhow!("Cannot check signature: missing certificate"))
        };

        if first {
            first = false;
        } else {
            wwriteln!(o, "");
        }

        if current_certifier != Some(certifier.key_handle()) {
            current_certifier = Some(certifier.key_handle());

            wwriteln!(o, " - Certifier:");
            if let Some(certifier) = certifier.cert() {
                ui::emit_cert_indent(o, "  ", &sq, &certifier)?;
            } else {
                ui::emit_cert_key_handle_userid_str_indent(
                    o, "  ",
                    &certifier.key_handle(), "<unknown: missing certificate>")?;
            }
            wwriteln!(o, "");
        }

        if certifier.cert().is_some() {
            if let Some(ref err) = invalid {
                wwriteln!(o, "   - Invalid certification: {}",
                          crate::one_line_error_chain(err));
            } else {
                wwriteln!(o, "   - Certified the binding:");
            }
        } else {
            wwriteln!(o, "   - Unchecked and possible invalid certification \
                          of the binding:");
        }
        ui::emit_cert_userid_indent(o, "    ", &cert, &userid)?;

        wwriteln!(o, "");
        let indent = "      ";
        crate::common::pki::list::summarize_certification(
            o, indent, &certification, false)?;
    }

    Ok(())
}
