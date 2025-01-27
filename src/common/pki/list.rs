use std::collections::BTreeMap;
use std::sync::Arc;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Fingerprint;
use openpgp::KeyHandle;
use openpgp::packet::Signature;

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;
use cert_store::Store;

use crate::Result;
use crate::Sq;
use crate::cli::types::CertDesignators;
use crate::cli::types::cert_designator;
use crate::commands::active_certification;
use crate::common::ui;
use crate::sq::TrustThreshold;

/// `link` is whether "link" should be used to talk about the
/// certification or "certification".
pub fn summarize_certification(o: &mut dyn std::io::Write,
                               indent: &str,
                               certification: &Signature,
                               link: bool)
    -> Result<()>
{
    let (link, linked) = if link {
        ("link", "linked")
    } else {
        ("certification", "certified")
    };

    let indent = &format!("{} - ", indent)[..];

    if let Some(t) = certification.signature_creation_time() {
        wwriteln!(stream=o, initial_indent=indent,
                  "created at {}",
                  chrono::DateTime::<chrono::Utc>::from(t)
                  .format("%Y‑%m‑%d %H:%M:%S"));
    } else {
        wwriteln!(stream=o, initial_indent=indent,
                  "creation time missing");
    }

    let (depth, amount) = certification.trust_signature()
        .unwrap_or((0, sequoia_wot::FULLY_TRUSTED as u8));

    if amount == 0 {
        wwriteln!(stream=o, initial_indent=indent,
                  "{} was retracted", link);
    } else {
        let mut regex: Vec<_> = certification.regular_expressions()
            .map(|re| ui::Safe(re).to_string())
            .collect();
        regex.sort();
        regex.dedup();

        if depth > 0 {
            if amount == sequoia_wot::FULLY_TRUSTED as u8
                && regex.is_empty()
            {
                wwriteln!(stream=o, initial_indent=indent,
                          "{} as a fully trusted CA", linked);
            } else {
                wwriteln!(stream=o, initial_indent=indent,
                          "{} as a partially trusted CA", linked);
            }
        }

        if let Some(e) = certification.signature_expiration_time() {
            wwriteln!(stream=o, initial_indent=indent,
                      "expiration: {}",
                      chrono::DateTime::<chrono::Utc>::from(e)
                      .format("%Y‑%m‑%d"));
        }

        if depth != 0 && depth != 255 {
            wwriteln!(stream=o, initial_indent=indent,
                      "trust depth: {}", depth);
        }

        if amount != sequoia_wot::FULLY_TRUSTED as u8 {
            wwriteln!(stream=o, initial_indent=indent,
                      "trust amount: {}", amount);
        }

        if ! regex.is_empty() {
            wwriteln!(stream=o, initial_indent=indent,
                      "regular expressions: {}", regex.join("; "));
        }
    }

    Ok(())
}

/// List the bindings made by `certifier`.
///
/// If `certs` or `pattern` is set, only list matching bindings.
///
/// If `ca` is true, only list delegations.
///
/// `link` is purely decorative and controls whether "link" or
/// "certification" is shown.
pub fn list<Arguments, Prefix, Options, Doc>(
    sq: Sq,
    certifier: &Cert,
    mut certs: CertDesignators<Arguments, Prefix, Options, Doc>,
    pattern: Option<String>,
    ca: bool,
    is_link: bool)
    -> Result<()>
where
    Prefix: cert_designator::ArgumentPrefix,
{
    let linked = if is_link {
        "linked"
    } else {
        "certified"
    };

    let cert_store = sq.cert_store_or_else()?;

    if let Some(pattern) = pattern {
        let mut d = None;
        if let Ok(kh) = pattern.parse::<KeyHandle>() {
            if matches!(kh, KeyHandle::Fingerprint(Fingerprint::Invalid(_))) {
                let hex = pattern.chars()
                    .map(|c| {
                        if c == ' ' { 0 } else { 1 }
                    })
                    .sum::<usize>();

                if hex >= 16 {
                    weprintln!("Warning: {} looks like a fingerprint or key ID, \
                                but its invalid.  Treating it as a text pattern.",
                               pattern);
                }
            } else {
                d = Some(cert_designator::CertDesignator::Cert(kh));
            }
        };

        certs.push(d.unwrap_or_else(|| {
            cert_designator::CertDesignator::Grep(pattern)
        }));
    }

    let mut active_certifications_cache: BTreeMap<Fingerprint, _>
        = BTreeMap::new();

    let (certs, errors) = if certs.is_empty() {
        (cert_store.certs(), Vec::new())
    } else {
        let (c, e) = sq.resolve_certs_filter(
            &certs, TrustThreshold::Full, &mut |_designator, cert| {
                let userids = cert.userids();
                let cert = cert.to_cert()?;

                let active_certifications = active_certification(
                    &sq, cert, userids,
                    certifier.primary_key().key().role_as_unspecified());

                if active_certifications.iter().any(|(_userid, certifications)| {
                    certifications.is_some()
                })
                {
                    active_certifications_cache.insert(
                        cert.fingerprint(),
                        active_certifications);
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("{} {} was never {}",
                                        cert.fingerprint(),
                                        sq.best_userid(cert, true),
                                        linked))
                }
            })?;
        (Box::new(c.into_iter().map(|c| Arc::new(LazyCert::from(c))))
         as Box<dyn Iterator<Item=Arc<LazyCert<'_>>>>,
         e)
    };

    for error in errors.iter() {
        crate::print_error_chain(error);
    }
    if ! errors.is_empty() {
        return Err(anyhow::anyhow!("Failed to resolve certificates"));
    }

    let o = &mut std::io::stdout();
    let mut dirty = false;

    for cert in certs {
        let cert = if let Ok(cert) = cert.to_cert() {
            cert
        } else {
            // Invalid cert.  Skip it.
            continue;
        };

        let active_certifications = if let Some(ac)
            = active_certifications_cache.remove(&cert.fingerprint())
        {
            ac
        } else {
            let userids = cert.userids().map(|ua| ua.userid().clone());

            active_certification(
                &sq, &cert, userids,
                certifier.primary_key().key().role_as_unspecified())
        };

        for (userid, certification) in active_certifications
            .into_iter()
            .filter_map(|(user, certification)| {
                if let Some(certification) = certification {
                    Some((user, certification))
                } else {
                    None
                }
            })
        {
            let (depth, _amount) = certification.trust_signature()
                .unwrap_or((0, sequoia_wot::FULLY_TRUSTED as u8));

            if ca && depth == 0 {
                // Only show CAs.
                continue;
            }

            if dirty {
                wwriteln!(stream=o);
            }
            dirty = true;

            ui::emit_cert_userid(o, &cert, &userid)?;
            let indent = "    ";
            summarize_certification(o, indent, &certification, is_link)?;
        }
    }

    Ok(())
}
