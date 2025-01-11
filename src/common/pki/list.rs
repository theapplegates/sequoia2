use std::sync::Arc;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Fingerprint;
use openpgp::KeyHandle;

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;
use cert_store::Store;

use crate::Result;
use crate::Sq;
use crate::cli::types::CertDesignators;
use crate::cli::types::cert_designator;
use crate::commands::active_certification;
use crate::common::ui;

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
    link: bool)
    -> Result<()>
where
    Prefix: cert_designator::ArgumentPrefix,
{
    let (link, linked) = if link {
        ("link", "linked")
    } else {
        ("certification", "certified")
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

    let (certs, errors) = if certs.is_empty() {
        (cert_store.certs(), Vec::new())
    } else {
        let (c, e) = sq.resolve_certs_filter(
            &certs, 0, &mut |designator, cert| {
                let userids = cert.userids().filter(|uid| {
                    match designator.query_params() {
                        Err(_) => false,
                        Ok(None) => true,
                        Ok(Some((q, p))) => q.check(uid, &p),
                    }
                });

                if active_certification(
                        &sq, cert.to_cert()?, userids,
                        certifier.primary_key().key().role_as_unspecified())
                    .into_iter()
                    .filter(|(_uid, certification)| certification.is_some())
                    .next().is_some()
                {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("not {}", linked))
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

        let userids = cert.userids()
            .map(|ua| ua.userid().clone())
            .collect::<Vec<_>>();

        for (userid, certification) in active_certification(
                &sq, &cert, userids.iter(),
                certifier.primary_key().key().role_as_unspecified())
            .into_iter()
            .filter_map(|(user, certification)| {
                if let Some(certification) = certification {
                    Some((user, certification))
                } else {
                    None
                }
            })
        {
            let (depth, amount) = certification.trust_signature()
                .unwrap_or((0, sequoia_wot::FULLY_TRUSTED as u8));

            if ca && depth == 0 {
                // Only show CAs.
                continue;
            }

            if dirty {
                wwriteln!(stream=o);
            }
            dirty = true;

            ui::emit_cert_userid(o, &cert, userid)?;

            const INDENT: &'static str = "     - ";

            if amount == 0 {
                wwriteln!(stream=o, initial_indent=INDENT,
                          "{} was retracted", link);
            } else {
                let mut regex: Vec<_> = certification.regular_expressions()
                    .map(|re| ui::Safe(re).to_string())
                    .collect();
                regex.sort();
                regex.dedup();

                let summary = if depth > 0 {
                    if amount == sequoia_wot::FULLY_TRUSTED as u8
                        && regex.is_empty()
                    {
                        format!("is {} as a fully trusted CA", linked)
                    } else {
                        format!("is {} as a partially trusted CA", linked)
                    }
                } else {
                    format!("is {}", linked)
                };
                wwriteln!(stream=o, initial_indent=INDENT, "{}", summary);

                if let Some(e) = certification.signature_expiration_time() {
                    wwriteln!(stream=o, initial_indent=INDENT,
                              "expiration: {}",
                              chrono::DateTime::<chrono::Utc>::from(e)
                              .format("%Y‑%m‑%d"));
                }

                if depth != 0 && depth != 255 {
                    wwriteln!(stream=o, initial_indent=INDENT,
                              "trust depth: {}", depth);
                }

                if amount != sequoia_wot::FULLY_TRUSTED as u8 {
                    wwriteln!(stream=o, initial_indent=INDENT,
                              "trust amount: {}", amount);
                }

                if ! regex.is_empty() {
                    wwriteln!(stream=o, initial_indent=INDENT,
                              "regular expressions: {}", regex.join("; "));
                }
            }
        }
    }

    Ok(())
}
