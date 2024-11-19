use std::sync::Arc;
use std::path::PathBuf;

use anyhow::Context;

use buffered_reader::{BufferedReader, Dup};

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;
use openpgp::Packet;
use openpgp::Result;
use openpgp::cert::raw::RawCertParser;
use openpgp::parse::Cookie;
use openpgp::parse::PacketParser;
use openpgp::parse::PacketParserResult;
use openpgp::parse::Parse;
use openpgp::types::SignatureType;

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;
use cert_store::StoreUpdate;

use crate::Sq;
use crate::cli::cert::import;
use crate::cli::types::FileOrStdin;
use crate::commands::autocrypt;
use crate::output::import::ImportStats;

pub fn dispatch<'store, 'rstore>(mut sq: Sq<'store, 'rstore>,
                                 cmd: import::Command)
    -> Result<()>
where 'store: 'rstore
{
    let inputs = if cmd.input.is_empty() {
        vec![ PathBuf::from("-") ]
    } else {
        cmd.input
    };

    let mut stats = ImportStats::default();

    let inner = || -> Result<()> {
        for input in inputs.into_iter() {
            let input = FileOrStdin::from(input);
            let mut input_reader = input.open("OpenPGP certificates")?;

            if input_reader.eof() {
                // Empty file.  Silently skip it.
                continue;
            }

            enum Type {
                Signature,
                Keyring,
                Other,
            }

            // See if it is OpenPGP data.
            let dup = Dup::with_cookie(&mut input_reader, Cookie::default());
            let mut typ = Type::Other;
            if let Ok(ppr) = PacketParser::from_buffered_reader(dup) {
                // See if it is a keyring, or a bare revocation
                // certificate.
                if let PacketParserResult::Some(ref pp) = ppr {
                    if let Packet::Signature(_) = pp.packet {
                        // Looks like a bare revocation.
                        typ = Type::Signature;
                    } else if pp.possible_keyring().is_ok() {
                        typ = Type::Keyring;
                    } else {
                        // If we have a message, then it might
                        // actually be an email with autocrypt data.
                    }
                }
            }

            let result = match typ {
                Type::Signature => {
                    import_rev(
                        &mut sq, &mut input_reader, &mut stats)
                }
                Type::Keyring => {
                    import_certs(
                        &mut sq, &mut input_reader,
                        input.path(), &mut stats)
                }
                Type::Other => {
                    autocrypt::import_certs(
                        &mut sq, &mut input_reader, &mut stats)
                }
            };

            if result.is_err() {
                if let Some(path) = input.path() {
                    result.with_context(|| {
                        format!("Reading {}", path.display())
                    })
                } else {
                    result
                }?;
            }
        }

        Ok(())
    };

    let result = inner();

    wprintln!();
    stats.print_summary(&sq)?;

    Ok(result?)
}

/// Imports certs encoded as OpenPGP keyring.
fn import_certs(sq: &mut Sq,
                source: &mut Box<dyn BufferedReader<Cookie>>,
                source_path: Option<&PathBuf>,
                stats: &mut ImportStats)
                -> Result<()>
{
    let dup = Dup::with_cookie(source, Cookie::default());
    let raw_certs = RawCertParser::from_buffered_reader(dup)?;
    let cert_store = sq.cert_store_or_else()?;

    let mut one_ok = false;
    let mut errors = Vec::new();
    for raw_cert in raw_certs {
        let cert = match raw_cert
            .and_then(|raw| LazyCert::from(raw).to_cert().cloned())
        {
            Ok(cert) => {
                one_ok = true;
                cert
            },
            Err(err) => {
                errors.push(err);
                stats.certs.inc_errors();
                continue;
            }
        };

        if cert.is_tsk() {
            let mut cmd = sq.hint(format_args!(
                "Certificate {} contains secret key material.  \
                 To import keys, do:", cert.fingerprint()))
                .sq().arg("key").arg("import");

            if let Some(file) = source_path {
                cmd = cmd.arg(file.display());
            }

            cmd.done();
        }


        let fingerprint = cert.fingerprint();
        let sanitized_userid = sq.best_userid(&cert, true);
        if let Err(err) = cert_store.update_by(Arc::new(cert.into()),
                                               stats)
        {
            wprintln!("Error importing {}, {}: {}",
                      fingerprint, sanitized_userid, err);
            stats.certs.inc_errors();
            continue;
        } else {
            wprintln!("Imported {}, {}", fingerprint, sanitized_userid);
        }
    }

    if ! one_ok {
        // This likely wasn't a keyring.
        errors.reverse();
        Err(errors.pop().ok_or_else(|| anyhow::anyhow!("no cert found"))?)
    } else {
        for err in errors {
            wprintln!("Error parsing input: {}", err);
        }
        Ok(())
    }
}

/// Import a bare revocation certificate.
fn import_rev(sq: &mut Sq,
              source: &mut Box<dyn BufferedReader<Cookie>>,
              stats: &mut ImportStats)
              -> Result<()>
{
    let dup = Dup::with_cookie(source, Cookie::default());
    let cert_store = sq.cert_store_or_else()?;

    let ppr = PacketParser::from_buffered_reader(dup)?;
    let sig = if let PacketParserResult::Some(pp) = ppr {
        let (packet, next_ppr) = pp.next()?;

        let sig = if let Packet::Signature(sig) = packet {
            sig
        } else {
            return Err(anyhow::anyhow!(
                "Not a revocation certificate: got a {}.",
                packet.tag()));
        };

        if let PacketParserResult::Some(_) = next_ppr {
            return Err(anyhow::anyhow!(
                "Not a revocation certificate: \
                 got more than one packet."));
        }

        sig
    } else {
        return Err(anyhow::anyhow!(
            "Not a bare revocation certificate."));
    };

    if sig.typ() != SignatureType::KeyRevocation {
        return Err(anyhow::anyhow!(
            "Not a revocation certificate: got a {} signature.",
            sig.typ()));
    }

    let issuers = sig.get_issuers();
    let mut missing = Vec::new();
    let mut bad = Vec::new();
    for issuer in issuers.iter() {
        let certs = if let Ok(certs)
            = sq.lookup(std::iter::once(issuer), None, false, true)
        {
            certs
        } else {
            missing.push(issuer);
            continue;
        };

        for cert in certs.into_iter() {
            if let Ok(_) = sig.clone().verify_primary_key_revocation(
                cert.primary_key().key(),
                cert.primary_key().key())
            {
                let cert = cert.insert_packets(sig.clone())?;

                let fingerprint = cert.fingerprint();
                let sanitized_userid = sq.best_userid(&cert, true);
                if let Err(err) = cert_store.update_by(Arc::new(cert.into()),
                                                       stats)
                {
                    wprintln!("Error importing revocation certificate \
                               for {}, {}: {}",
                              fingerprint, sanitized_userid, err);
                    stats.certs.inc_errors();
                    continue;
                } else {
                    wprintln!("Imported revocation certificate \
                               for {}, {}",
                              fingerprint, sanitized_userid);
                }

                return Ok(());
            } else {
                bad.push(issuer);
            }
        }
    }

    let search: Option<&KeyHandle> = if let Some(bad) = bad.first() {
        wprintln!("Appears to be a revocation for {}, \
                   but the certificate is not available.",
                  bad);
        Some(bad)
    } else if ! missing.is_empty() {
        wprintln!("Appears to be a revocation for {}, \
                   but the certificate is not available.",
                  missing.iter()
                  .map(|issuer| issuer.to_string())
                  .collect::<Vec<_>>()
                  .join(" or "));
        Some(missing[0])
    } else {
        None
    };

    if let Some(search) = search {
        sq.hint(format_args!("{}", "To search for a certificate, try:"))
            .sq().arg("network").arg("search")
            .arg(search.to_string())
            .done();
    }

    Err(anyhow::anyhow!("Failed to import revocation certificate."))
}
