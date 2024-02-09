use std::{
    collections::btree_map::{BTreeMap, Entry},
    fs::File,
    io,
    path::PathBuf,
};
use std::ops::Deref;
use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::{
    Result,
    armor,
    cert::{
        Cert,
        CertParser,
    },
    Fingerprint,
    packet::{
        UserID,
        UserAttribute,
        Key,
        Tag,
    },
    parse::Parse,
    serialize::Serialize,
};

use crate::{
    Config,
    Model,
    cli::types::FileOrStdout,
    output::KeyringListItem,
};

use crate::cli::toolbox::keyring;

pub fn dispatch(config: Config, c: keyring::Command) -> Result<()> {
    use keyring::Subcommands::*;
    match c.subcommand {
        Filter(command) => {
            let any_uid_predicates =
                ! command.userid.is_empty()
                || !command.name.is_empty()
                || !command.email.is_empty()
                || !command.domain.is_empty();
            let uid_predicate = |uid: &UserID| {
                let mut keep = false;

                for userid in &command.userid {
                    keep |= uid.value() == userid.as_bytes();
                }

                for name in &command.name {
                    keep |= uid
                        .name2().unwrap_or(None)
                        .map(|n| n == name)
                        .unwrap_or(false);
                }

                for email in &command.email {
                    keep |= uid
                        .email2().unwrap_or(None)
                        .map(|n| n == email)
                        .unwrap_or(false);
                }

                for domain in &command.domain {
                    keep |= uid
                        .email2().unwrap_or(None)
                        .map(|n| n.ends_with(&format!("@{}", domain)))
                        .unwrap_or(false);
                }

                keep
            };

            let any_ua_predicates = false;
            let ua_predicate = |_ua: &UserAttribute| false;

            let any_key_predicates = ! command.handle.is_empty();
            let key_predicate = |key: &Key<_, _>| {
                let mut keep = false;

                for handle in &command.handle {
                    keep |= handle.aliases(key.key_handle());
                }

                keep
            };

            let filter_fn = |c: Cert| -> Option<Cert> {
                if ! (any_uid_predicates
                      || any_ua_predicates
                      || any_key_predicates) {
                    // If there are no filters, pass it through.
                    Some(c)
                } else if ! (c.userids().any(|c| uid_predicate(&c))
                             || c.user_attributes().any(|c| ua_predicate(&c))
                             || c.keys().any(|c| key_predicate(c.key()))) {
                    None
                } else if command.prune_certs {
                    let c = c
                        .retain_userids(|c| {
                            ! any_uid_predicates || uid_predicate(&c)
                        })
                        .retain_user_attributes(|c| {
                            ! any_ua_predicates || ua_predicate(&c)
                        })
                        .retain_subkeys(|c| {
                            ! any_key_predicates
                                || key_predicate(c.key().role_as_unspecified())
                        });
                    if c.userids().count() == 0
                        && c.user_attributes().count() == 0
                        && c.keys().subkeys().count() == 0
                    {
                        // We stripped all components, omit this cert.
                        None
                    } else {
                        Some(c)
                    }
                } else {
                    Some(c)
                }
            };

            filter(&config, command.input, command.output, filter_fn,
                   command.binary, command.to_certificate)
        },
        Merge(c) =>
            merge(&config, c.input, c.output, c.binary),
        List(c) => {
            let mut input = c.input.open()?;
            list(config, &mut input, c.all_userids)
        },
        Split(c) => {
            let mut input = c.input.open()?;
            let prefix =
            // The prefix is either specified explicitly...
                c.prefix.unwrap_or(
                    // ... or we derive it from the input file...
                    c.input.and_then(|x| {
                        // (but only use the filename)
                        x.file_name().map(|f|
                            String::from(f.to_string_lossy())
                        )
                    })
                    // ... or we use a generic prefix...
                        .unwrap_or_else(|| String::from("output"))
                    // ... finally, add a hyphen to the derived prefix.
                        + "-");
            split(&mut input, &prefix, c.binary)
        },
    }
}

/// Joins certificates and keyrings into a keyring, applying a filter.
fn filter<F>(config: &Config, inputs: Vec<PathBuf>, output: FileOrStdout,
             mut filter: F,
             binary: bool,
             to_certificate: bool)
             -> Result<()>
    where F: FnMut(Cert) -> Option<Cert>,
{
    let mut certs = Vec::new();

    if !inputs.is_empty() {
        for name in inputs {
            for cert in CertParser::from_file(name.deref())? {
                let cert = cert.context(
                    format!("Malformed certificate in keyring {:?}", name.display()))?;
                if let Some(cert) = filter(cert) {
                    certs.push(cert);
                }
            }
        }
    } else {
        for cert in CertParser::from_reader(io::stdin())? {
            let cert = cert.context("Malformed certificate in keyring")?;
            if let Some(cert) = filter(cert) {
                certs.push(cert);
            }
        }
    }

    let mut output = output.for_secrets().create_pgp_safe(
        config.force,
        binary,
        if ! to_certificate && certs.iter().any(|c| c.is_tsk()) {
            armor::Kind::SecretKey
        } else {
            armor::Kind::PublicKey
        },
    )?;

    for cert in certs {
        if let Some(cert) = filter(cert) {
            if to_certificate {
                cert.serialize(&mut output)?;
            } else {
                cert.as_tsk().serialize(&mut output)?;
            }
        }
    }
    output.finalize()?;

    Ok(())
}

/// Lists certs in a keyring.
fn list(config: Config,
        input: &mut (dyn io::Read + Sync + Send),
        list_all_uids: bool)
        -> Result<()>
{
    let mut certs = vec![];
    let iter = CertParser::from_reader(input)?
        .map(|item| KeyringListItem::from_cert_with_config(item, &config));
    for item in iter {
        certs.push(item);
    }
    let list = Model::keyring_list(config.output_version, certs, list_all_uids)?;
    list.write(config.output_format, &mut std::io::stdout())?;
    Ok(())
}

/// Splits a keyring into individual certs.
fn split(input: &mut (dyn io::Read + Sync + Send), prefix: &str, binary: bool)
         -> Result<()> {
    for (i, cert) in CertParser::from_reader(input)?.enumerate() {
        let (filename, cert) = match cert {
            Ok(cert) => {
                let filename = format!(
                    "{}{}-{:X}",
                    prefix,
                    i,
                    cert.fingerprint());
                (filename, Ok(cert))
            },
            Err(mut e) => if let Some(openpgp::Error::UnsupportedCert2(m, p)) =
                e.downcast_mut::<openpgp::Error>()
            {
                // We didn't understand the cert.  But, we can still
                // write it out!
                let filename = format!(
                    "{}{}-{}",
                    prefix,
                    i,
                    to_filename_fragment(m).unwrap_or_else(|| "unknown".to_string()));
                (filename, Err(std::mem::take(p)))
            } else {
                return Err(e.context("Malformed certificate in keyring"));
            },
        };

        // Try to be more helpful by including the first userid in the
        // filename.
        let mut sink = if let Some(f) = cert.as_ref().ok()
            .and_then(|cert| cert.userids().next())
            .and_then(|uid| uid.email2().unwrap_or(None).map(|e| e.to_string()))
            .and_then(to_filename_fragment)
        {
            let filename_email = format!("{}-{}", filename, f);
            if let Ok(s) = File::create(filename_email) {
                s
            } else {
                // Degrade gracefully in case our sanitization
                // produced an invalid filename on this system.
                File::create(&filename)
                    .context(format!("Writing cert to {:?} failed", filename))?
            }
        } else {
            File::create(&filename)
                .context(format!("Writing cert to {:?} failed", filename))?
        };

        if binary {
            match cert {
                Ok(cert) => cert.as_tsk().serialize(&mut sink)?,
                Err(packets) => for p in packets {
                    p.serialize(&mut sink)?;
                },
            }
        } else {
            let is_tsk = match &cert {
                Ok(cert) => cert.is_tsk(),
                Err(packets) => packets.iter().any(
                    |p| p.tag() == Tag::SecretKey || p.tag() == Tag::SecretSubkey),
            };

            use sequoia_openpgp::serialize::stream::{Message, Armorer};
            let message = Message::new(sink);
            let mut message = Armorer::new(message)
                .kind(if is_tsk {
                    armor::Kind::SecretKey
                } else {
                    armor::Kind::PublicKey
                })
                .build()?;
            match cert {
                Ok(cert) => cert.as_tsk().serialize(&mut message)?,
                Err(packets) => for p in packets {
                    p.serialize(&mut message)?;
                },
            }
            message.finalize()?;
        }
    }
    Ok(())
}

/// Merge multiple keyrings.
fn merge(config: &Config, inputs: Vec<PathBuf>, output: FileOrStdout,
         binary: bool)
         -> Result<()>
{
    let mut certs: BTreeMap<Fingerprint, Option<Cert>> = BTreeMap::new();

    if !inputs.is_empty() {
        for name in inputs {
            for cert in CertParser::from_file(&name)? {
                let cert = cert.context(
                    format!("Malformed certificate in keyring {:?}", name))?;
                match certs.entry(cert.fingerprint()) {
                    e @ Entry::Vacant(_) => {
                        e.or_insert(Some(cert));
                    }
                    Entry::Occupied(mut e) => {
                        let e = e.get_mut();
                        let curr = e.take().unwrap();
                        *e = Some(curr.merge_public_and_secret(cert)
                            .expect("Same certificate"));
                    }
                }
            }
        }
    } else {
        for cert in CertParser::from_reader(io::stdin())? {
            let cert = cert.context("Malformed certificate in keyring")?;
            match certs.entry(cert.fingerprint()) {
                e @ Entry::Vacant(_) => {
                    e.or_insert(Some(cert));
                }
                Entry::Occupied(mut e) => {
                    let e = e.get_mut();
                    let curr = e.take().unwrap();
                    *e = Some(curr.merge_public_and_secret(cert)
                              .expect("Same certificate"));
                }
            }
        }
    }

    let mut output = output.for_secrets().create_pgp_safe(
        config.force,
        binary,
        if certs.values().any(|c| c.as_ref().map(Cert::is_tsk).unwrap_or(false))
        {
            armor::Kind::SecretKey
        } else {
            armor::Kind::PublicKey
        },
    )?;

    for cert in certs.values().filter_map(|v| v.as_ref()) {
        cert.as_tsk().serialize(&mut output)?;
    }
    output.finalize()?;

    Ok(())
}

/// Sanitizes a string to a safe filename fragment.
fn to_filename_fragment<S: AsRef<str>>(s: S) -> Option<String> {
    let mut r = String::with_capacity(s.as_ref().len());

    s.as_ref().chars().filter_map(|c| match c {
        '/' | ':' | '\\' => None,
        c if c.is_ascii_whitespace() => None,
        c if c.is_ascii() => Some(c),
        _ => None,
    }).for_each(|c| r.push(c));

    if !r.is_empty() {
        Some(r)
    } else {
        None
    }
}
