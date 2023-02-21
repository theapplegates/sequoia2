#![doc(html_favicon_url = "https://docs.sequoia-pgp.org/favicon.png")]
#![doc(html_logo_url = "https://docs.sequoia-pgp.org/logo.svg")]

#![doc = include_str!(concat!(env!("OUT_DIR"), "/sq-usage.md"))]

use anyhow::Context as _;
use std::fs::OpenOptions;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use chrono::{DateTime, offset::Utc};
use itertools::Itertools;

use buffered_reader::{BufferedReader, Dup, File, Generic, Limitor};
use sequoia_openpgp as openpgp;

use openpgp::{
    Result,
};
use openpgp::{armor, Cert};
use openpgp::crypto::Password;
use openpgp::packet::prelude::*;
use openpgp::parse::{Parse, PacketParser, PacketParserResult};
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::packet::signature::subpacket::NotationDataFlags;
use openpgp::serialize::{Serialize, stream::{Message, Armorer}};
use openpgp::cert::prelude::*;
use openpgp::policy::StandardPolicy as P;

use clap::FromArgMatches;
use crate::sq_cli::packet;
use sq_cli::SqSubcommands;

mod sq_cli;
mod man;
mod commands;
pub mod output;
pub use output::{wkd::WkdUrlVariant, Model, OutputFormat, OutputVersion};


fn open_or_stdin(f: Option<&str>)
                 -> Result<Box<dyn BufferedReader<()>>> {
    match f {
        Some(f) => Ok(Box::new(File::open(f)
                               .context("Failed to open input file")?)),
        None => Ok(Box::new(Generic::new(io::stdin(), None))),
    }
}

const SECONDS_IN_DAY : u64 = 24 * 60 * 60;
const SECONDS_IN_YEAR : u64 =
    // Average number of days in a year.
    (365.2422222 * SECONDS_IN_DAY as f64) as u64;

fn parse_duration(expiry: &str) -> Result<Duration> {
    let mut expiry = expiry.chars().peekable();

    let _ = expiry.by_ref()
        .peeking_take_while(|c| c.is_whitespace())
        .for_each(|_| ());
    let digits = expiry.by_ref()
        .peeking_take_while(|c| {
            *c == '+' || *c == '-' || c.is_digit(10)
        }).collect::<String>();
    let _ = expiry.by_ref()
        .peeking_take_while(|c| c.is_whitespace())
        .for_each(|_| ());
    let suffix = expiry.next();
    let _ = expiry.by_ref()
        .peeking_take_while(|c| c.is_whitespace())
        .for_each(|_| ());
    let junk = expiry.collect::<String>();

    if digits.is_empty() {
        return Err(anyhow::anyhow!(
            "--expiry: missing count \
             (try: '2y' for 2 years)"));
    }

    let count = match digits.parse::<i32>() {
        Ok(count) if count < 0 =>
            return Err(anyhow::anyhow!(
                "--expiry: Expiration can't be in the past")),
        Ok(count) => count as u64,
        Err(err) =>
            return Err(err).context("--expiry: count is out of range"),
    };

    let factor = match suffix {
        Some('y') | Some('Y') => SECONDS_IN_YEAR,
        Some('m') | Some('M') => SECONDS_IN_YEAR / 12,
        Some('w') | Some('W') => 7 * SECONDS_IN_DAY,
        Some('d') | Some('D') => SECONDS_IN_DAY,
        Some('s') | Some('S') => 1,
        None =>
            return Err(anyhow::anyhow!(
                "--expiry: missing suffix \
                 (try: '{}y', '{}m', '{}w', '{}d' or '{}s' instead)",
                digits, digits, digits, digits, digits)),
        Some(suffix) =>
            return Err(anyhow::anyhow!(
                "--expiry: invalid suffix '{}' \
                 (try: '{}y', '{}m', '{}w', '{}d' or '{}s' instead)",
                suffix, digits, digits, digits, digits, digits)),
    };

    if !junk.is_empty() {
        return Err(anyhow::anyhow!(
            "--expiry: contains trailing junk ('{:?}') \
             (try: '{}{}')",
            junk, count, factor));
    }

    Ok(Duration::new(count * factor, 0))
}

/// Loads one TSK from every given file.
fn load_keys<'a, I>(files: I) -> openpgp::Result<Vec<Cert>>
    where I: Iterator<Item=&'a str>
{
    let mut certs = vec![];
    for f in files {
        let cert = Cert::from_file(f)
            .context(format!("Failed to load key from file {:?}", f))?;
        if ! cert.is_tsk() {
            return Err(anyhow::anyhow!(
                "Cert in file {:?} does not contain secret keys", f));
        }
        certs.push(cert);
    }
    Ok(certs)
}

/// Loads one or more certs from every given file.
fn load_certs<'a, I>(files: I) -> openpgp::Result<Vec<Cert>>
    where I: Iterator<Item=&'a str>
{
    let mut certs = vec![];
    for f in files {
        for maybe_cert in CertParser::from_file(f)
            .context(format!("Failed to load certs from file {:?}", f))?
        {
            certs.push(maybe_cert.context(
                format!("A cert from file {:?} is bad", f)
            )?);
        }
    }
    Ok(certs)
}

/// Serializes a keyring, adding descriptive headers if armored.
#[allow(dead_code)]
fn serialize_keyring(mut output: &mut dyn io::Write, certs: &[Cert], binary: bool)
                     -> openpgp::Result<()> {
    // Handle the easy options first.  No armor no cry:
    if binary {
        for cert in certs {
            cert.serialize(&mut output)?;
        }
        return Ok(());
    }

    // Just one Cert?  Ez:
    if certs.len() == 1 {
        return certs[0].armored().serialize(&mut output);
    }

    // Otherwise, collect the headers first:
    let mut headers = Vec::new();
    for (i, cert) in certs.iter().enumerate() {
        headers.push(format!("Key #{}", i));
        headers.append(&mut cert.armor_headers());
    }

    let headers: Vec<_> = headers.iter()
        .map(|value| ("Comment", value.as_str()))
        .collect();
    let mut output = armor::Writer::with_headers(&mut output,
                                                 armor::Kind::PublicKey,
                                                 headers)?;
    for cert in certs {
        cert.serialize(&mut output)?;
    }
    output.finalize()?;
    Ok(())
}

/// How much data to look at when detecting armor kinds.
const ARMOR_DETECTION_LIMIT: u64 = 1 << 24;

/// Peeks at the first packet to guess the type.
///
/// Returns the given reader unchanged.  If the detection fails,
/// armor::Kind::File is returned as safe default.
fn detect_armor_kind(
    input: Box<dyn BufferedReader<()>>,
) -> (Box<dyn BufferedReader<()>>, armor::Kind) {
    let mut dup =
        Limitor::new(Dup::new(input), ARMOR_DETECTION_LIMIT).as_boxed();
    let kind = match PacketParser::from_reader(&mut dup) {
        Ok(PacketParserResult::Some(pp)) => match pp.next() {
            Ok((Packet::Signature(_), _)) => armor::Kind::Signature,
            Ok((Packet::SecretKey(_), _)) => armor::Kind::SecretKey,
            Ok((Packet::PublicKey(_), _)) => armor::Kind::PublicKey,
            Ok((Packet::PKESK(_), _)) => armor::Kind::Message,
            Ok((Packet::SKESK(_), _)) => armor::Kind::Message,
            _ => armor::Kind::File,
        },
        _ => armor::Kind::File,
    };
    (dup.into_inner().unwrap().into_inner().unwrap(), kind)
}

// Decrypts a key, if possible.
//
// The passwords in `passwords` are tried first.  If the key can't be
// decrypted using those, the user is prompted.  If a valid password
// is entered, it is added to `passwords`.
fn decrypt_key<R>(key: Key<key::SecretParts, R>, passwords: &mut Vec<String>)
    -> Result<Key<key::SecretParts, R>>
    where R: key::KeyRole + Clone
{
    let key = key.parts_as_secret()?;
    match key.secret() {
        SecretKeyMaterial::Unencrypted(_) => {
            Ok(key.clone())
        }
        SecretKeyMaterial::Encrypted(_) => {
            for p in passwords.iter() {
                if let Ok(key)
                    = key.clone().decrypt_secret(&Password::from(&p[..]))
                {
                    return Ok(key);
                }
            }

            let mut first = true;
            loop {
                // Prompt the user.
                match rpassword::prompt_password(&format!(
                    "{}Enter password to unlock {} (blank to skip): ",
                    if first { "" } else { "Invalid password. " },
                    key.keyid().to_hex()
                )) {
                    Ok(p) => {
                        first = false;
                        if p.is_empty() {
                            // Give up.
                            break;
                        }

                        if let Ok(key) = key
                            .clone()
                            .decrypt_secret(&Password::from(&p[..]))
                        {
                            passwords.push(p);
                            return Ok(key);
                        }
                    }
                    Err(err) => {
                        eprintln!("While reading password: {}", err);
                        break;
                    }
                }
            }

            Err(anyhow::anyhow!("Key {}: Unable to decrypt secret key material",
                                key.keyid().to_hex()))
        }
    }
}

/// Prints a warning if the user supplied "help" or "-help" to an
/// positional argument.
///
/// This should be used wherever a positional argument is followed by
/// an optional positional argument.
#[allow(dead_code)]
fn help_warning(arg: &str) {
    if arg == "help" {
        eprintln!("Warning: \"help\" is not a subcommand here.  \
                   Did you mean --help?");
    }
}

/// Prints a warning if sq is run in a non-interactive setting without
/// a terminal.
///
/// Detecting non-interactive use is done using a heuristic.
fn emit_unstable_cli_warning() {
    if term_size::dimensions_stdout().is_some() {
        // stdout is connected to a terminal, assume interactive use.
        return;
    }

    // For bash shells, we can use a very simple heuristic.  We simply
    // look at whether the COLUMNS variable is defined in our
    // environment.
    if std::env::var_os("COLUMNS").is_some() {
        // Heuristic detected interactive use.
        return;
    }

    eprintln!("\nWARNING: sq does not have a stable CLI interface.  \
               Use with caution in scripts.\n");
}

#[derive(Clone)]
pub struct Config<'a> {
    force: bool,
    output_format: OutputFormat,
    output_version: Option<OutputVersion>,
    policy: P<'a>,
    /// Have we emitted the warning yet?
    unstable_cli_warning_emitted: bool,
}

impl Config<'_> {
    /// Opens the file (or stdout) for writing data that is safe for
    /// non-interactive use.
    ///
    /// This is suitable for any kind of OpenPGP data, or decrypted or
    /// authenticated payloads.
    fn create_or_stdout_safe(&self, f: Option<&str>)
                             -> Result<Box<dyn io::Write + Sync + Send>> {
        Config::create_or_stdout(f, self.force)
    }

    /// Opens the file (or stdout) for writing data that is NOT safe
    /// for non-interactive use.
    ///
    /// If our heuristic detects non-interactive use, we will emit a
    /// warning.
    fn create_or_stdout_unsafe(&mut self, f: Option<&str>)
                               -> Result<Box<dyn io::Write + Sync + Send>> {
        if ! self.unstable_cli_warning_emitted {
            emit_unstable_cli_warning();
            self.unstable_cli_warning_emitted = true;
        }
        Config::create_or_stdout(f, self.force)
    }

    /// Opens the file (or stdout) for writing data that is safe for
    /// non-interactive use because it is an OpenPGP data stream.
    fn create_or_stdout_pgp<'a>(&self, f: Option<&str>,
                                binary: bool, kind: armor::Kind)
                                -> Result<Message<'a>> {
        let sink = self.create_or_stdout_safe(f)?;
        let mut message = Message::new(sink);
        if ! binary {
            message = Armorer::new(message).kind(kind).build()?;
        }
        Ok(message)
    }

    /// Helper function, do not use directly. Instead, use create_or_stdout_safe
    /// or create_or_stdout_unsafe.
    fn create_or_stdout(
        f: Option<&str>,
        force: bool,
    ) -> Result<Box<dyn io::Write + Sync + Send>> {
        match f {
            None => Ok(Box::new(io::stdout())),
            Some(p) if p == "-" => Ok(Box::new(io::stdout())),
            Some(f) => {
                let p = Path::new(f);
                if !p.exists() || force {
                    Ok(Box::new(
                        OpenOptions::new()
                            .write(true)
                            .truncate(true)
                            .create(true)
                            .open(f)
                            .context("Failed to create output file")?,
                    ))
                } else {
                    Err(anyhow::anyhow!(format!(
                        "File {:?} exists, use \"sq --force ...\" to \
                                overwrite",
                        p
                    )))
                }
            }
        }
    }
}

// TODO: Use `derive`d command structs. No more values_of
// TODO: Handling (and cli position) of global arguments
fn main() -> Result<()> {
    if let Ok(dirname) = std::env::var("SQ_MAN") {
        let dirname = PathBuf::from(dirname);
        if !dirname.exists() {
            std::fs::create_dir(&dirname)?;
        }
        for man in man::manpages(&sq_cli::build()) {
            std::fs::write(dirname.join(man.filename()), man.troff_source())?;
        }
        return Ok(())
    }

    let policy = &mut P::new();

    let c = sq_cli::SqCommand::from_arg_matches(&sq_cli::build().get_matches())?;

    let known_notations = c.known_notation
        .iter()
        .map(|n| n.as_str())
        .collect::<Vec<&str>>();
    policy.good_critical_notations(&known_notations);

    let force = c.force;
    let output_format = OutputFormat::from_str(&c.output_format)?;
    let output_version = if let Some(v) = c.output_version {
        Some(OutputVersion::from_str(&v)?)
    } else {
        None
    };

    let mut config = Config {
        force,
        output_format,
        output_version,
        policy: policy.clone(),
        unstable_cli_warning_emitted: false,
    };

    match c.subcommand {
        SqSubcommands::OutputVersions(command) => {
            if command.default {
                println!("{}", output::DEFAULT_OUTPUT_VERSION);
            } else {
                for v in output::OUTPUT_VERSIONS {
                    println!("{}", v);
                }
            }
        }

        SqSubcommands::Decrypt(command) => {

            let mut input = open_or_stdin(command.io.input.as_deref())?;
            let mut output =
                config.create_or_stdout_safe(command.io.output.as_deref())?;

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
            // TODO: should this be load_keys?
            let secrets =
                load_certs(command.secret_key_file.iter().map(|s| s.as_ref()))?;
            let private_key_store = command.private_key_store;
            let session_keys = command.session_key;
            commands::decrypt(config, private_key_store.as_deref(),
                              &mut input, &mut output,
                              signatures, certs, secrets,
                              command.dump_session_key,
                              session_keys,
                              command.dump, command.hex)?;
        },
        SqSubcommands::Encrypt(command) => {
            let recipients = load_certs(
                command.recipients_cert_file.iter().map(|s| s.as_ref()),
            )?;
            let mut input = open_or_stdin(command.io.input.as_deref())?;

            let output = config.create_or_stdout_pgp(
                command.io.output.as_deref(),
                command.binary,
                armor::Kind::Message,
            )?;

            let additional_secrets =
                load_certs(command.signer_key_file.iter().map(|s| s.as_ref()))?;

            let time = command.time.map(|t| t.time.into());
            let private_key_store = command.private_key_store.as_deref();
            commands::encrypt(commands::EncryptOpts {
                policy,
                private_key_store,
                input: &mut input,
                message: output,
                npasswords: command.symmetric,
                recipients: &recipients,
                signers: additional_secrets,
                mode: command.mode,
                compression: command.compression,
                time,
                use_expired_subkey: command.use_expired_subkey,
            })?;
        },
        SqSubcommands::Sign(command) => {
            let mut input = open_or_stdin(command.io.input.as_deref())?;
            let output = command.io.output.as_deref();
            let detached = command.detached;
            let binary = command.binary;
            let append = command.append;
            let notarize = command.notarize;
            let private_key_store = command.private_key_store.as_deref();
            let secrets =
                load_certs(command.secret_key_file.iter().map(|s| s.as_ref()))?;
            let time = command.time.map(|t| t.time.into());

            let notations = parse_notations(command.notation.unwrap_or_default())?;

            if let Some(merge) = command.merge {
                let output = config.create_or_stdout_pgp(output, binary,
                                                         armor::Kind::Message)?;
                let mut input2 = open_or_stdin(Some(&merge))?;
                commands::merge_signatures(&mut input, &mut input2, output)?;
            } else if command.clearsign {
                let output = config.create_or_stdout_safe(output)?;
                commands::sign::clearsign(config, private_key_store, input, output, secrets,
                                          time, &notations)?;
            } else {
                commands::sign(commands::sign::SignOpts {
                    config,
                    private_key_store,
                    input: &mut input,
                    output_path: output,
                    secrets,
                    detached,
                    binary,
                    append,
                    notarize,
                    time,
                    notations: &notations
                })?;
            }
        },
        SqSubcommands::Verify(command) => {
            // TODO: Fix interface of open_or_stdin, create_or_stdout_safe, etc.
            let mut input = open_or_stdin(command.io.input.as_deref())?;
            let mut output =
                config.create_or_stdout_safe(command.io.output.as_deref())?;
            let mut detached = if let Some(f) = command.detached {
                Some(File::open(f)?)
            } else {
                None
            };
            let signatures = command.signatures;
            // TODO ugly adaptation to load_certs' signature, fix later
            let certs = load_certs(command.sender_cert_file.iter().map(|s| s.as_ref()))?;
            commands::verify(config, &mut input,
                             detached.as_mut().map(|r| r as &mut (dyn io::Read + Sync + Send)),
                             &mut output, signatures, certs)?;
        },

        // TODO: Extract body to commands/armor.rs
        SqSubcommands::Armor(command) => {
            let input = open_or_stdin(command.io.input.as_deref())?;
            let mut want_kind: Option<armor::Kind> = command.kind.into();

            // Peek at the data.  If it looks like it is armored
            // data, avoid armoring it again.
            let mut dup = Limitor::new(Dup::new(input), ARMOR_DETECTION_LIMIT);
            let (already_armored, have_kind) = {
                let mut reader =
                    armor::Reader::from_reader(&mut dup,
                                       armor::ReaderMode::Tolerant(None));
                (reader.data(8).is_ok(), reader.kind())
            };
            let mut input =
                dup.as_boxed().into_inner().unwrap().into_inner().unwrap();

            if already_armored
                && (want_kind.is_none() || want_kind == have_kind)
            {
                // It is already armored and has the correct kind.
                let mut output =
                    config.create_or_stdout_safe(command.io.output.as_deref())?;
                io::copy(&mut input, &mut output)?;
                return Ok(());
            }

            if want_kind.is_none() {
                let (tmp, kind) = detect_armor_kind(input);
                input = tmp;
                want_kind = Some(kind);
            }

            // At this point, want_kind is determined.
            let want_kind = want_kind.expect("given or detected");

            let mut output =
                config.create_or_stdout_pgp(command.io.output.as_deref(),
                                            false, want_kind)?;

            if already_armored {
                // Dearmor and copy to change the type.
                let mut reader =
                    armor::Reader::from_reader(input,
                                       armor::ReaderMode::Tolerant(None));
                io::copy(&mut reader, &mut output)?;
            } else {
                io::copy(&mut input, &mut output)?;
            }
            output.finalize()?;
        },
        SqSubcommands::Dearmor(command) => {
            let mut input = open_or_stdin(command.io.input.as_deref())?;
            let mut output =
                config.create_or_stdout_safe(command.io.output.as_deref())?;
            let mut filter = armor::Reader::from_reader(&mut input, None);
            io::copy(&mut filter, &mut output)?;
        },
        #[cfg(feature = "autocrypt")]
        SqSubcommands::Autocrypt(command) => {
            commands::autocrypt::dispatch(config, &command)?;
        },
        SqSubcommands::Inspect(command) => {
            // sq inspect does not have --output, but commands::inspect does.
            // Work around this mismatch by always creating a stdout output.
            let mut output = config.create_or_stdout_unsafe(None)?;
            commands::inspect(command, policy, &mut output)?;
        },

        SqSubcommands::Keyring(command) => {
            commands::keyring::dispatch(config, command)?
        },

        SqSubcommands::Packet(command) => match command.subcommand {
            packet::Subcommands::Dump(command) => {
                let mut input = open_or_stdin(command.io.input.as_deref())?;
                let mut output = config.create_or_stdout_unsafe(
                    command.io.output.as_deref(),
                )?;

                let session_key = command.session_key;
                let width = term_size::dimensions_stdout().map(|(w, _)| w);
                commands::dump(&mut input, &mut output,
                               command.mpis, command.hex,
                               session_key.as_ref(), width)?;
            },

            packet::Subcommands::Decrypt(command) => {
                let mut input = open_or_stdin(command.io.input.as_deref())?;
                let mut output = config.create_or_stdout_pgp(
                    command.io.output.as_deref(),
                    command.binary,
                    armor::Kind::Message,
                )?;

                let secrets =
                    load_keys(command.secret_key_file.iter().map(|s| s.as_ref()))?;
                let session_keys = command.session_key;
                commands::decrypt::decrypt_unwrap(
                    config,
                    &mut input, &mut output,
                    secrets,
                    session_keys,
                    command.dump_session_key)?;
                output.finalize()?;
            },

            packet::Subcommands::Split(command) => {
                let mut input = open_or_stdin(command.input.as_deref())?;
                let prefix =
                // The prefix is either specified explicitly...
                    command.prefix.unwrap_or(
                        // ... or we derive it from the input file...
                        command.input.and_then(|i| {
                            let p = PathBuf::from(i);
                            // (but only use the filename)
                            p.file_name().map(|f| String::from(f.to_string_lossy()))
                        })
                        // ... or we use a generic prefix...
                            .unwrap_or_else(|| String::from("output"))
                        // ... finally, add a hyphen to the derived prefix.
                            + "-");
                commands::split(&mut input, &prefix)?;
            },
            packet::Subcommands::Join(command) => commands::join(config, command)?,
        },

        SqSubcommands::Keyserver(command) => {
            commands::net::dispatch_keyserver(config, command)?
        }

        SqSubcommands::Key(command) => {
            commands::key::dispatch(config, command)?
        }

        SqSubcommands::Revoke(command) => {
            commands::revoke::dispatch(config, command)?
        }

        SqSubcommands::Wkd(command) => {
            commands::net::dispatch_wkd(config, command)?
        }

        SqSubcommands::Dane(command) => {
            commands::net::dispatch_dane(config, command)?
        }

        SqSubcommands::Certify(command) => {
            commands::certify::certify(config, command)?
        }
    }

    Ok(())
}

fn parse_notations(n: Vec<String>) -> Result<Vec<(bool, NotationData)>> {

    // TODO I'm not sure what to do about this requirement.  Setting
    // number_of_values = 2 for the argument already makes clap bail if the
    // length of the vec is odd.
    assert_eq!(n.len() % 2, 0);

    // Each --notation takes two values.  Iterate over them in chunks of 2.
    let notations: Vec<(bool, NotationData)> = n
        .chunks(2)
        .map(|arg_pair| {
            let name = &arg_pair[0];
            let value = &arg_pair[1];

            let (critical, name) = match name.strip_prefix('!') {
                Some(name) => (true, name),
                None => (false, name.as_str()),
            };

            let notation_data = NotationData::new(
                name,
                value,
                NotationDataFlags::empty().set_human_readable(),
            );
            (critical, notation_data)
        })
        .collect();

    Ok(notations)
}

// TODO: Replace all uses with CliTime argument type
/// Parses the given string depicting a ISO 8601 timestamp.
fn parse_iso8601(s: &str, pad_date_with: chrono::NaiveTime)
                 -> Result<DateTime<Utc>>
{
    // If you modify this function this function, synchronize the
    // changes with the copy in sqv.rs!
    for f in &[
        "%Y-%m-%dT%H:%M:%S%#z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M%#z",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%dT%H%#z",
        "%Y-%m-%dT%H",
        "%Y%m%dT%H%M%S%#z",
        "%Y%m%dT%H%M%S",
        "%Y%m%dT%H%M%#z",
        "%Y%m%dT%H%M",
        "%Y%m%dT%H%#z",
        "%Y%m%dT%H",
    ] {
        if f.ends_with("%#z") {
            if let Ok(d) = DateTime::parse_from_str(s, *f) {
                return Ok(d.into());
            }
        } else if let Ok(d) = chrono::NaiveDateTime::parse_from_str(s, *f) {
            return Ok(DateTime::from_utc(d, Utc));
        }
    }
    for f in &[
        "%Y-%m-%d",
        "%Y-%m",
        "%Y-%j",
        "%Y%m%d",
        "%Y%m",
        "%Y%j",
        "%Y",
    ] {
        if let Ok(d) = chrono::NaiveDate::parse_from_str(s, *f) {
            return Ok(DateTime::from_utc(d.and_time(pad_date_with), Utc));
        }
    }
    Err(anyhow::anyhow!("Malformed ISO8601 timestamp: {}", s))
}

#[test]
fn test_parse_iso8601() {
    let z = chrono::NaiveTime::from_hms_opt(0, 0, 0).unwrap();
    parse_iso8601("2017-03-04T13:25:35Z", z).unwrap();
    parse_iso8601("2017-03-04T13:25:35+08:30", z).unwrap();
    parse_iso8601("2017-03-04T13:25:35", z).unwrap();
    parse_iso8601("2017-03-04T13:25Z", z).unwrap();
    parse_iso8601("2017-03-04T13:25", z).unwrap();
    // parse_iso8601("2017-03-04T13Z", z).unwrap(); // XXX: chrono doesn't like
    // parse_iso8601("2017-03-04T13", z).unwrap(); // ditto
    parse_iso8601("2017-03-04", z).unwrap();
    // parse_iso8601("2017-03", z).unwrap(); // ditto
    parse_iso8601("2017-031", z).unwrap();
    parse_iso8601("20170304T132535Z", z).unwrap();
    parse_iso8601("20170304T132535+0830", z).unwrap();
    parse_iso8601("20170304T132535", z).unwrap();
    parse_iso8601("20170304T1325Z", z).unwrap();
    parse_iso8601("20170304T1325", z).unwrap();
    // parse_iso8601("20170304T13Z", z).unwrap(); // ditto
    // parse_iso8601("20170304T13", z).unwrap(); // ditto
    parse_iso8601("20170304", z).unwrap();
    // parse_iso8601("201703", z).unwrap(); // ditto
    parse_iso8601("2017031", z).unwrap();
    // parse_iso8601("2017", z).unwrap(); // ditto
}

/// Prints the error and causes, if any.
pub fn print_error_chain(err: &anyhow::Error) {
    eprintln!("           {}", err);
    err.chain().skip(1).for_each(|cause| eprintln!("  because: {}", cause));
}
