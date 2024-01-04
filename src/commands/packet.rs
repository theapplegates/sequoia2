use std::{
    ffi::OsString,
    fs::File,
    io::{self, Write},
};

use anyhow::Context as _;
use terminal_size::terminal_size;

use sequoia_openpgp as openpgp;
use openpgp::{
    armor,
    packet::Tag,
    parse::{
        Parse,
        PacketParserResult,
    },
};
use openpgp::serialize::stream::Message;

use crate::Config;
use crate::Result;
use crate::cli;
use crate::cli::types::FileOrStdout;
use crate::commands;
use crate::load_keys;

pub mod dump;

pub fn dispatch(config: Config, command: cli::packet::Command)
    -> Result<()>
{
    tracer!(TRACE, "packet::dispatch");
    match command.subcommand {
        cli::packet::Subcommands::Dump(command) => {
            let mut input = command.input.open()?;
            let output_type = command.output;
            let mut output = output_type.create_unsafe(config.force)?;

            let session_key = command.session_key;
            let width = if let Some((width, _)) = terminal_size() {
                Some(width.0.into())
            } else {
                None
            };
            dump::dump(&mut input, &mut output,
                       command.mpis, command.hex,
                       session_key.as_ref(), width)?;
        },

        cli::packet::Subcommands::Decrypt(command) => {
            let mut input = command.input.open()?;
            let mut output = command.output.create_pgp_safe(
                config.force,
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

        cli::packet::Subcommands::Split(command) =>
            split(config, command)?,
        cli::packet::Subcommands::Join(command) => {
            join(config, command)?;
        }
    }

    Ok(())
}


pub fn split(_config: Config, c: cli::packet::SplitCommand) -> Result<()>
{
    let input = c.input.open()?;

    let prefix =
        // The prefix is either specified explicitly...
        c.prefix.map(|p| p.into_os_string())
        .unwrap_or_else(|| {
            // ... or we derive it from the input file...
            let mut prefix = c.input.and_then(|x| {
                // (but only use the filename)
                x.file_name().map(|f| {
                    f.to_os_string()
                })
            })
            // ... or we use a generic prefix.
                .unwrap_or_else(|| OsString::from("output"));

            // We also add a hyphen to a derived prefix.
            prefix.push("-");
            prefix
        });

    // We (ab)use the mapping feature to create byte-accurate dumps of
    // nested packets.
    let mut ppr =
        openpgp::parse::PacketParserBuilder::from_reader(input)?
        .map(true).build()?;

    fn join(pos: &[usize], delimiter: &str) -> String {
        pos.iter().map(ToString::to_string).collect::<Vec<_>>().join(delimiter)
    }

    while let PacketParserResult::Some(pp) = ppr {
        if let Some(map) = pp.map() {
            let mut filename = prefix.as_os_str().to_os_string();
            filename.push(join(pp.path(), "-"));
            filename.push(pp.packet.kind().map(|_| "").unwrap_or("Unknown-"));
            filename.push(format!("{}", pp.packet.tag()));

            let mut sink = File::create(filename)
                .context("Failed to create output file")?;

            // Write all the bytes.
            for field in map.iter() {
                sink.write_all(field.as_bytes())?;
            }
        }

        ppr = pp.recurse()?.1;
    }
    Ok(())
}

/// Joins the given files.
pub fn join(config: Config, c: cli::packet::JoinCommand) -> Result<()> {
    // Either we know what kind of armor we want to produce, or we
    // need to detect it using the first packet we see.
    let kind = c.kind.into();
    let output = c.output.for_secrets();
    let mut sink = if c.binary {
        // No need for any auto-detection.
        Some(output.create_pgp_safe(
            config.force, true, openpgp::armor::Kind::File)?)
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
                let kind = match pp.packet.tag() {
                    Tag::Signature => openpgp::armor::Kind::Signature,
                    Tag::SecretKey => openpgp::armor::Kind::SecretKey,
                    Tag::PublicKey => openpgp::armor::Kind::PublicKey,
                    Tag::PKESK | Tag::SKESK | Tag::OnePassSig =>
                        openpgp::armor::Kind::Message,
                    _ => openpgp::armor::Kind::File,
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
