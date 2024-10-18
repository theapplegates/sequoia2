use std::{
    fs::File,
    io::{self, Write},
};

use anyhow::Context as _;
use terminal_size::terminal_size;

use sequoia_openpgp as openpgp;
use openpgp::{
    armor::{
        Kind,
        ReaderMode,
        Writer,
    },
    packet::{Packet, Tag},
    parse::{
        Dearmor,
        Parse,
        PacketParserBuilder,
        PacketParserResult,
    },
};
use openpgp::serialize::stream::Message;

use crate::Sq;
use crate::Convert;
use crate::Result;
use crate::cli::toolbox::packet::{
    Command,
    Subcommands,
    SplitCommand,
    JoinCommand,
};
use crate::cli::types::FileOrStdout;
use crate::commands;
use crate::load_keys;

pub mod dump;

pub fn dispatch(sq: Sq, command: Command)
    -> Result<()>
{
    tracer!(TRACE, "packet::dispatch");
    match command.subcommand {
        Subcommands::Dump(command) => {
            let mut input = command.input.open()?;
            let output_type = command.output;
            let mut output = output_type.create_unsafe(&sq)?;

            let width = if let Some((width, _)) = terminal_size() {
                Some(width.0.into())
            } else {
                None
            };
            let secrets =
                load_keys(command.recipient_file.iter())?;
            dump::dump(&sq,
                       secrets,
                       &mut input, &mut output,
                       command.mpis, command.hex,
                       command.session_key, width)?;
        },

        Subcommands::Decrypt(command) => {
            let mut input = command.input.open()?;
            let mut output = command.output.create_pgp_safe(
                &sq,
                command.binary,
                openpgp::armor::Kind::Message,
            )?;

            let secrets =
                load_keys(command.secret_key_file.iter())?;
            let session_keys = command.session_key;
            commands::decrypt::decrypt_unwrap(
                sq,
                &mut input, &mut output,
                secrets,
                session_keys,
                command.dump_session_key)?;
            output.finalize()?;
        },

        Subcommands::Split(command) =>
            split(sq, command)?,
        Subcommands::Join(command) => {
            join(sq, command)?;
        }
    }

    Ok(())
}


pub fn split(sq: Sq, c: SplitCommand) -> Result<()>
{
    let input = c.input.open()?;

    // If --binary is given, the user has to provide a prefix.
    assert!(! c.binary || c.prefix.is_some(),
            "clap failed to enforce --binary requiring --prefix");

    // We either emit one stream, or open one file per packet.
    let mut sink = match c.prefix {
        Some(p) => Err(p),
        None => Ok(
            c.output.as_ref()
                .expect("either prefix or output must be given")
                .create_pgp_safe(&sq, true, Kind::SecretKey)?),
    };

    // We (ab)use the mapping feature to create byte-accurate dumps of
    // nested packets.
    let mut ppr =
        openpgp::parse::PacketParserBuilder::from_buffered_reader(input)?
        .buffer_unread_content()
        .map(true).build()?;

    fn join(pos: &[usize], delimiter: &str) -> String {
        pos.iter().map(ToString::to_string).collect::<Vec<_>>().join(delimiter)
    }

    let mut first = true;
    while let PacketParserResult::Some(pp) = ppr {
        if let Some(map) = pp.map() {
            let mut sink: Box<dyn io::Write> = match &mut sink {
                Ok(sink) => Box::new(sink),
                Err(prefix) => {
                    // Construct the filename:
                    //
                    //   PREFIX - PATH - [Unknown-]TAG

                    // Start with the prefix.
                    let mut filename = prefix.clone();

                    // Add the path.
                    filename.push("-");
                    filename.push(join(pp.path(), "-"));

                    // Add the tag.
                    filename.push("-");
                    filename.push(
                        pp.packet.kind().map(|_| "").unwrap_or("Unknown-"));
                    filename.push(
                        pp.packet.tag().to_string().replace(" ", "-"));

                    let sink = File::create(filename)
                        .context("Failed to create output file")?;
                    Box::new(sink)
                }
            };

            if c.binary {
                // Write all the bytes.
                for field in map.iter() {
                    sink.write_all(field.as_bytes())?;
                }
            } else {
                let mut headers = vec![
                    ("Comment", if let Some(i) = c.input.inner() {
                        format!(
                            "{}[{}]: {}", i.display(), join(pp.path(), "."),
                            pp.packet.tag())
                    } else {
                        format!(
                            "{}: {}", join(pp.path(), "."), pp.packet.tag())
                    }),
                ];

                match &pp.packet {
                    Packet::PKESK(p) => headers.push(
                        ("Comment", format!("Recipient: {}", p.recipient()))),
                    Packet::PublicKey(k) => headers.push(
                        ("Comment", format!("Fingerprint: {}", k.fingerprint()))),
                    Packet::PublicSubkey(k) => headers.push(
                        ("Comment", format!("Fingerprint: {}", k.fingerprint()))),
                    Packet::SecretKey(k) => headers.push(
                        ("Comment", format!("Fingerprint: {}", k.fingerprint()))),
                    Packet::SecretSubkey(k) => headers.push(
                        ("Comment", format!("Fingerprint: {}", k.fingerprint()))),
                    Packet::Signature(s) => {
                        headers.push(("Comment", format!("Type: {}", s.typ())));
                        if let Some(t) = s.signature_creation_time() {
                            headers.push(("Comment", format!("Created: {}", t.convert())));
                        }
                        if let Some(i) = s.get_issuers().get(0)
                        {
                            headers.push(
                                ("Comment", format!("Issuer: {}", i)));
                        }
                    },
                    Packet::UserID(u) => headers.push(
                        ("Comment", format!("UserID: {}",
                                            String::from_utf8_lossy(u.value())))),
                    _ => (),
                }

                // Provide more structure to the human reader.
                if ! first {
                    writeln!(sink)?;
                    writeln!(sink)?;
                }

                let mut writer = Writer::with_headers(
                    &mut sink, Kind::File, headers)?;

                // Write all the bytes.
                for field in map.iter() {
                    writer.write_all(field.as_bytes())?;
                }
                writer.finalize()?;
            }

            first = false;
        }

        ppr = pp.recurse()?.1;
    }
    Ok(())
}

/// Joins the given files.
pub fn join(sq: Sq, c: JoinCommand) -> Result<()> {
    // Either we know what kind of armor we want to produce, or we
    // need to detect it using the first packet we see.
    let kind = c.kind.into();
    let output = c.output.for_secrets();
    let mut sink = if c.binary {
        // No need for any auto-detection.
        Some(output.create_pgp_safe(
            &sq, true, openpgp::armor::Kind::File)?)
    } else if let Some(kind) = kind {
        Some(output.create_pgp_safe(&sq, false, kind)?)
    } else {
        None // Defer.
    };

    /// Writes a bit-accurate copy of all top-level packets in PPR to
    /// OUTPUT.
    fn copy<'a, 'b, 'pp>(sq: &Sq,
            mut ppr: PacketParserResult<'pp>,
            output: &'a FileOrStdout,
            sink: &'b mut Option<Message<'a>>)
            -> Result<PacketParserResult<'pp>> {
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
                    output.create_pgp_safe(&sq, false, kind)?
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
        Ok(ppr)
    }

    /// Writes a bit-accurate copy of all top-level packets in all
    /// armored sections in the input to OUTPUT.
    fn copy_all<'a, 'b>(sq: &Sq,
                        mut ppr: PacketParserResult,
                        output: &'a FileOrStdout,
                        sink: &'b mut Option<Message<'a>>)
                        -> Result<()>
    {
        // First, copy all the packets, armored or not.
        ppr = copy(sq, ppr, output, sink)?;

        loop {
            // Now, the parser is exhausted, but we may find another
            // armored blob.  Note that this can only happen if the
            // first set of packets was also armored.
            match ppr {
                PacketParserResult::Some(_) =>
                    unreachable!("copy exhausted the packet parser"),
                PacketParserResult::EOF(eof) => {
                    // See if there is another armor block.
                    let reader = eof.into_reader();
                    ppr = match
                        PacketParserBuilder::from_buffered_reader(reader)
                        .and_then(
                            |builder| builder
                                .buffer_unread_content()
                                .map(true)
                                .dearmor(Dearmor::Enabled(
                                    ReaderMode::Tolerant(None)))
                                .build())
                    {
                        Ok(ppr) => ppr,
                        Err(e) => {
                            // There isn't, or we encountered an error.
                            if let Some(e) = e.downcast_ref::<io::Error>() {
                                if e.kind() == io::ErrorKind::UnexpectedEof {
                                    return Ok(());
                                }
                            }

                            return Err(e);
                        },
                    }
                },
            }

            // We found another armor block, copy all the packets.
            ppr = copy(sq, ppr, output, sink)?;
        }
    }

    if !c.input.is_empty() {
        for name in c.input {
            let ppr =
                openpgp::parse::PacketParserBuilder::from_file(name)?
                .buffer_unread_content()
                .map(true).build()?;
            copy_all(&sq, ppr, &output, &mut sink)?;
        }
    } else {
        let ppr =
            openpgp::parse::PacketParserBuilder::from_reader(io::stdin())?
            .buffer_unread_content()
            .map(true).build()?;
        copy_all(&sq, ppr, &output, &mut sink)?;
    }

    sink.unwrap().finalize()?;
    Ok(())
}
