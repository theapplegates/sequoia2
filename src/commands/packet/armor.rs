use std::io;

use buffered_reader::BufferedReader;
use buffered_reader::Dup;
use buffered_reader::Limitor;

use sequoia_openpgp as openpgp;
use openpgp::Packet;
use openpgp::armor;
use openpgp::parse::Parse;
use openpgp::parse::PacketParser;
use openpgp::parse::PacketParserResult;

use crate::Config;
use crate::Result;
use crate::cli;

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
        Limitor::new(Dup::new(input), ARMOR_DETECTION_LIMIT).into_boxed();
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

pub fn dispatch(config: Config, command: cli::armor::Command)
    -> Result<()>
{
    tracer!(TRACE, "armor::dispatch");

    let input = command.input.open()?;
    let mut want_kind: Option<armor::Kind>
        = command.kind.into();

    // Peek at the data.  If it looks like it is armored
    // data, avoid armoring it again.
    let mut dup = Limitor::new(Dup::new(input), ARMOR_DETECTION_LIMIT);
    let (already_armored, have_kind) = {
        let mut reader =
            armor::Reader::from_reader(
                &mut dup,
                armor::ReaderMode::Tolerant(None));
        (reader.data(8).is_ok(), reader.kind())
    };
    let mut input =
        dup.into_boxed().into_inner().unwrap().into_inner().unwrap();

    if already_armored
        && (want_kind.is_none() || want_kind == have_kind)
    {
        // It is already armored and has the correct kind.
        let mut output = command.output.create_safe(config.force)?;
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
        command.output.create_pgp_safe(config.force, false, want_kind)?;

    if already_armored {
        // Dearmor and copy to change the type.
        let mut reader =
            armor::Reader::from_reader(
                input,
                armor::ReaderMode::Tolerant(None));
        io::copy(&mut reader, &mut output)?;
    } else {
        io::copy(&mut input, &mut output)?;
    }
    output.finalize()?;

    Ok(())
}
