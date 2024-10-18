use std::io;
use std::path::PathBuf;

use anyhow::Context;

use buffered_reader::File;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::types::KeyFlags;
use openpgp::parse::stream::DetachedVerifierBuilder;
use openpgp::parse::stream::VerifierBuilder;
use openpgp::parse::Parse;

use crate::Sq;
use crate::Result;
use crate::cli;
use crate::commands::VHelper;
use crate::commands::inspect::Kind;
use crate::load_certs;

pub fn dispatch(sq: Sq, command: cli::verify::Command)
    -> Result<()>
{
    tracer!(TRACE, "verify::dispatch");

    let mut input = command.input.open()?;
    let mut output = command.output.create_safe(&sq)?;
    let signatures = command.signatures;
    let mut certs = load_certs(
        command.sender_file.iter())?;
    certs.extend(
        sq.lookup(command.sender_certs,
                      Some(KeyFlags::empty().set_signing()),
                      true,
                      false)
            .context("--sender-cert")?);
    verify(sq, &mut input,
           command.detached,
           &mut output, signatures, certs)?;

    Ok(())
}

pub fn verify(mut sq: Sq,
              input: &mut (dyn io::Read + Sync + Send),
              detached: Option<PathBuf>,
              output: &mut dyn io::Write,
              signatures: usize, certs: Vec<Cert>)
              -> Result<()> {
    let detached = if let Some(sig_path) = detached {
        let sig = File::with_cookie(&sig_path, Default::default())?;

        let (kind, sig) = Kind::identify(&mut sq, sig)?;
        kind.expect_or_else(&sq, "verify", Kind::DetachedSig,
                            "--signature-file", Some(&sig_path))?;

        Some(sig)
    } else {
        None
    };

    let helper = VHelper::new(&sq, signatures, certs);
    let helper = if let Some(dsig) = detached {
        let mut v = DetachedVerifierBuilder::from_reader(dsig)?
            .with_policy(sq.policy, Some(sq.time), helper)?;
        v.verify_reader(input)?;
        v.into_helper()
    } else {
        let mut v = VerifierBuilder::from_reader(input)?
            .with_policy(sq.policy, Some(sq.time), helper)?;
        io::copy(&mut v, output)?;
        v.into_helper()
    };

    helper.print_status();
    Ok(())
}
