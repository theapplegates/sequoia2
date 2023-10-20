use std::io;
use std::fs::File;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::types::KeyFlags;
use openpgp::parse::stream::DetachedVerifierBuilder;
use openpgp::parse::stream::VerifierBuilder;
use openpgp::parse::Parse;

use crate::Config;
use crate::Result;
use crate::cli;
use crate::commands::VHelper;
use crate::load_certs;

pub fn dispatch(config: Config, command: cli::verify::Command)
    -> Result<()>
{
    tracer!(TRACE, "verify::dispatch");

    let mut input = command.input.open()?;
    let mut output = command.output.create_safe(config.force)?;
    let mut detached = if let Some(f) = command.detached {
        Some(File::open(f)?)
    } else {
        None
    };
    let signatures = command.signatures;
    // TODO ugly adaptation to load_certs' signature, fix later
    let mut certs = load_certs(
        command.sender_file.iter().map(|s| s.as_ref()))?;
    certs.extend(
        config.lookup(command.sender_certs,
                      Some(KeyFlags::empty().set_signing()),
                      true,
                      false)
            .context("--sender-cert")?);
    verify(config, &mut input,
           detached.as_mut().map(|r| r as &mut (dyn io::Read + Sync + Send)),
           &mut output, signatures, certs)?;

    Ok(())
}

pub fn verify(config: Config,
              input: &mut (dyn io::Read + Sync + Send),
              detached: Option<&mut (dyn io::Read + Sync + Send)>,
              output: &mut dyn io::Write,
              signatures: usize, certs: Vec<Cert>)
              -> Result<()> {
    let helper = VHelper::new(&config, signatures, certs);
    let helper = if let Some(dsig) = detached {
        let mut v = DetachedVerifierBuilder::from_reader(dsig)?
            .with_policy(&config.policy, Some(config.time), helper)?;
        v.verify_reader(input)?;
        v.into_helper()
    } else {
        let mut v = VerifierBuilder::from_reader(input)?
            .with_policy(&config.policy, Some(config.time), helper)?;
        io::copy(&mut v, output)?;
        v.into_helper()
    };

    helper.print_status();
    Ok(())
}
