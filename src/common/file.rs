/// Common file handling support.

use std::{
    fs::OpenOptions,
    io::{self, Write, stdout},
};

use anyhow::{Context, Result};

use sequoia_openpgp::{
    self as openpgp,
    armor,
    serialize::stream::{Armorer, Message},
};

use crate::cli::types::FileOrStdout;

impl FileOrStdout {
    /// Opens the file (or stdout) for writing data that is safe for
    /// non-interactive use.
    ///
    /// This is suitable for any kind of OpenPGP data, decrypted or
    /// authenticated payloads.
    pub fn create_safe(
        &self,
        force: bool,
    ) -> Result<Box<dyn Write + Sync + Send>> {
        self.create(force)
    }

    /// Opens the file (or stdout) for writing data that is NOT safe
    /// for non-interactive use.
    ///
    /// If our heuristic detects non-interactive use, we will emit a
    /// warning once.
    pub fn create_unsafe(
        &self,
        force: bool,
    ) -> Result<Box<dyn Write + Sync + Send>> {
        CliWarningOnce::warn();
        self.create(force)
    }

    /// Opens the file (or stdout) for writing data that is safe for
    /// non-interactive use because it is an OpenPGP data stream.
    ///
    /// Emitting armored data with the label `armor::Kind::SecretKey`
    /// implicitly configures this output to emit secret keys.
    pub fn create_pgp_safe<'a>(
        &self,
        force: bool,
        binary: bool,
        kind: armor::Kind,
    ) -> Result<Message<'a>> {
        // Allow secrets to be emitted if the armor label says secret
        // key.
        let mut o = self.clone();
        if kind == armor::Kind::SecretKey {
            o = o.for_secrets();
        }
        let sink = o.create_safe(force)?;

        let mut message = Message::new(sink);
        if ! binary {
            message = Armorer::new(message).kind(kind).build()?;
        }
        Ok(message)
    }

    /// Helper function, do not use directly. Instead, use create_or_stdout_safe
    /// or create_or_stdout_unsafe.
    fn create(&self, force: bool) -> Result<Box<dyn Write + Sync + Send>> {
        let sink = self._create_sink(force)?;
        if self.is_for_secrets() || ! cfg!(debug_assertions) {
            // We either expect secrets, or we are in release mode.
            Ok(sink)
        } else {
            // In debug mode, if we don't expect secrets, scan the
            // output for inadvertently leaked secret keys.
            Ok(Box::new(SecretLeakDetector::new(sink)))
        }
    }
    fn _create_sink(&self, force: bool) -> Result<Box<dyn Write + Sync + Send>>
    {
        if let Some(path) = self.path() {
            if !path.exists() || force {
                Ok(Box::new(
                    OpenOptions::new()
                        .write(true)
                        .truncate(true)
                        .create(true)
                        .open(path)
                        .context("Failed to create output file")?,
                ))
            } else {
                Err(anyhow::anyhow!(
                    "File {} exists, use \"sq --force ...\" to overwrite",
                    path.display(),
                ))
            }
        } else {
            Ok(Box::new(stdout()))
        }
    }
}

/// A writer that buffers all data, and scans for secret keys on drop.
///
/// This is used to assert that we only write secret keys in places
/// where we expect that.  As this buffers all data, and has a
/// performance impact, we only do this in debug builds.
struct SecretLeakDetector<W: io::Write + Send + Sync> {
    sink: W,
    data: Vec<u8>,
}

impl<W: io::Write + Send + Sync> io::Write for SecretLeakDetector<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.sink.write(buf)?;
        self.data.extend_from_slice(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sink.flush()
    }
}

impl<W: io::Write + Send + Sync> Drop for SecretLeakDetector<W> {
    fn drop(&mut self) {
        let _ = self.detect_leaks();
    }
}

impl<W: io::Write + Send + Sync> SecretLeakDetector<W> {
    /// Creates a shim around `sink` that scans for inadvertently
    /// leaked secret keys.
    fn new(sink: W) -> Self {
        SecretLeakDetector {
            sink,
            data: Vec::with_capacity(4096),
        }
    }

    /// Scans the buffered data for secret keys, panic'ing if one is
    /// found.
    fn detect_leaks(&self) -> Result<()> {
        use openpgp::Packet;
        use openpgp::parse::{Parse, PacketParserResult, PacketParser};

        let mut ppr = PacketParser::from_bytes(&self.data)?;
        while let PacketParserResult::Some(pp) = ppr {
            match &pp.packet {
                Packet::SecretKey(_) | Packet::SecretSubkey(_) =>
                    panic!("Leaked secret key: {:?}", pp.packet),
                _ => (),
            }
            let (_, next_ppr) = pp.recurse()?;
            ppr = next_ppr;
        }

        Ok(())
    }
}

struct CliWarningOnce(());
impl CliWarningOnce {
    /// Emit a warning message only once
    pub fn warn() {
        use std::sync::Once;
        static WARNING: Once = Once::new();
        WARNING.call_once(|| {
            // stdout is connected to a terminal, assume interactive use.
            use std::io::IsTerminal;
            if ! std::io::stdout().is_terminal()
                // For bash shells, we can use a very simple heuristic.
                // We simply look at whether the COLUMNS variable is defined in
                // our environment.
                && std::env::var_os("COLUMNS").is_none() {
                eprintln!(
                    "\nWARNING: sq does not have a stable CLI interface, \
                     and the human-readable output should not be parsed.\n\
                    Use with caution in scripts.\n"
                );
            }
        });
    }
}
