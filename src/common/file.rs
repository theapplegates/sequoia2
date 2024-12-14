/// Common file handling support.

use std::{
    io::{self, Write, stdout},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};

use tempfile::NamedTempFile;

use sequoia_openpgp::{
    self as openpgp,
    armor,
    serialize::stream::{Armorer, Message},
};

use crate::{
    cli::types::FileOrStdout,
    sq::Sq,
};

impl FileOrStdout {
    /// Returns whether the stream is stdout.
    pub fn is_stdout(&self) -> bool {
        self.path().is_none()
    }

    /// Opens the file (or stdout) for writing data that is safe for
    /// non-interactive use.
    ///
    /// This is suitable for any kind of OpenPGP data, decrypted or
    /// authenticated payloads.
    pub fn create_safe(
        &self,
        sq: &Sq,
    ) -> Result<Box<dyn Write + Sync + Send>> {
        self.create(sq)
    }

    /// Opens the file (or stdout) for writing data that is NOT safe
    /// for non-interactive use.
    pub fn create_unsafe(
        &self,
        sq: &Sq,
    ) -> Result<Box<dyn Write + Sync + Send>> {
        self.create(sq)
    }

    /// Opens the file (or stdout) for writing data that is safe for
    /// non-interactive use because it is an OpenPGP data stream.
    ///
    /// Emitting armored data with the label `armor::Kind::SecretKey`
    /// implicitly configures this output to emit secret keys.
    pub fn create_pgp_safe<'a>(
        &self,
        sq: &Sq,
        binary: bool,
        kind: armor::Kind,
    ) -> Result<Message<'a>> {
        // Allow secrets to be emitted if the armor label says secret
        // key.
        let mut o = self.clone();
        if kind == armor::Kind::SecretKey {
            o = o.for_secrets();
        }
        let sink = o.create_safe(sq)?;

        let mut message = Message::new(sink);
        if ! binary {
            message = Armorer::new(message).kind(kind).build()?;
        }
        Ok(message)
    }

    /// Helper function, do not use directly. Instead, use create_or_stdout_safe
    /// or create_or_stdout_unsafe.
    fn create(&self, sq: &Sq) -> Result<Box<dyn Write + Sync + Send>> {
        let sink = self._create_sink(sq)?;
        if self.is_for_secrets() || ! cfg!(debug_assertions) {
            // We either expect secrets, or we are in release mode.
            Ok(sink)
        } else {
            // In debug mode, if we don't expect secrets, scan the
            // output for inadvertently leaked secret keys.
            Ok(Box::new(SecretLeakDetector::new(sink)))
        }
    }
    fn _create_sink(&self, sq: &Sq) -> Result<Box<dyn Write + Sync + Send>>
    {
        if let Some(path) = self.path() {
            if !path.exists() || sq.overwrite {
                Ok(Box::new(
                    PartFileWriter::create(path)
                        .context("Failed to create output file")?,
                ))
            } else {
                Err(anyhow::anyhow!(
                    "File {} exists, use \"sq --overwrite ...\" to overwrite",
                    path.display(),
                ))
            }
        } else {
            Ok(Box::new(stdout()))
        }
    }
}

/// A writer that writes to a temporary file first, then persists the
/// file under the desired name.
///
/// This has two benefits.  First, consumers only see the file once we
/// are done writing to it, i.e. they don't see a partial file.
///
/// Second, we guarantee not to overwrite the file until the operation
/// is finished.  Therefore, it is safe to use the same file as input
/// and output.
struct PartFileWriter {
    path: PathBuf,
    sink: Option<NamedTempFile>,
}

impl io::Write for PartFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sink()?.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sink()?.flush()
    }
}

impl Drop for PartFileWriter {
    fn drop(&mut self) {
        if let Err(e) = self.persist() {
            weprintln!(initial_indent = "Error: ", "{}", e);
            std::process::exit(1);
        }
    }
}

impl PartFileWriter {
    /// Opens a file for writing.
    ///
    /// The file will be created under a different name in the target
    /// directory, and will only be renamed to `path` once
    /// [`PartFileWriter::persist`] is called or the object is
    /// dropped.
    pub fn create<P: AsRef<Path>>(path: P) -> Result<PartFileWriter> {
        let path = path.as_ref().to_path_buf();
        let parent = path.parent()
            .ok_or(anyhow::anyhow!("cannot write to the root"))?;
        let file_name = path.file_name()
            .ok_or(anyhow::anyhow!("cannot write to .."))?;

        let mut sink = tempfile::Builder::new();

        // By default, temporary files are 0x600 on Unix.  But, we
        // rather want created files to respect umask.
        platform! {
            unix => {
                use std::os::unix::fs::PermissionsExt;
                let all_read_write =
                    std::fs::Permissions::from_mode(0o666);

                // The permissions will be masked by the user's umask.
                sink.permissions(all_read_write);
            },
            windows => {
                // We cannot do the same on Windows.
            },
        }

        let sink = sink
            .prefix(file_name)
            .suffix(".part")
            .tempfile_in(parent)?;

        Ok(PartFileWriter {
            path,
            sink: Some(sink),
        })
    }

    /// Returns a mutable reference to the file, or an error.
    fn sink(&mut self) -> io::Result<&mut NamedTempFile> {
        self.sink.as_mut().ok_or(io::Error::new(
            io::ErrorKind::Other,
            anyhow::anyhow!("file already persisted")))
    }

    /// Persists the file under its final name.
    pub fn persist(&mut self) -> Result<()> {
        if let Some(file) = self.sink.take() {
            file.persist(&self.path)?;
        }
        Ok(())
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
