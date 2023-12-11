use std::fmt::Display;
use std::fmt::Formatter;
use std::fs::OpenOptions;
use std::io::Write;
use std::io::stdin;
use std::io::stdout;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use std::time::SystemTime;

use anyhow::Context;
use anyhow::Result;

use buffered_reader::BufferedReader;
use buffered_reader::File;
use buffered_reader::Generic;
use chrono::{offset::Utc, DateTime};
/// Common types for arguments of sq.
use clap::ValueEnum;

use sequoia_openpgp as openpgp;
use openpgp::armor;
use openpgp::fmt::hex;
use openpgp::serialize::stream::Armorer;
use openpgp::serialize::stream::Message;
use openpgp::types::SymmetricAlgorithm;
use openpgp::types::Timestamp;

use crate::cli::SECONDS_IN_DAY;
use crate::cli::SECONDS_IN_YEAR;

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
                    "\nWARNING: sq does not have a stable CLI interface. \
                    Use with caution in scripts.\n"
                );
            }
        });
    }
}

/// A trait to provide const &str for clap annotations for custom structs
pub trait ClapData {
    /// The clap value name
    const VALUE_NAME: &'static str;
    /// The clap help text
    const HELP: &'static str;
}

/// A type wrapping an optional PathBuf to use as stdin or file input
///
/// When creating `FileOrStdin` from `&str`, providing a `"-"` is interpreted
/// as `None`, i.e. read from stdin. Providing other strings is interpreted as
/// `Some(PathBuf)`, i.e. read from file.
/// Use this if a CLI should allow input from a file and if unset from stdin.
///
/// ## Examples
/// ```
/// use clap::Args;
///
/// #[derive(Debug, Args)]
/// #[clap(name = "example", about = "an example")]
/// pub struct Example {
///     #[clap(
///         default_value_t = FileOrStdin::default(),
///         help = FileOrStdin::HELP,
///         value_name = FileOrStdin::VALUE_NAME,
///     )]
///     pub input: FileOrStdin,
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileOrStdin(Option<PathBuf>);

impl ClapData for FileOrStdin {
    const VALUE_NAME: &'static str = "FILE";
    const HELP: &'static str = "Reads from FILE or stdin if omitted";
}

impl FileOrStdin {
    pub fn new(path: Option<PathBuf>) -> Self {
        FileOrStdin(path)
    }

    /// Return a reference to the inner type
    pub fn inner(&self) -> Option<&PathBuf> {
        self.0.as_ref()
    }

    /// Returns `None` if `self.0` is `None`, otherwise calls f with the wrapped
    /// value and returns the result
    pub fn and_then<U, F>(self, f: F) -> Option<U>
    where
        F: FnOnce(PathBuf) -> Option<U>,
    {
        self.0.and_then(|x| f(x))
    }

    /// Get a boxed BufferedReader for the FileOrStdin
    ///
    /// Opens a file if there is Some(PathBuf), else opens stdin.
    pub fn open(&self) -> Result<Box<dyn BufferedReader<()>>> {
        if let Some(path) = self.inner() {
            Ok(Box::new(
                File::open(path)
                .with_context(|| format!("Failed to open {}", self))?))
        } else {
            Ok(Box::new(Generic::new(stdin(), None)))
        }
    }
}

impl Default for FileOrStdin {
    fn default() -> Self {
        FileOrStdin(None)
    }
}

impl From<PathBuf> for FileOrStdin {
    fn from(value: PathBuf) -> Self {
        if value == PathBuf::from("-") {
            FileOrStdin::default()
        } else {
            FileOrStdin::new(Some(value))
        }
    }
}

impl From<Option<PathBuf>> for FileOrStdin {
    fn from(value: Option<PathBuf>) -> Self {
        if let Some(path) = value {
            FileOrStdin::from(path)
        } else {
            FileOrStdin::default()
        }
    }
}

impl From<&Path> for FileOrStdin {
    fn from(value: &Path) -> Self {
        if Path::new("-") == value {
            FileOrStdin::default()
        } else {
            FileOrStdin::from(value.to_owned())
        }
    }
}

impl From<Option<&Path>> for FileOrStdin {
    fn from(value: Option<&Path>) -> Self {
        if let Some(path) = value {
            FileOrStdin::from(path)
        } else {
            FileOrStdin::default()
        }
    }
}

impl FromStr for FileOrStdin {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if "-" == s {
            Ok(FileOrStdin(None))
        } else {
            Ok(FileOrStdin(Some(PathBuf::from(s))))
        }
    }
}

impl Display for FileOrStdin {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match &self.0 {
            None => write!(f, "-"),
            Some(path) => write!(f, "{}", path.display()),
        }
    }
}

/// A type providing const strings for output to certstore by default
///
/// This struct is empty and solely used to provide strings to clap.
/// Use this in combination with a [`FileOrStdout`] if a CLI should allow output
/// to a file and if unset output to a cert store.
///
/// ## Examples
/// ```
/// use clap::Args;
///
/// #[derive(Debug, Args)]
/// #[clap(name = "example", about = "an example")]
/// pub struct Example {
///     #[clap(
///         help = FileOrCertStore::HELP,
///         long,
///         short,
///         value_name = FileOrCertStore::VALUE_NAME,
///     )]
///     pub output: Option<FileOrStdout>,
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileOrCertStore{}

impl ClapData for FileOrCertStore {
    const VALUE_NAME: &'static str = "FILE";
    const HELP: &'static str
        = "Writes to FILE (or stdout when providing \"-\") instead of \
          importing into the certificate store";
}

/// A type wrapping an optional PathBuf to use as stdout or file output
///
/// When creating `FileOrStdout` from `&str`, providing a `"-"` is interpreted
/// as `None`, i.e. output to stdout. Providing other strings is interpreted as
/// `Some(PathBuf)`, i.e. output to file.
/// Use this if a CLI should allow output to a file and if unset output to
/// stdout.
///
/// ## Examples
/// ```
/// use clap::Args;
///
/// #[derive(Debug, Args)]
/// #[clap(name = "example", about = "an example")]
/// pub struct Example {
///     #[clap(
///         default_value_t = FileOrStdout::default(),
///         help = FileOrStdout::HELP,
///         long,
///         short,
///         value_name = FileOrStdout::VALUE_NAME,
///     )]
///     pub output: FileOrStdout,
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileOrStdout(Option<PathBuf>);

impl ClapData for FileOrStdout {
    const VALUE_NAME: &'static str = "FILE";
    const HELP: &'static str = "Writes to FILE or stdout if omitted";
}

impl FileOrStdout {
    pub fn new(path: Option<PathBuf>) -> Self {
        FileOrStdout(path)
    }

    /// Return a reference to the optional PathBuf
    pub fn path(&self) -> Option<&PathBuf> {
        self.0.as_ref()
    }

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
    pub fn create_pgp_safe(
        &self,
        force: bool,
        binary: bool,
        kind: armor::Kind,
    ) -> Result<Message> {
        let sink = self.create_safe(force)?;
        let mut message = Message::new(sink);
        if ! binary {
            message = Armorer::new(message).kind(kind).build()?;
        }
        Ok(message)
    }

    /// Helper function, do not use directly. Instead, use create_or_stdout_safe
    /// or create_or_stdout_unsafe.
    fn create(&self, force: bool) -> Result<Box<dyn Write + Sync + Send>> {
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

impl Default for FileOrStdout {
    fn default() -> Self {
        FileOrStdout(None)
    }
}

impl From<PathBuf> for FileOrStdout {
    fn from(value: PathBuf) -> Self {
        if value == PathBuf::from("-") {
            FileOrStdout::default()
        } else {
            FileOrStdout::new(Some(value))
        }
    }
}

impl From<Option<PathBuf>> for FileOrStdout {
    fn from(value: Option<PathBuf>) -> Self {
        if let Some(path) = value {
            FileOrStdout::from(path)
        } else {
            FileOrStdout::default()
        }
    }
}

impl FromStr for FileOrStdout {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if "-" == s {
            Ok(FileOrStdout::default())
        } else {
            Ok(FileOrStdout::new(Some(PathBuf::from(s))))
        }
    }
}

impl Display for FileOrStdout {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self.path() {
            Some(path) => write!(f, "{}", path.display()),
            None => write!(f, "-"),
        }
    }
}

#[derive(ValueEnum, Debug, Clone)]
pub enum ArmorKind {
    Auto,
    Message,
    #[clap(name = "cert")]
    PublicKey,
    #[clap(name = "key")]
    SecretKey,
    #[clap(name = "sig")]
    Signature,
    File,
}

impl From<ArmorKind> for Option<openpgp::armor::Kind> {
    fn from(c: ArmorKind) -> Self {
        match c {
            ArmorKind::Auto => None,
            ArmorKind::Message => Some(openpgp::armor::Kind::Message),
            ArmorKind::PublicKey => Some(openpgp::armor::Kind::PublicKey),
            ArmorKind::SecretKey => Some(openpgp::armor::Kind::SecretKey),
            ArmorKind::Signature => Some(openpgp::armor::Kind::Signature),
            ArmorKind::File => Some(openpgp::armor::Kind::File),
        }
    }
}

/// Time for metadata in literal data packet
///
/// This enum tracks time information for literal data packets, which may carry
/// unsigned metadata about the encrypted file.
#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum MetadataTime {
    /// No time is added
    None,
    /// The timestamp of the file creation
    FileCreation,
    /// The timestamp of the file modification
    FileModification,
    /// The timestamp of the message creation
    MessageCreation,
    /// A specific timestamp
    Timestamp(Time),
}

impl MetadataTime {
    /// Create a new MetadataTime in a Result
    pub fn new(date: &str) -> Result<Self> {
        match date {
            "none" => Ok(Self::None),
            "file-creation" => Ok(Self::FileCreation),
            "file-modification" => Ok(Self::FileModification),
            "message-creation" => Ok(Self::MessageCreation),
            _ => Ok(Self::Timestamp(Time::from_str(date)?))
        }
    }
}

impl FromStr for MetadataTime {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<MetadataTime> {
        MetadataTime::new(s)
    }
}

impl Display for MetadataTime {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            MetadataTime::Timestamp(time) => write!(f, "{}", time),
            MetadataTime::FileCreation => write!(f, "{}", "file-creation"),
            MetadataTime::FileModification => write!(f, "{}", "file-modification"),
            MetadataTime::MessageCreation => write!(f, "{}", "message-creation"),
            MetadataTime::None => write!(f, "none"),
        }
    }
}

impl Default for MetadataTime {
    fn default() -> Self {
        MetadataTime::None
    }
}

/// Expiry information
///
/// This enum tracks expiry information either in the form of a timestamp or
/// a duration.
#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Expiry {
    /// An expiry timestamp
    Timestamp(Time),
    /// A validity duration
    Duration(Duration),
    /// There is no expiry
    Never,
}

impl Expiry {
    /// Create a new Expiry in a Result
    ///
    /// If `expiry` ends with `"y"`, `"m"`, `"w"`, `"w"`, `"d"` or `"s"` it
    /// is treated as a duration, which is parsed using `parse_duration()` and
    /// returned in an `Expiry::Duration`.
    /// If the special keyword `"never"` is provided as `expiry`,
    /// `Expiry::Never` is returned.
    /// If `expiry` is an ISO 8601 compatible string it is returned as
    /// `cli::types::Time` in an `Expiry::Timestamp`.
    pub fn new(expiry: &str) -> Result<Self> {
        match expiry {
            "never" => Ok(Expiry::Never),
            _ if expiry.ends_with("y")
                || expiry.ends_with("m")
                || expiry.ends_with("w")
                || expiry.ends_with("d")
                || expiry.ends_with("s") =>
            {
                Ok(Expiry::Duration(Expiry::parse_duration(expiry)?))
            }
            _ => Ok(Expiry::Timestamp(Time::from_str(expiry)?)),
        }
    }

    /// Parse a string as Duration and return it in a Result
    ///
    /// The `expiry` must be at least two chars long, and consist of digits and
    /// a trailing factor identifier (one of `"y"`, `"m"`, `"w"`, `"d"`, `"s"`
    /// for year, month, week, day or second, respectively).
    fn parse_duration(expiry: &str) -> Result<Duration> {
        if expiry.len() < 2 {
            return Err(anyhow::anyhow!(
                "Expiry must contain at least one digit and one factor."
            ));
        }

        match expiry.strip_suffix(['y', 'm', 'w', 'd', 's']) {
            Some(digits) => Ok(Duration::new(
                match digits.parse::<i64>() {
                    Ok(count) if count < 0 => {
                        return Err(anyhow::anyhow!(
                            "Negative expiry ('{}') detected. \
                            Did you mean '{}'?",
                            expiry,
                            expiry.trim_start_matches("-")
                        ))
                    }
                    Ok(count) => count as u64,
                    Err(err) => return Err(err).context(
                        format!("Expiry '{}' is out of range", digits)
                    ),
                } * match expiry.chars().last() {
                    Some('y') => SECONDS_IN_YEAR,
                    Some('m') => SECONDS_IN_YEAR / 12,
                    Some('w') => 7 * SECONDS_IN_DAY,
                    Some('d') => SECONDS_IN_DAY,
                    Some('s') => 1,
                    _ => unreachable!(
                        "Expiry without 'y', 'm', 'w', 'd' or 's' \
                                suffix impossible since checked for it."
                    ),
                },
                0,
            )),
            None => {
                return Err(anyhow::anyhow!(
                    if let Some(suffix) = expiry.chars().last() {
                        format!(
                            "Invalid suffix '{}' in duration '{}' \
                        (try <digits><y|m|w|d|s>, e.g. '1y')",
                            suffix,
                            expiry
                        )
                    } else {
                        format!(
                            "Invalid duration: {} \
                        (try <digits><y|m|w|d|s>, e.g. '1y')",
                            expiry
                        )
                    }
                ))
            }
        }
    }

    /// Return the expiry as an optional Duration in a Result
    ///
    /// This method returns an Error if the reference time is later than the
    /// time provided in an `Expiry::Timestamp(Time)`.
    ///
    /// If self is `Expiry::Timestamp(Time)`, `reference` is used as the start
    /// of a period, `Some(Time - reference)` is returned.
    /// If self is `Expiry::Duration(duration)`, `Some(duration)` is returned.
    /// If self is `Expiry::Never`, `None` is returned.
    pub fn as_duration(
        &self,
        reference: DateTime<Utc>,
    ) -> Result<Option<Duration>> {
        match self {
            Expiry::Timestamp(time) => Ok(
                Some(
                    SystemTime::from(time.time).duration_since(reference.into())?
                )
            ),
            Expiry::Duration(duration) => Ok(Some(duration.clone())),
            Expiry::Never => Ok(None),
        }
    }
}

impl FromStr for Expiry {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Expiry> {
        Expiry::new(s)
    }
}

impl Display for Expiry {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Expiry::Timestamp(time) => write!(f, "{}", time),
            Expiry::Duration(duration) => write!(f, "{:?}", duration),
            Expiry::Never => write!(f, "never"),
        }
    }
}

/// Holds a session key as parsed from the command line, with an optional
/// algorithm specifier.
///
/// This struct does not implement [`Display`] to prevent accidental leaking
/// of key material. If you are sure you want to print a session key, use
/// [`display_sensitive`].
///
/// [`Display`]: std::fmt::Display
/// [`display_sensitive`]: SessionKey::display_sensitive
#[derive(Debug, Clone)]
pub struct SessionKey {
    pub session_key: openpgp::crypto::SessionKey,
    pub symmetric_algo: Option<SymmetricAlgorithm>,
}

impl std::str::FromStr for SessionKey {
    type Err = anyhow::Error;

    /// Parse a session key. The format is: an optional prefix specifying the
    /// symmetric algorithm as a number, followed by a colon, followed by the
    /// session key in hexadecimal representation.
    fn from_str(sk: &str) -> anyhow::Result<Self> {
        let result = if let Some((algo, sk)) = sk.split_once(':') {
            let algo = SymmetricAlgorithm::from(algo.parse::<u8>()?);
            let dsk = hex::decode_pretty(sk)?.into();
            SessionKey {
                session_key: dsk,
                symmetric_algo: Some(algo),
            }
        } else {
            let dsk = hex::decode_pretty(sk)?.into();
            SessionKey {
                session_key: dsk,
                symmetric_algo: None,
            }
        };
        Ok(result)
    }
}

impl SessionKey {
    /// Returns an object that implements Display for explicitly opting into
    /// printing a `SessionKey`.
    pub fn display_sensitive(&self) -> SessionKeyDisplay {
        SessionKeyDisplay { csk: self }
    }
}

/// Helper struct for intentionally printing session keys with format! and {}.
///
/// This struct implements the `Display` trait to print the session key. This
/// construct requires the user to explicitly call
/// [`SessionKey::display_sensitive`]. By requiring the user to opt-in, this
/// will hopefully reduce that the chance that the session key is inadvertently
/// leaked, e.g., in a log that may be publicly posted.
pub struct SessionKeyDisplay<'a> {
    csk: &'a SessionKey,
}

/// Print the session key without prefix in hexadecimal representation.
impl<'a> std::fmt::Display for SessionKeyDisplay<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let sk = self.csk;
        write!(f, "{}", hex::encode(&sk.session_key))
    }
}

/// A thin wrapper around `openpgp::types::Timestamp`.
///
/// Recall: an OpenPGP timestamp has a whole second resolution, and
/// uses a 32-bit quantity to represent the number of seconds since
/// the UNIX epoch.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Time {
    pub time: Timestamp,
}

impl std::str::FromStr for Time {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Time> {
        let time =
            Time::parse_iso8601(s, chrono::NaiveTime::from_hms_opt(0, 0, 0)
                                .unwrap())?;
        Ok(Time::try_from(SystemTime::from(time))?)
    }
}

impl From<Time> for SystemTime {
    fn from(t: Time) -> SystemTime {
        t.time.into()
    }
}

impl TryFrom<SystemTime> for Time {
    type Error = anyhow::Error;

    fn try_from(time: SystemTime) -> Result<Self> {
        Ok(Self {
            time: Timestamp::try_from(time)?,
        })
    }
}

impl TryFrom<DateTime<Utc>> for Time {
    type Error = anyhow::Error;

    fn try_from(time: DateTime<Utc>) -> Result<Self> {
        Self::try_from(SystemTime::try_from(time)?)
    }
}

impl Time {
    /// Returns the current time.
    pub fn now() -> Self {
        Self {
            time: Timestamp::now()
        }
    }

    /// Returns the time as openpgp::types::Timestamp.
    pub fn timestamp(&self) -> openpgp::types::Timestamp {
        self.time.clone()
    }

    /// Parses the given string depicting a ISO 8601 timestamp.
    fn parse_iso8601(
        s: &str,
        pad_date_with: chrono::NaiveTime,
    ) -> anyhow::Result<DateTime<Utc>> {
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
        for f in &["%Y-%m-%d", "%Y-%m", "%Y-%j", "%Y%m%d", "%Y%m", "%Y%j", "%Y"]
        {
            if let Ok(d) = chrono::NaiveDate::parse_from_str(s, *f) {
                return Ok(DateTime::from_utc(d.and_time(pad_date_with), Utc));
            }
        }
        Err(anyhow::anyhow!("Malformed ISO8601 timestamp: {}", s))
    }
}

impl Display for Time {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", self.time)
    }
}

#[cfg(test)]
mod test {
    use chrono::NaiveDateTime;

    use super::*;

    #[test]
    fn test_parse_iso8601() -> anyhow::Result<()> {
        let z = chrono::NaiveTime::from_hms_opt(0, 0, 0).unwrap();
        Time::parse_iso8601("2017-03-04T13:25:35Z", z)?;
        Time::parse_iso8601("2017-03-04T13:25:35+08:30", z)?;
        Time::parse_iso8601("2017-03-04T13:25:35", z)?;
        Time::parse_iso8601("2017-03-04T13:25Z", z)?;
        Time::parse_iso8601("2017-03-04T13:25", z)?;
        // CliTime::parse_iso8601("2017-03-04T13Z", z)?; // XXX: chrono doesn't like
        // CliTime::parse_iso8601("2017-03-04T13", z)?; // ditto
        Time::parse_iso8601("2017-03-04", z)?;
        // CliTime::parse_iso8601("2017-03", z)?; // ditto
        Time::parse_iso8601("2017-031", z)?;
        Time::parse_iso8601("20170304T132535Z", z)?;
        Time::parse_iso8601("20170304T132535+0830", z)?;
        Time::parse_iso8601("20170304T132535", z)?;
        Time::parse_iso8601("20170304T1325Z", z)?;
        Time::parse_iso8601("20170304T1325", z)?;
        // CliTime::parse_iso8601("20170304T13Z", z)?; // ditto
        // CliTime::parse_iso8601("20170304T13", z)?; // ditto
        Time::parse_iso8601("20170304", z)?;
        // CliTime::parse_iso8601("201703", z)?; // ditto
        Time::parse_iso8601("2017031", z)?;
        // CliTime::parse_iso8601("2017", z)?; // ditto
        Ok(())
    }

    #[test]
    fn test_expiry() {
        assert_eq!(
            Expiry::new("1y").unwrap(),
            Expiry::Duration(Duration::new(SECONDS_IN_YEAR, 0)),
        );
        assert_eq!(
            Expiry::new("2023-05-15T20:00:00Z").unwrap(),
            Expiry::Timestamp(Time::from_str("2023-05-15T20:00:00Z").unwrap()),
        );
        assert_eq!(
            Expiry::new("never").unwrap(),
            Expiry::Never,
        );
    }

    #[test]
    fn test_expiry_parse_duration() {
        assert_eq!(
            Expiry::parse_duration("1y").unwrap(),
            Duration::new(SECONDS_IN_YEAR, 0),
        );
        assert!(Expiry::parse_duration("f").is_err());
        assert!(Expiry::parse_duration("-1y").is_err());
        assert!(Expiry::parse_duration("foo").is_err());
        assert!(Expiry::parse_duration("1o").is_err());
    }

    #[test]
    fn test_expiry_as_duration() {
        let reference = DateTime::from_utc(
            NaiveDateTime::from_timestamp_opt(1, 0).unwrap(),
            Utc,
        );

        let expiry = Expiry::Timestamp(
            Time::try_from(DateTime::from_utc(
                NaiveDateTime::from_timestamp_opt(2, 0).unwrap(),
                Utc
            )).expect("valid"));
        assert_eq!(
            expiry.as_duration(reference).unwrap(),
            Some(Duration::new(1, 0)),
        );

        let expiry = Expiry::Duration(Duration::new(2,0));
        assert_eq!(
            expiry.as_duration(reference).unwrap(),
            Some(Duration::new(2, 0)),
        );

        let expiry = Expiry::Never;
        assert_eq!(expiry.as_duration(reference).unwrap(), None);
    }

    #[test]
    fn test_expiry_as_duration_errors() {
        let reference = DateTime::from_utc(
            NaiveDateTime::from_timestamp_opt(2, 0).unwrap(),
            Utc,
        );
        let expiry = Expiry::Timestamp(
            Time::try_from(DateTime::from_utc(
                NaiveDateTime::from_timestamp_opt(1, 0).unwrap(),
                Utc
            )).expect("valid"));
        assert!(expiry.as_duration(reference).is_err());
    }
}
