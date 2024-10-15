//! Types used in the command-line parser.

use std::fmt::Display;
use std::fmt::Formatter;
use std::io::stdin;
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

use chrono::offset::Utc;
use chrono::DateTime;
use chrono::TimeZone;

/// Common types for arguments of sq.
use clap::ValueEnum;

use sequoia_openpgp as openpgp;
use openpgp::fmt::hex;
use openpgp::KeyHandle;
use openpgp::parse::Cookie;
use openpgp::types::KeyFlags;
use openpgp::types::SymmetricAlgorithm;
use openpgp::types::Timestamp;

use crate::cli::SECONDS_IN_DAY;
use crate::cli::SECONDS_IN_YEAR;

pub mod cert_designator;
pub use cert_designator::CertDesignators;
pub mod paths;
pub mod userid_designator;
pub use userid_designator::UserIDDesignators;

/// A trait to provide const &str for clap annotations for custom structs
pub trait ClapData {
    /// The clap value name.
    const VALUE_NAME: &'static str;

    /// The clap help text for required arguments.
    ///
    /// Use this as the default help text if the value must be given.
    const HELP_REQUIRED: &'static str;

    /// The clap help text for optional arguments.
    ///
    /// Use this as the default help text if the value must not be
    /// given, because either:
    ///
    ///   - there is a default value, or
    ///   - the type is an `Option<T>`.
    const HELP_OPTIONAL: &'static str;
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
///         help = FileOrStdin::HELP_OPTIONAL,
///         value_name = FileOrStdin::VALUE_NAME,
///     )]
///     pub input: FileOrStdin,
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileOrStdin(Option<PathBuf>);

impl ClapData for FileOrStdin {
    const VALUE_NAME: &'static str = "FILE";
    const HELP_OPTIONAL: &'static str =
        "Read from FILE or stdin if FILE is '-'";
    const HELP_REQUIRED: &'static str =
        "Read from FILE or stdin if omitted";
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
    pub fn open<'a>(&self) -> Result<Box<dyn BufferedReader<Cookie> + 'a>> {
        if let Some(path) = self.inner() {
            Ok(Box::new(
                File::with_cookie(path, Default::default())
                .with_context(|| format!("Failed to open {}", self))?))
        } else {
            Ok(Box::new(
                Generic::with_cookie(stdin(), None, Default::default())))
        }
    }

    /// Return a reference to the optional PathBuf.
    pub fn path(&self) -> Option<&PathBuf> {
        self.0.as_ref()
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
///         help = FileOrCertStore::HELP_OPTIONAL,
///         long,
///         value_name = FileOrCertStore::VALUE_NAME,
///     )]
///     pub output: Option<FileOrStdout>,
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileOrCertStore{}

impl ClapData for FileOrCertStore {
    const VALUE_NAME: &'static str = "FILE";
    const HELP_REQUIRED: &'static str
        = "Write to FILE (or stdout if FILE is '-') instead of \
          importing into the certificate store";
    const HELP_OPTIONAL: &'static str
        = "Write to FILE (or stdout when omitted) instead of \
          importing into the certificate store";
}

/// Designates a certificate by path, by stdin, or by key handle.
///
/// Use [`Sq::lookup_one`] to read the certificate.
#[derive(Debug)]
pub enum FileStdinOrKeyHandle {
    FileOrStdin(FileOrStdin),
    KeyHandle(KeyHandle),
}

impl From<FileOrStdin> for FileStdinOrKeyHandle {
    fn from(file: FileOrStdin) -> Self {
        FileStdinOrKeyHandle::FileOrStdin(file)
    }
}

impl From<&str> for FileStdinOrKeyHandle {
    fn from(path: &str) -> Self {
        PathBuf::from(path).into()
    }
}

impl From<&Path> for FileStdinOrKeyHandle {
    fn from(path: &Path) -> Self {
        path.to_path_buf().into()
    }
}

impl From<PathBuf> for FileStdinOrKeyHandle {
    fn from(path: PathBuf) -> Self {
        FileStdinOrKeyHandle::FileOrStdin(path.into())
    }
}

impl From<&KeyHandle> for FileStdinOrKeyHandle {
    fn from(kh: &KeyHandle) -> Self {
        FileStdinOrKeyHandle::KeyHandle(kh.clone())
    }
}

impl From<KeyHandle> for FileStdinOrKeyHandle {
    fn from(kh: KeyHandle) -> Self {
        FileStdinOrKeyHandle::KeyHandle(kh)
    }
}

impl FileStdinOrKeyHandle {
    /// Returns whether this contains a `FileOrStdin`.
    pub fn is_file(&self) -> bool {
        match self {
            FileStdinOrKeyHandle::FileOrStdin(_) => true,
            FileStdinOrKeyHandle::KeyHandle(_) => false,
        }
    }

    /// Returns whether this contains a `KeyHandle`.
    pub fn is_key_handle(&self) -> bool {
        match self {
            FileStdinOrKeyHandle::FileOrStdin(_) => false,
            FileStdinOrKeyHandle::KeyHandle(_) => true,
        }
    }
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
///         help = FileOrStdout::HELP_OPTIONAL,
///         long,
///         value_name = FileOrStdout::VALUE_NAME,
///     )]
///     pub output: FileOrStdout,
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileOrStdout {
    path: Option<PathBuf>,

    /// If set, secret keys may be written to this sink.
    for_secrets: bool,
}

impl ClapData for FileOrStdout {
    const VALUE_NAME: &'static str = "FILE";
    const HELP_REQUIRED: &'static str =
        "Write to FILE or stdout if FILE is '-'";
    const HELP_OPTIONAL: &'static str =
        "Write to FILE or stdout if omitted";
}

impl FileOrStdout {
    pub fn new(path: Option<PathBuf>) -> Self {
        FileOrStdout {
            path,
            ..Default::default()
        }
    }

    /// Indicates that we will emit secrets.
    ///
    /// Use this to mark outputs where we intend to emit secret keys.
    pub fn for_secrets(mut self) -> Self {
        self.for_secrets = true;
        self
    }

    /// Queries whether we are configured to emit secrets.
    pub fn is_for_secrets(&self) -> bool {
        self.for_secrets
    }

    /// Return a reference to the optional PathBuf
    pub fn path(&self) -> Option<&PathBuf> {
        self.path.as_ref()
    }

}

impl Default for FileOrStdout {
    fn default() -> Self {
        FileOrStdout {
            path: None,
            for_secrets: false,
        }
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
        match &self.path {
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

/// Expiration information
///
/// This enum tracks expiry information either in the form of a timestamp or
/// a duration.
#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Expiration {
    /// An expiry timestamp
    Timestamp(Time),
    /// A validity duration
    Duration(Duration),
    /// There is no expiry
    Never,
}

impl Expiration {
    /// Create a new Expiration in a Result
    ///
    /// If `expiry` ends with `"y"`, `"m"`, `"w"`, `"w"`, `"d"` or `"s"` it
    /// is treated as a duration, which is parsed using `parse_duration()` and
    /// returned in an `Expiration::Duration`.
    /// If the special keyword `"never"` is provided as `expiry`,
    /// `Expiration::Never` is returned.
    /// If `expiry` is an ISO 8601 compatible string it is returned as
    /// `cli::types::Time` in an `Expiration::Timestamp`.
    pub fn new(expiry: &str) -> Result<Self> {
        match expiry {
            "never" => Ok(Expiration::Never),
            _ if expiry.ends_with("y")
                || expiry.ends_with("m")
                || expiry.ends_with("w")
                || expiry.ends_with("d")
                || expiry.ends_with("s") =>
            {
                Ok(Expiration::Duration(Expiration::parse_duration(expiry)?))
            }
            _ => Ok(Expiration::Timestamp(Time::from_str(expiry)?)),
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
                "Expiration must contain at least one digit and one factor."
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
                        format!("Expiration '{}' is out of range", digits)
                    ),
                } * match expiry.chars().last() {
                    Some('y') => SECONDS_IN_YEAR,
                    Some('m') => SECONDS_IN_YEAR / 12,
                    Some('w') => 7 * SECONDS_IN_DAY,
                    Some('d') => SECONDS_IN_DAY,
                    Some('s') => 1,
                    _ => unreachable!(
                        "Expiration without 'y', 'm', 'w', 'd' or 's' \
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
    /// time provided in an `Expiration::Timestamp(Time)`.
    ///
    /// If self is `Expiration::Timestamp(Time)`, `reference` is used as the start
    /// of a period, `Some(Time - reference)` is returned.
    /// If self is `Expiration::Duration(duration)`, `Some(duration)` is returned.
    /// If self is `Expiration::Never`, `None` is returned.
    pub fn as_duration(
        &self,
        reference: DateTime<Utc>,
    ) -> Result<Option<Duration>> {
        match self {
            Expiration::Timestamp(time) => Ok(
                Some(
                    SystemTime::from(time.time).duration_since(reference.into())?
                )
            ),
            Expiration::Duration(duration) => Ok(Some(duration.clone())),
            Expiration::Never => Ok(None),
        }
    }

    /// Return the expiry as absolute time.
    pub fn to_systemtime(&self, now: SystemTime) -> Option<SystemTime> {
        match self {
            Expiration::Timestamp(t) => Some(t.clone().into()),
            Expiration::Duration(d) => Some(now + *d),
            Expiration::Never => None,
        }
    }
}

impl FromStr for Expiration {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Expiration> {
        Expiration::new(s)
    }
}

impl Display for Expiration {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Expiration::Timestamp(time) => write!(f, "{}", time),
            Expiration::Duration(duration) => {
                let seconds = duration.as_secs();

                if seconds % SECONDS_IN_YEAR == 0 {
                    write!(f, "{}y", seconds / SECONDS_IN_YEAR)
                } else if seconds % (SECONDS_IN_YEAR / 12) == 0 {
                    write!(f, "{}m", seconds / (SECONDS_IN_YEAR / 12))
                } else if seconds % (SECONDS_IN_DAY * 7) == 0 {
                    write!(f, "{}w", seconds / (SECONDS_IN_DAY * 7))
                } else if seconds % SECONDS_IN_DAY == 0 {
                    write!(f, "{}d", seconds / SECONDS_IN_DAY)
                } else {
                    write!(f, "{}s", seconds)
                }
            },
            Expiration::Never => write!(f, "never"),
        }
    }
}

/// Describes the purpose of the encryption.
#[derive(ValueEnum, Clone, Debug)]
pub enum EncryptPurpose {
    /// Protects data in transport.
    Transport,

    /// Protects data at rest.
    Storage,

    /// Protects data in transport and at rest.
    Universal,
}

impl From<EncryptPurpose> for KeyFlags {
    fn from(p: EncryptPurpose) -> Self {
        match p {
            EncryptPurpose::Storage => {
                KeyFlags::empty().set_storage_encryption()
            }
            EncryptPurpose::Transport => {
                KeyFlags::empty().set_transport_encryption()
            }
            EncryptPurpose::Universal => KeyFlags::empty()
                .set_storage_encryption()
                .set_transport_encryption(),
        }
    }
}

/// Describes the purpose of the encryption.
#[derive(Copy, Clone, Debug)]
pub enum TrustAmount<T> {
    /// No trust.
    None,

    /// Partial trust.
    Partial,

    /// Full trust.
    Full,

    /// Double trust.
    Double,

    /// Other trust amount.
    Other(T),
}

impl<T: Copy + From<u8>> TrustAmount<T> {
    /// Returns the trust amount as numeric value.
    pub fn amount(&self) -> T {
        match self {
            TrustAmount::None => 0.into(),
            // See section 5.2.3.13. Trust Signature of RFC4880 for
            // the values of partial and full trust.
            TrustAmount::Partial => 60.into(),
            TrustAmount::Full => 120.into(),
            TrustAmount::Double => 240.into(),
            TrustAmount::Other(a) => *a,
        }
    }
}

impl<T: Display + FromStr> FromStr for TrustAmount<T>
where
    <T as FromStr>::Err: std::error::Error + Send + Sync + 'static,
{
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<TrustAmount<T>> {
        if s.eq_ignore_ascii_case("none") {
            Ok(TrustAmount::None)
        } else if s.eq_ignore_ascii_case("partial") {
            Ok(TrustAmount::Partial)
        } else if s.eq_ignore_ascii_case("full") {
            Ok(TrustAmount::Full)
        } else if s.eq_ignore_ascii_case("double") {
            Ok(TrustAmount::Double)
        } else {
            Ok(TrustAmount::Other(s.parse()?))
        }
    }
}

impl<T: Display + FromStr> Display for TrustAmount<T> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            TrustAmount::None => f.write_str("none"),
            TrustAmount::Partial => f.write_str("partial"),
            TrustAmount::Full => f.write_str("full"),
            TrustAmount::Double => f.write_str("double"),
            TrustAmount::Other(a) => write!(f, "{}", a),
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
                return Ok(Utc.from_utc_datetime(&d));
            }
        }
        for f in &["%Y-%m-%d", "%Y-%m", "%Y-%j", "%Y%m%d", "%Y%m", "%Y%j", "%Y"]
        {
            if let Ok(d) = chrono::NaiveDate::parse_from_str(s, *f) {
                return Ok(Utc.from_utc_datetime(&d.and_time(pad_date_with)));
            }
        }
        Err(anyhow::anyhow!("Malformed ISO8601 timestamp: {}.\n\
                             Try: YYYY-MM-DD[Thh:mm[:ss][[+|-]hh[:mm]]]", s))
    }
}

impl Display for Time {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", self.time)
    }
}

#[cfg(test)]
mod test {
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
            Expiration::new("1y").unwrap(),
            Expiration::Duration(Duration::new(SECONDS_IN_YEAR, 0)),
        );
        assert_eq!(
            Expiration::new("2023-05-15T20:00:00Z").unwrap(),
            Expiration::Timestamp(Time::from_str("2023-05-15T20:00:00Z").unwrap()),
        );
        assert_eq!(
            Expiration::new("never").unwrap(),
            Expiration::Never,
        );
    }

    #[test]
    fn test_expiry_parse_duration() {
        assert_eq!(
            Expiration::parse_duration("1y").unwrap(),
            Duration::new(SECONDS_IN_YEAR, 0),
        );
        assert!(Expiration::parse_duration("f").is_err());
        assert!(Expiration::parse_duration("-1y").is_err());
        assert!(Expiration::parse_duration("foo").is_err());
        assert!(Expiration::parse_duration("1o").is_err());
    }

    #[test]
    fn test_expiry_as_duration() {
        let reference = DateTime::from_timestamp(1, 0).unwrap();

        let expiry = Expiration::Timestamp(
            Time::try_from(DateTime::from_timestamp(2, 0).unwrap())
                .expect("valid"));
        assert_eq!(
            expiry.as_duration(reference).unwrap(),
            Some(Duration::new(1, 0)),
        );

        let expiry = Expiration::Duration(Duration::new(2,0));
        assert_eq!(
            expiry.as_duration(reference).unwrap(),
            Some(Duration::new(2, 0)),
        );

        let expiry = Expiration::Never;
        assert_eq!(expiry.as_duration(reference).unwrap(), None);
    }

    #[test]
    fn test_expiry_as_duration_errors() {
        let reference = DateTime::from_timestamp(2, 0).unwrap();
        let expiry = Expiration::Timestamp(
            Time::try_from(DateTime::from_timestamp(1, 0).unwrap())
                .expect("valid"));
        assert!(expiry.as_duration(reference).is_err());
    }
}
