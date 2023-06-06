use std::fmt::Display;
use std::fmt::Formatter;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use std::time::SystemTime;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;

use chrono::{offset::Utc, DateTime};
/// Common types for arguments of sq.
use clap::{ValueEnum, Args};

use openpgp::fmt::hex;
use openpgp::types::SymmetricAlgorithm;
use sequoia_openpgp as openpgp;

use crate::sq_cli::SECONDS_IN_DAY;
use crate::sq_cli::SECONDS_IN_YEAR;

#[derive(Debug, Args)]
pub struct IoArgs {
    #[clap(value_name = "FILE", help = "Reads from FILE or stdin if omitted")]
    pub input: Option<PathBuf>,
    #[clap(
        short,
        long,
        value_name = "FILE",
        help = "Writes to FILE or stdout if omitted"
    )]
    pub output: Option<PathBuf>,
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
    /// `sq_cli::types::Time` in an `Expiry::Timestamp`.
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
            Expiry::Timestamp(time) => write!(f, "{:?}", time),
            Expiry::Duration(duration) => write!(f, "{:?}", duration),
            Expiry::Never => write!(f, "never"),
        }
    }
}

#[derive(ValueEnum, Clone, Debug)]
pub enum NetworkPolicy {
    Offline,
    Anonymized,
    Encrypted,
    Insecure,
}

impl From<NetworkPolicy> for sequoia_net::Policy {
    fn from(kp: NetworkPolicy) -> Self {
        match kp {
            NetworkPolicy::Offline => sequoia_net::Policy::Offline,
            NetworkPolicy::Anonymized => sequoia_net::Policy::Anonymized,
            NetworkPolicy::Encrypted => sequoia_net::Policy::Encrypted,
            NetworkPolicy::Insecure => sequoia_net::Policy::Insecure,
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Time {
    pub time: DateTime<Utc>,
}

impl std::str::FromStr for Time {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Time> {
        let time =
            Time::parse_iso8601(s, chrono::NaiveTime::from_hms_opt(0, 0, 0)
                                .unwrap())?;
        Ok(Time { time })
    }
}

impl Time {
    /// Returns the time as openpgp::types::Timestamp.
    pub fn timestamp(&self) -> Result<openpgp::types::Timestamp> {
        let seconds = u32::try_from(self.time.naive_utc().timestamp())
           .map_err(|_| anyhow!("Time {} not representable", self.time))?;
        Ok(seconds.try_into()?)
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
            Time{
                time: DateTime::from_utc(
                    NaiveDateTime::from_timestamp_opt(2, 0).unwrap(),
                    Utc,
                )}
        );
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
            Time{
                time: DateTime::from_utc(
                    NaiveDateTime::from_timestamp_opt(1, 0).unwrap(),
                    Utc,
                )}
        );
        assert!(expiry.as_duration(reference).is_err());
    }
}
