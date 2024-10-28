use std::fmt::Display;
use std::fmt::Formatter;
use std::str::FromStr;
use std::time::Duration;
use std::time::SystemTime;

use anyhow::Context;

use chrono::DateTime;
use chrono::Utc;

use crate::cli::types::SECONDS_IN_DAY;
use crate::cli::types::SECONDS_IN_YEAR;
use crate::cli::types::Time;
use crate::Result;

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

#[cfg(test)]
mod test {
    use super::*;

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
