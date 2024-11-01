use std::fmt::Display;
use std::fmt::Formatter;
use std::time::SystemTime;

use chrono::offset::Utc;
use chrono::DateTime;
use chrono::TimeZone;

use sequoia_openpgp as openpgp;
use openpgp::types::Timestamp;

use crate::Result;

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
        write!(f, "{}",
               chrono::DateTime::<chrono::offset::Utc>::from(
                   SystemTime::from(self.time)))
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
}
