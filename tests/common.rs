#![allow(unused)]

use std::path::Path;
use std::path::PathBuf;
use std::process::Output;

use anyhow::anyhow;
use assert_cmd::Command;

use chrono::DateTime;
use chrono::Duration;
use chrono::Utc;

use openpgp::packet::Signature;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::Cert;
use openpgp::KeyHandle;
use openpgp::Result;
use sequoia_openpgp as openpgp;

use tempfile::TempDir;

pub const STANDARD_POLICY: &StandardPolicy = &StandardPolicy::new();

// Returns the power set excluding the empty set.
pub fn power_set<T: Clone>(set: &[T]) -> Vec<Vec<T>> {
    let mut power_set: Vec<Vec<T>> = Vec::new();
    for element in set.iter() {
        power_set.extend(
            power_set.clone().into_iter().map(|mut v: Vec<T>| {
                v.push(element.clone());
                v
            }));
        power_set.push(vec![ element.clone() ]);
    }
    power_set
}

/// Returns the time formatted as an ISO 8106 string.
pub fn time_as_string(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}


pub struct Sq {
    base: TempDir,
    home: PathBuf,
    now: std::time::SystemTime,
}

impl Sq {
    /// Creates a new Sq context in a new, emphemeral home directory.
    /// The clock is set to the specified time.
    pub fn at(now: std::time::SystemTime) -> Self {
        let base = TempDir::new()
            .expect("can create a temporary directory");
        let home = base.path().join("home");

        Sq {
            base,
            home,
            now,
        }
    }

    /// Creates a new Sq context in a new, emphemeral home directory.
    /// The clock is set to the current time.
    pub fn new() -> Self {
        // The current time.
        let mut now = std::time::SystemTime::now();
        let since_epoch = now.duration_since(std::time::UNIX_EPOCH).unwrap();
        now = now - std::time::Duration::new(0, since_epoch.subsec_nanos());

        Self::at(now)
    }

    /// Returns the base directory.
    ///
    /// The sequoia home directory is under the `home` subdirectory.
    /// The rest can be used as scratch space.
    pub fn base(&self) -> &Path {
        self.base.path()
    }

    /// Returns the home directory.
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// Returns the current time.
    pub fn now(&self) -> std::time::SystemTime {
        self.now
    }

    /// Returns the current time formatted as an ISO 8106 string.
    pub fn now_as_string(&self) -> String {
        time_as_string(self.now.into())
    }

    /// Advances the clock by `sec` number of seconds.
    pub fn tick(&mut self, secs: u64)
    {
        self.now += std::time::Duration::new(secs, 0);
    }

    /// Returns a command that is set to run `sq`.  The home directory
    /// and time are already set.
    pub fn command(&self) -> Command {
        let mut cmd = Command::cargo_bin("sq")
            .expect("can run sq");
        cmd.arg("--home").arg(self.home());
        cmd.arg("--time").arg(&self.now_as_string());

        cmd
    }

    /// Runs the command.  If `expect` is `Some`, asserts that the
    /// command succeeds or fails as per the boolean.
    pub fn run<E>(&self, mut cmd: Command, expect: E) -> Output
        where E: Into<Option<bool>>
    {
        eprintln!("Running: {:?}", cmd);
        let output = cmd.output().expect("can run command");
        if let Some(expect) = expect.into() {
            match (output.status.success(), expect) {
                (true, true) => (),
                (false, false) => (),
                (got, expected) => {
                    panic!(
                        "Running {:?}: {}, but should have {}:\n\
                         stdout: {}\n\
                         stderr: {}",
                        cmd,
                        if got { "succeeded" } else { "failed" },
                        if expected { "succeeded" } else { "failed" },
                        &String::from_utf8_lossy(&output.stdout),
                        &String::from_utf8_lossy(&output.stderr));
                }
            }
        }
        output
    }

    pub fn inspect<P>(&self, path: P) -> String
    where P: AsRef<Path>
    {
        let mut cmd = self.command();
        cmd.arg("inspect").arg(path.as_ref());
        let output = self.run(cmd, Some(true));
        String::from_utf8_lossy(&output.stdout).to_string()
    }
}

/// Generate a new key in a temporary directory and return its TempDir,
/// PathBuf and creation time in a Result
pub fn sq_key_generate(
    userids: Option<&[&str]>,
) -> Result<(TempDir, PathBuf, DateTime<Utc>)> {
    let tmpdir = TempDir::new().unwrap();
    let path = tmpdir.path().join("key.pgp");
    let mut time = Utc::now();
    // Round it down to a whole second to match the resolution of
    // OpenPGP's timestamp.
    time = time - Duration::nanoseconds(time.timestamp_subsec_nanos() as i64);
    let userids = if let Some(userids) = userids {
        userids
    } else {
        &["alice <alice@example.org>"]
    };

    let mut cmd = Command::cargo_bin("sq")?;
    cmd.args([
        "--no-cert-store",
        "--no-key-store",
        "key",
        "generate",
        "--time",
        &time.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        "--expiry",
        "never",
        "--output",
        &*path.to_string_lossy(),
    ]);
    for userid in userids {
        cmd.args(["--userid", userid]);
    }
    cmd.assert().success();

    let original_cert = Cert::from_file(&path)?;
    let original_valid_cert =
        original_cert.with_policy(STANDARD_POLICY, None)?;
    assert_eq!(
        original_valid_cert
            .keys()
            .filter(|x| x.for_authentication())
            .count(),
        1
    );
    assert_eq!(
        original_valid_cert
            .keys()
            .filter(|x| x.for_certification())
            .count(),
        1
    );
    assert_eq!(
        original_valid_cert
            .keys()
            .filter(|x| x.for_signing())
            .count(),
        1
    );
    assert_eq!(
        original_valid_cert
            .keys()
            .filter(|x| x.for_storage_encryption())
            .count(),
        1
    );
    assert_eq!(
        original_valid_cert
            .keys()
            .filter(|x| x.for_transport_encryption())
            .count(),
        1
    );

    Ok((tmpdir, path, time))
}

/// Ensure notations can be found in a Signature
///
/// ## Errors
///
/// Returns an error if a notation can not be found in the Signature
pub fn compare_notations(
    signature: &Signature,
    notations: Option<&[(&str, &str); 2]>,
) -> Result<()> {
    if let Some(notations) = notations {
        let found_notations: Vec<(&str, String)> = signature
            .notation_data()
            .map(|n| (n.name(), String::from_utf8_lossy(n.value()).into()))
            .collect();

        for (key, value) in notations {
            if !found_notations.contains(&(key, String::from(*value))) {
                return Err(anyhow!(format!(
                    "Expected notation \"{}: {}\" in {:?}",
                    key, value, found_notations
                )));
            }
        }
    }
    Ok(())
}
