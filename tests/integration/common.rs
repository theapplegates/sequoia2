#![allow(unused)]

use std::borrow::Borrow;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs::File;
use std::path::Path;
use std::path::PathBuf;
use std::process::Output;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use anyhow::anyhow;
use anyhow::Context;

use assert_cmd::Command;

use chrono::DateTime;
use chrono::Duration;
use chrono::Utc;

use openpgp::packet::Signature;
use openpgp::parse::Parse;
use openpgp::policy::NullPolicy;
use openpgp::policy::StandardPolicy;
use openpgp::Cert;
use openpgp::cert::CertParser;
use openpgp::Fingerprint;
use openpgp::KeyHandle;
use openpgp::Result;
use openpgp::serialize::Serialize;
use sequoia_openpgp as openpgp;

use tempfile::TempDir;

pub const STANDARD_POLICY: &StandardPolicy = &StandardPolicy::new();
pub const NULL_POLICY: &NullPolicy = &NullPolicy::new();

pub fn artifact(filename: &str) -> PathBuf {
    PathBuf::from("tests/data").join(filename)
}

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

/// Designates a certificate by path, or by key handle.
#[derive(Clone, Debug)]
pub enum FileOrKeyHandle {
    FileOrStdin(PathBuf),
    KeyHandle((KeyHandle, OsString)),
}

impl From<&str> for FileOrKeyHandle {
    fn from(path: &str) -> Self {
        PathBuf::from(path).into()
    }
}

impl From<String> for FileOrKeyHandle {
    fn from(path: String) -> Self {
        PathBuf::from(path).into()
    }
}

impl From<&Path> for FileOrKeyHandle {
    fn from(path: &Path) -> Self {
        path.to_path_buf().into()
    }
}

impl From<&PathBuf> for FileOrKeyHandle {
    fn from(path: &PathBuf) -> Self {
        path.clone().into()
    }
}

impl From<PathBuf> for FileOrKeyHandle {
    fn from(path: PathBuf) -> Self {
        FileOrKeyHandle::FileOrStdin(path.into())
    }
}

impl From<&KeyHandle> for FileOrKeyHandle {
    fn from(kh: &KeyHandle) -> Self {
        FileOrKeyHandle::KeyHandle((kh.clone(), kh.to_string().into()))
    }
}

impl From<KeyHandle> for FileOrKeyHandle {
    fn from(kh: KeyHandle) -> Self {
        let s = kh.to_string().into();
        FileOrKeyHandle::KeyHandle((kh, s))
    }
}

impl From<&Fingerprint> for FileOrKeyHandle {
    fn from(fpr: &Fingerprint) -> Self {
        KeyHandle::from(fpr).into()
    }
}

impl From<Fingerprint> for FileOrKeyHandle {
    fn from(fpr: Fingerprint) -> Self {
        KeyHandle::from(fpr).into()
    }
}

impl From<&FileOrKeyHandle> for FileOrKeyHandle {
    fn from(h: &FileOrKeyHandle) -> Self {
        h.clone()
    }
}

impl AsRef<OsStr> for FileOrKeyHandle {
    fn as_ref(&self) -> &OsStr {
        match self {
            FileOrKeyHandle::FileOrStdin(file) => file.as_os_str(),
            FileOrKeyHandle::KeyHandle((kh, s)) => s.as_os_str(),
        }
    }
}

impl FileOrKeyHandle {
    /// Returns whether this contains a `FileOrStdin`.
    pub fn is_file(&self) -> bool {
        match self {
            FileOrKeyHandle::FileOrStdin(_) => true,
            FileOrKeyHandle::KeyHandle(_) => false,
        }
    }

    /// Returns whether this contains a `KeyHandle`.
    pub fn is_key_handle(&self) -> bool {
        match self {
            FileOrKeyHandle::FileOrStdin(_) => false,
            FileOrKeyHandle::KeyHandle(_) => true,
        }
    }
}

pub struct Sq {
    base: TempDir,
    // Whether to preserve the directory on exit.  Normally we clean
    // it up, but preserving it can simplify debugging when a test
    // fails.
    preserve: bool,
    home: PathBuf,
    policy: PathBuf,
    certd: PathBuf,
    now: std::time::SystemTime,
    scratch: AtomicUsize,
}

impl Drop for Sq {
    fn drop(&mut self) {
        if self.preserve {
            self.preserve = false;

            match TempDir::new() {
                Ok(tmp) => {
                    let base = std::mem::replace(&mut self.base, tmp);
                    let path = base.into_path();
                    eprintln!("Preserving state in {}", path.display());
                }
                Err(err) => {
                    eprintln!("Error preserving state in {}: {}",
                              self.base.path().display(), err);
                }
            }
        }
    }
}

impl Sq {
    /// Creates a new Sq context in a new, emphemeral home directory.
    /// The clock is set to the specified time.
    pub fn at(now: std::time::SystemTime) -> Self {
        let base = TempDir::new()
            .expect("can create a temporary directory");
        let home = base.path().join("home");

        // Create an empty policy configuration file.  We use this
        // instead of the system-wide policy configuration file, which
        // might be more strict than what our test vectors expect.
        let policy = base.path().join("empty-policy.toml");
        std::fs::write(&policy, "").unwrap();

        let certd = home.join("data").join("pgp.cert.d");

        Sq {
            base,
            preserve: false,
            home,
            policy,
            certd,
            now,
            scratch: 0.into(),
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

    /// Preserves the files on exit.
    ///
    /// Normally we clean delete all files and directories.  This
    /// suppresses that behavior.  Preserving the state can facilitate
    /// debugging.  Normally, you'll only enable this to debug a test,
    /// and then disable it again.
    pub fn preserve(&mut self) {
        self.preserve = true;
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

    /// Returns the path to the cert.d.
    pub fn certd(&self) -> &Path {
        &self.certd
    }

    /// Returns the scratch directory.
    pub fn scratch_dir(&self) -> PathBuf {
        let dir = self.home.join("scratch");
        std::fs::create_dir_all(&dir)
            .expect("can create scratch directory");
        dir
    }

    /// Returns a new scratch file.
    ///
    /// The file is guaranteed to not exist, but it isn't actually
    /// created.
    pub fn scratch_file<'a, S>(&self, name: S) -> PathBuf
        where S: Into<Option<&'a str>>
    {
        let name = name.into();

        let name_;
        let name = if let Some(name) = name {
            name_ = name.chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() {
                        c
                    } else {
                        '-'
                    }
                })
                .collect::<String>();
            &name_
        } else {
            name.unwrap_or("scratch-file")
        };

        let dir = self.scratch_dir();
        loop {
            let i = self.scratch.fetch_add(1, Ordering::Relaxed);
            let file = dir.join(format!("{}-{}", i, name));
            if ! file.exists() {
                return file;
            }
        }
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
        cmd.env("SEQUOIA_CRYPTO_POLICY", &self.policy);
        cmd.arg("--batch");
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
        let expect = expect.into();
        match (output.status.success(), expect) {
            (true, Some(true)) | (false, Some(false)) | (_, None) => {
                eprintln!("Exit status:");

                let dump = |id, stream| {
                    let limit = 70;

                    let data = String::from_utf8_lossy(stream)
                        .chars()
                        .collect::<Vec<_>>();

                    if data.is_empty() {
                        eprintln!("{}: empty", id);
                    } else {
                        eprintln!("{}: {}{}",
                                  id,
                                  data.iter().take(limit).collect::<String>(),
                                  if data.len() > limit {
                                      format!("... {} more bytes",
                                              data.len() - limit)
                                  } else {
                                      "".to_string()
                                  });
                    }
                };

                dump("stdout", &output.stdout);
                dump("stderr", &output.stderr);
            }
            (got, expected) => {
                let expected = expect.unwrap();

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
        output
    }

    /// Decrypts a message.
    pub fn decrypt<M>(&self, args: &[&str], msg: M) -> Vec<u8>
    where M: AsRef<[u8]>,
    {
        self.decrypt_maybe(args, msg).expect("can decrypt")
    }

    /// Decrypts a message.
    pub fn decrypt_maybe<M>(&self, args: &[&str], msg: M) -> Result<Vec<u8>>
    where M: AsRef<[u8]>,
    {
        let mut cmd = self.command();
        cmd.args([ "decrypt" ]);
        for arg in args {
            cmd.arg(arg);
        }
        cmd.write_stdin(msg.as_ref());
        let output = self.run(cmd, None);

        if output.status.success() {
            Ok(output.stdout.to_vec())
        } else {
            Err(anyhow::anyhow!("sq decrypt returned an error"))
        }
    }

    /// Encrypts a message.
    pub fn encrypt<A, M>(&self, args: &[A], msg: M) -> Vec<u8>
    where A: AsRef<str>,
          M: AsRef<[u8]>,
    {
        self.encrypt_maybe(args, msg).expect("can encrypt")
    }

    /// Encrypts a message.
    pub fn encrypt_maybe<A, M>(&self, args: &[A], msg: M) -> Result<Vec<u8>>
    where A: AsRef<str>,
          M: AsRef<[u8]>,
    {
        let mut cmd = self.command();
        cmd.args([ "encrypt" ]);
        for arg in args {
            cmd.arg(arg.as_ref());
        }
        cmd.write_stdin(msg.as_ref());
        let output = self.run(cmd, None);

        if output.status.success() {
            Ok(output.stdout.to_vec())
        } else {
            Err(anyhow::anyhow!("sq encrypt returned an error"))
        }
    }

    /// Generates a new key.
    ///
    /// The certificate is not imported into the cert store or key
    /// store, but saved in a file.
    ///
    /// Returns the certificate, the certificate's filename, and the
    /// revocation certificate's filename.
    pub fn key_generate(&self,
                        extra_args: &[&str],
                        userids: &[&str])
        -> (Cert, PathBuf, PathBuf)
    {
        let mut cmd = self.command();
        cmd.args([ "key", "generate" ]);

        if ! extra_args.contains(&"--new-password-file") {
            cmd.arg("--without-password");
        }

        for arg in extra_args {
            cmd.arg(arg);
        }

        let any_userids = ! userids.is_empty()
            || extra_args.iter().any(|a| a.starts_with("--name")
                                     || a.starts_with("--email"));
        if ! any_userids {
            cmd.arg("--no-userids");
        } else {
            for userid in userids {
                cmd.arg("--userid").arg(userid);
            }
        }

        let cert_filename = self.scratch_file(
            userids.get(0).map(|u| format!("{}-cert", u)).as_deref());
        cmd.arg("--output").arg(&cert_filename);

        let rev_filename = self.scratch_file(
            userids.get(0).map(|u| format!("{}-rev", u)).as_deref());
        cmd.arg("--rev-cert").arg(&rev_filename);

        let output = self.run(cmd, Some(true));

        let cert = Cert::from_file(&cert_filename)
            .expect("can parse certificate");
        assert!(cert.is_tsk());

        (cert, cert_filename, rev_filename)
    }

    /// Run `sq inspect` and return stdout.
    pub fn inspect<H>(&self, handle: H) -> String
    where H: Into<FileOrKeyHandle>
    {
        let mut cmd = self.command();
        cmd.arg("inspect");
        match handle.into() {
            FileOrKeyHandle::FileOrStdin(path) => {
                cmd.arg(path);
            }
            FileOrKeyHandle::KeyHandle((_kh, s)) => {
                cmd.arg("--cert").arg(&s);
            }
        };

        let output = self.run(cmd, Some(true));
        String::from_utf8_lossy(&output.stdout).to_string()
    }

    /// Delete the specified key.
    pub fn key_delete<'a, H, Q>(&self,
                                cert_handle: H,
                                output_file: Q)
        -> Cert
    where H: Into<FileOrKeyHandle>,
          Q: Into<Option<&'a Path>>,
    {
        let cert_handle = cert_handle.into();
        let output_file = output_file.into();

        let mut cmd = self.command();
        cmd.arg("key").arg("delete");

        match &cert_handle {
            FileOrKeyHandle::FileOrStdin(path) => {
                cmd.arg("--cert-file").arg(path);
            }
            FileOrKeyHandle::KeyHandle((_kh, s)) => {
                cmd.arg("--cert").arg(&s);
            }
        };

        if let Some(output_file) = output_file {
            cmd.arg("--output").arg(output_file);
        }

        let output = self.run(cmd, Some(true));
        assert!(output.status.success());

        if let Some(output_file) = output_file {
            if output_file != &PathBuf::from("-") {
                return Cert::from_file(output_file)
                    .expect("can parse certificate");
            }
        } else if output_file.is_none() {
            if let FileOrKeyHandle::KeyHandle((kh, _s)) = cert_handle {
                return self.cert_export(kh);
            }
        }
        Cert::from_bytes(&output.stdout)
            .expect("can parse certificate")
    }

    /// Run `sq key revoked` and return the revocation certificate.
    pub fn key_revoke<'a, H, I, Q>(&self,
                                cert_handle: H,
                                revoker_handle: I,
                                reason: &str,
                                message: &str,
                                revocation_time: Option<DateTime<Utc>>,
                                notations: &[(&str, &str)],
                                output_file: Q)
        -> Cert
        where H: Into<FileOrKeyHandle>,
              I: Into<Option<FileOrKeyHandle>>,
              Q: Into<Option<&'a Path>>,
    {
        let cert_handle = cert_handle.into();
        let revoker_handle = revoker_handle.into();
        let output_file = output_file.into();

        let mut cmd = self.command();
        cmd.arg("key").arg("revoke")
            .arg(reason)
            .arg(message);

        match &cert_handle {
            FileOrKeyHandle::FileOrStdin(path) => {
                cmd.arg("--cert-file").arg(path);
            }
            FileOrKeyHandle::KeyHandle((_kh, s)) => {
                cmd.arg("--cert").arg(&s);
            }
        };
        match revoker_handle.as_ref() {
            Some(FileOrKeyHandle::FileOrStdin(path)) => {
                cmd.arg("--revoker-file").arg(path);
            }
            Some(FileOrKeyHandle::KeyHandle((_kh, s))) => {
                cmd.arg("--revoker").arg(&s);
            }
            None => (),
        };

        if let Some(output_file) = output_file {
            cmd.arg("--output").arg(output_file);
        }

        for (k, v) in notations {
            cmd.args(["--notation", k, v]);
        }

        if let Some(time) = revocation_time {
            cmd.args([
                "--time",
                &time.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            ]);
        }

        let output = self.run(cmd, Some(true));
        assert!(output.status.success());

        if let Some(output_file) = output_file {
            if output_file != &PathBuf::from("-") {
                return Cert::from_file(output_file)
                    .expect("can parse certificate");
            }
        } else if output_file.is_none() {
            if let FileOrKeyHandle::KeyHandle((kh, _s)) = cert_handle {
                return self.cert_export(kh);
            }
        }
        Cert::from_bytes(&output.stdout)
            .expect("can parse certificate")
    }

    /// Imports the specified key into the keystore.
    pub fn key_import<P>(&self, path: P)
    where P: AsRef<Path>
    {
        let mut cmd = self.command();
        cmd.arg("key").arg("import").arg(path.as_ref());
        self.run(cmd, Some(true));
    }

    /// Exports the specified key.
    pub fn key_export(&self, kh: KeyHandle) -> Cert {
        self.key_export_maybe(kh)
            .expect("can export key")
    }

    /// Exports the specified key from the key store.
    ///
    /// Returns an error if `sq key export` fails.  This happens if
    /// the certificate is known, but the key store doesn't manage any
    /// of its secret key material.
    pub fn key_export_maybe(&self, kh: KeyHandle) -> Result<Cert> {
        let mut cmd = self.command();
        cmd.args([ "key", "export", "--cert", &kh.to_string() ]);
        let output = self.run(cmd, None);

        if output.status.success() {
            Ok(Cert::from_bytes(&output.stdout).expect("can parse certificate"))
        } else {
            Err(anyhow::anyhow!("sq key export returned an error"))
        }
    }

    /// Change the key's password.
    pub fn key_password<'a, H, Q>(&self,
                                  cert_handle: H,
                                  old_password_file: Option<&'a Path>,
                                  new_password_file: Option<&'a Path>,
                                  output_file: Q,
                                  success: bool)
                                  -> Result<Cert>
    where
        H: Into<FileOrKeyHandle>,
        Q: Into<Option<&'a Path>>,
    {
        let cert_handle = cert_handle.into();
        let output_file = output_file.into();

        let mut cmd = self.command();
        cmd.arg("key").arg("password");

        if cert_handle.is_file() {
            cmd.arg("--cert-file").arg(&cert_handle);
        } else {
            cmd.arg("--cert").arg(&cert_handle);
        };

        if let Some(p) = old_password_file {
            cmd.arg("--password-file").arg(p);
        }

        if let Some(p) = new_password_file {
            cmd.arg("--new-password-file").arg(p);
        } else {
            cmd.arg("--clear-password");
        }

        if let Some(output_file) = output_file {
            cmd.arg("--output").arg(output_file);
        }

        let output = self.run(cmd, Some(success));
        if output.status.success() {
            if let Some(output_file) = output_file {
                if output_file != &PathBuf::from("-") {
                    return Ok(Cert::from_file(output_file)
                        .expect("can parse certificate"));
                }
            } else if output_file.is_none() {
                if let FileOrKeyHandle::KeyHandle((kh, _s)) = cert_handle {
                    return Ok(self.key_export(kh));
                }
            }
            Ok(Cert::from_bytes(&output.stdout)
                .expect("can parse certificate"))
        } else {
            Err(anyhow::anyhow!(format!(
                "Failed (expected):\n{}",
                String::from_utf8_lossy(&output.stderr))))
        }
    }

    /// Target is a certificate.
    ///
    /// `keys` is the set of keys to adopt.
    pub fn key_adopt<P, T, K, Q>(&self,
                                 keyrings: Vec<P>,
                                 target: T,
                                 keys: Vec<K>,
                                 expire: Option<DateTime<Utc>>,
                                 allow_broken_crypto: bool,
                                 output_file: Q,
                                 success: bool)
        -> Result<Cert>
    where
        P: AsRef<Path>,
        T: Into<FileOrKeyHandle>,
        K: Into<KeyHandle>,
        Q: AsRef<Path>,
    {
        let target = target.into();
        let output_file = output_file.as_ref();

        let mut cmd = self.command();
        cmd.arg("key").arg("adopt");

        for k in keyrings.into_iter() {
            cmd.arg("--keyring").arg(k.as_ref());
        }

        if target.is_file() {
            cmd.arg("--cert-file").arg(target);
        } else {
            cmd.arg("--cert").arg(target);
        };

        assert!(! keys.is_empty());
        for k in keys.into_iter() {
            let k: KeyHandle = k.into();
            cmd.arg("--key").arg(k.to_string());
        }

        if let Some(expire) = expire {
            cmd.arg("--expire").arg(time_as_string(expire.into()));
        }

        if allow_broken_crypto {
            cmd.arg("--allow-broken-crypto");
        }

        cmd.arg("--output").arg(&output_file);

        let output = self.run(cmd, Some(success));
        if output.status.success() {
            let cert = if output_file == PathBuf::from("-") {
                Cert::from_bytes(&output.stdout)
                    .expect("can parse certificate")
            } else {
                Cert::from_file(output_file)
                    .expect("can parse certificate")
            };

            Ok(cert)
        } else {
            Err(anyhow::anyhow!(format!(
                "Failed (expected):\n{}",
                String::from_utf8_lossy(&output.stderr))))
        }
    }

    pub fn key_approvals_update<'a, H, Q>(&self,
                                          cert: H,
                                          args: &[&str],
                                          output_file: Q)
        -> Cert
    where H: Into<FileOrKeyHandle>,
          Q: Into<Option<&'a Path>>,
    {
        let cert = cert.into();
        let output_file = output_file.into();

        let mut cmd = self.command();
        cmd.arg("key").arg("approvals").arg("update");

        match &cert {
            FileOrKeyHandle::FileOrStdin(file) => {
                cmd.arg("--cert-file").arg(file);
            }
            FileOrKeyHandle::KeyHandle((_kh, s)) => {
                cmd.arg("--cert").arg(s);
            }
        }

        cmd.args(args);

        if let Some(output_file) = output_file {
            cmd.arg("--output").arg(output_file);
        }

        let output = self.run(cmd, Some(true));

        if let Some(output_file) = output_file {
            if output_file != &PathBuf::from("-") {
                return Cert::from_file(output_file)
                    .expect("can parse certificate");
            }
        } else if output_file.is_none() {
            if let FileOrKeyHandle::KeyHandle((kh, _s)) = cert {
                return self.cert_export(kh);
            }
        }
        Cert::from_bytes(&output.stdout)
            .expect("can parse certificate")
    }

    /// Exports the specified keys.
    pub fn key_subkey_export<H>(&self, khs: Vec<H>) -> Vec<Cert>
    where H: Into<KeyHandle>
    {
        self.key_subkey_export_maybe(khs)
            .expect("can export key")
    }

    /// Exports the specified keys from the key store.
    ///
    /// Returns an error if `sq key subkey export` fails.  This
    /// happens if the key is known, but the key store doesn't manage
    /// any of its secret key material.
    pub fn key_subkey_export_maybe<H>(&self, khs: Vec<H>) -> Result<Vec<Cert>>
    where H: Into<KeyHandle>
    {
        let mut cmd = self.command();
        cmd.args([ "key", "subkey", "export" ]);
        for kh in khs.into_iter() {
            let kh: KeyHandle = kh.into();
            cmd.arg("--key").arg(kh.to_string());
        }
        let output = self.run(cmd, None);

        if output.status.success() {
            let parser = CertParser::from_bytes(&output.stdout)
                .expect("can parse certificate");
            Ok(parser.collect::<Result<Vec<Cert>>>()?)
        } else {
            Err(anyhow::anyhow!("sq key export returned an error"))
        }
    }

    /// Delete the specified key.
    pub fn key_subkey_delete<'a, H, Q>(&self,
                                       cert_handle: H,
                                       key_handles: &[KeyHandle],
                                       output_file: Q)
        -> Cert
    where H: Into<FileOrKeyHandle>,
          Q: Into<Option<&'a Path>>,
    {
        let cert_handle = cert_handle.into();
        let output_file = output_file.into();

        let mut cmd = self.command();
        cmd.arg("key").arg("subkey").arg("delete");

        match &cert_handle {
            FileOrKeyHandle::FileOrStdin(path) => {
                cmd.arg("--cert-file").arg(path);
            }
            FileOrKeyHandle::KeyHandle((_kh, s)) => {
                cmd.arg("--cert").arg(&s);
            }
        };

        for kh in key_handles {
            cmd.arg("--key").arg(kh.to_string());
        }

        if let Some(output_file) = output_file {
            cmd.arg("--output").arg(output_file);
        }

        let output = self.run(cmd, Some(true));
        assert!(output.status.success());

        if let Some(output_file) = output_file {
            if output_file != &PathBuf::from("-") {
                return Cert::from_file(output_file)
                    .expect("can parse certificate");
            }
        } else if output_file.is_none() {
            if let FileOrKeyHandle::KeyHandle((kh, _s)) = cert_handle {
                // This will fail if the key no longer has any secret
                // key material.  If it fails, fall back to `sq cert
                // export`.
                if let Ok(cert) = self.key_export_maybe(kh.clone()) {
                    return cert;
                } else {
                    return self.cert_export(kh.clone());
                }
            }
        }
        Cert::from_bytes(&output.stdout)
            .expect("can parse certificate")
    }

    /// Change the key's password.
    pub fn key_subkey_password<'a, H, Q>(&self,
                                         cert_handle: H,
                                         keys: &[KeyHandle],
                                         old_password_file: Option<&'a Path>,
                                         new_password_file: Option<&'a Path>,
                                         output_file: Q,
                                         success: bool)
                                         -> Result<Cert>
    where
        H: Into<FileOrKeyHandle>,
        Q: Into<Option<&'a Path>>,
    {
        let cert_handle = cert_handle.into();
        let output_file = output_file.into();

        let mut cmd = self.command();
        cmd.arg("key").arg("subkey").arg("password");

        if cert_handle.is_file() {
            cmd.arg("--cert-file").arg(&cert_handle);
        } else {
            cmd.arg("--cert").arg(&cert_handle);
        };

        for key in keys.iter() {
            cmd.arg("--key").arg(key.to_string());
        }

        if let Some(p) = old_password_file {
            cmd.arg("--password-file").arg(p);
        }

        if let Some(p) = new_password_file {
            cmd.arg("--new-password-file").arg(p);
        } else {
            cmd.arg("--clear-password");
        }

        if let Some(output_file) = output_file {
            cmd.arg("--output").arg(output_file);
        }

        let output = self.run(cmd, Some(success));
        if output.status.success() {
            if let Some(output_file) = output_file {
                if output_file != &PathBuf::from("-") {
                    return Ok(Cert::from_file(output_file)
                        .expect("can parse certificate"));
                }
            } else if output_file.is_none() {
                if let FileOrKeyHandle::KeyHandle((kh, _s)) = cert_handle {
                    return Ok(self.key_export(kh));
                }
            }
            Ok(Cert::from_bytes(&output.stdout)
                .expect("can parse certificate"))
        } else {
            Err(anyhow::anyhow!(format!(
                "Failed (expected):\n{}",
                String::from_utf8_lossy(&output.stderr))))
        }
    }

    /// Adds user IDs to the given key.
    pub fn key_userid_add(&self, key: Cert, args: &[&str]) -> Result<Cert> {
        let mut cmd = self.command();
        cmd.args(["key", "userid", "add"]);
        for arg in args {
            cmd.arg(arg);
        }

        let in_filename = self.scratch_file(None);
        key.as_tsk().serialize(&mut File::create(&in_filename)?)?;
        cmd.arg("--cert-file").arg(&in_filename);
        let out_filename = self.scratch_file(None);
        cmd.arg("--output").arg(&out_filename);

        let output = self.run(cmd, Some(true));

        let out_key = Cert::from_file(&out_filename)?;
        assert!(out_key.is_tsk());
        Ok(out_key)
    }

    /// Strips user IDs to the given key.
    pub fn toolbox_strip_userid(&self, key: Cert, args: &[&str]) -> Result<Cert> {
        let mut cmd = self.command();
        cmd.args(["toolbox", "strip-userid"]);
        for arg in args {
            cmd.arg(arg);
        }

        let in_filename = self.scratch_file(None);
        key.as_tsk().serialize(&mut File::create(&in_filename)?)?;
        cmd.arg("--cert-file").arg(&in_filename);
        let out_filename = self.scratch_file(None);
        cmd.arg("--output").arg(&out_filename);

        let output = self.run(cmd, Some(true));

        let out_key = Cert::from_file(&out_filename)?;
        assert!(out_key.is_tsk());
        Ok(out_key)
    }

    /// Imports the specified certificate into the keystore.
    pub fn cert_import<P>(&self, path: P)
    where P: AsRef<Path>
    {
        let mut cmd = self.command();
        cmd.arg("cert").arg("import").arg(path.as_ref());
        self.run(cmd, Some(true));
    }

    /// Exports the specified certificate.
    pub fn cert_export<H>(&self, kh: H) -> Cert
    where
        H: Borrow<KeyHandle>,
    {
        let mut cmd = self.command();
        cmd.args([ "cert", "export", "--cert", &kh.borrow().to_string() ]);
        let output = self.run(cmd, Some(true));

        Cert::from_bytes(&output.stdout)
            .expect("can parse certificate")
    }

    /// Try to certify the user ID binding.
    ///
    /// If `output_file` is `Some`, then the output is written to that
    /// file.  Otherwise, the default behavior is followed.
    pub fn pki_certify_p<'a, H, C, Q>(&self, extra_args: &[&str],
                                      certifier: H,
                                      cert: C,
                                      userid: &str,
                                      output_file: Q,
                                      success: bool)
        -> Result<Cert>
    where H: Into<FileOrKeyHandle>,
          C: Into<FileOrKeyHandle>,
          Q: Into<Option<&'a Path>>,
    {
        let certifier = certifier.into();
        let cert = cert.into();
        let output_file = output_file.into();

        let mut cmd = self.command();
        cmd.args([ "pki", "certify" ]);
        for arg in extra_args {
            cmd.arg(arg);
        }
        match &certifier {
            FileOrKeyHandle::FileOrStdin(file) => {
                cmd.arg("--certifier-file").arg(file);
            }
            FileOrKeyHandle::KeyHandle((_kh, s)) => {
                cmd.arg("--certifier").arg(s);
            }
        }
        cmd.arg(&cert).arg(userid);

        if let Some(output_file) = output_file {
            cmd.arg("--force").arg("--output").arg(output_file);
        }

        let output = self.run(cmd, Some(success));
        if output.status.success() {
            if let Some(output_file) = output_file {
                // The output was explicitly written to a file.
                if output_file == &PathBuf::from("-") {
                    Ok(Cert::from_bytes(&output.stdout)
                       .expect("can parse certificate"))
                } else {
                    Ok(Cert::from_file(&output_file)
                       .expect("can parse certificate"))
                }
            } else {
                match cert {
                    FileOrKeyHandle::FileOrStdin(_) => {
                        // When the cert is from a file, the output is
                        // written to stdout by default.
                        Ok(Cert::from_bytes(&output.stdout)
                           .with_context(|| {
                               format!("Importing result from the file {:?}",
                                       cert)
                           })
                           .expect("can parse certificate"))
                    }
                    FileOrKeyHandle::KeyHandle((kh, _s)) => {
                        // When the cert is from the cert store, the
                        // output is written to the cert store by
                        // default.
                        Ok(self.cert_export(kh.clone()))
                    }
                }
            }
        } else {
            Err(anyhow::anyhow!(format!(
                "Failed (expected):\n{}",
                String::from_utf8_lossy(&output.stderr))))
        }
    }

    /// Certify the user ID binding.
    pub fn pki_certify<'a, H, C, Q>(&self, extra_args: &[&str],
                                    certifier: H,
                                    cert: C,
                                    userid: &str,
                                    output_file: Q)
        -> Cert
    where H: Into<FileOrKeyHandle>,
          C: Into<FileOrKeyHandle>,
          Q: Into<Option<&'a Path>>,
    {
        self.pki_certify_p(
            extra_args, certifier, cert, userid, output_file, true)
            .expect("success")
    }

    /// Add a link for the binding.
    pub fn pki_link_add_maybe(&self, extra_args: &[&str],
                              cert: KeyHandle, userid: &str)
        -> Result<()>
    {
        let mut cmd = self.command();
        cmd.args([ "pki", "link", "add" ]);
        for arg in extra_args {
            cmd.arg(arg);
        }
        cmd.arg(&cert.to_string());
        cmd.arg(userid);

        let output = self.run(cmd, None);
        if output.status.success() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(format!(
                "Command failed:\n{}",
                String::from_utf8_lossy(&output.stderr))))
        }
    }

    /// Add a link for the binding.
    pub fn pki_link_add(&self, args: &[&str],
                        cert: KeyHandle, userid: &str)
    {
        self.pki_link_add_maybe(args, cert, userid).expect("success")
    }

    pub fn sign<'a, H, Q>(&self,
                          signer: H,
                          password_file: Option<&Path>,
                          input_file: &Path,
                          output_file: Q)
        -> Vec<u8>
    where H: Into<FileOrKeyHandle>,
          Q: Into<Option<&'a Path>>,
    {
        let signer = signer.into();
        let output_file = output_file.into();

        let mut cmd = self.command();
        cmd.arg("sign");

        match &signer {
            FileOrKeyHandle::FileOrStdin(path) => {
                cmd.arg("--signer-file").arg(path);
            }
            FileOrKeyHandle::KeyHandle((_kh, s)) => {
                cmd.arg("--signer-key").arg(&s);
            }
        };

        if let Some(password_file) = password_file {
            cmd.arg("--password-file").arg(password_file);
        }

        cmd.arg(input_file);

        if let Some(output_file) = output_file {
            cmd.arg("--output").arg(output_file);
        };

        let output = self.run(cmd, Some(true));
        assert!(output.status.success());

        if let Some(output_file) = output_file {
            std::fs::read(output_file).expect("can read file")
        } else {
            output.stdout
        }
    }

    // Strips the secret key material from input.  Writes it to
    // `output_file`, if `Some`.
    pub fn toolbox_extract_cert<'a, P, Q>(&self, input: P,
                                          output_file: Q)
        -> Cert
    where P: AsRef<Path>,
          Q: Into<Option<&'a Path>>,
    {
        let output_file = output_file.into();

        let mut cmd = self.command();
        cmd.args([ "toolbox", "extract-cert" ]);
        cmd.arg(input.as_ref());
        if let Some(output_file) = output_file {
            cmd.arg("--output").arg(output_file);
        }

        let output = self.run(cmd, Some(true));
        if let Some(output_file) = output_file {
            if output_file != &PathBuf::from("-") {
                return Cert::from_file(&output_file)
                   .expect("can parse certificate");
            }
        }

        // Read from stdout.
        Cert::from_bytes(&output.stdout)
           .expect("can parse certificate")
    }

    // Merges the certificates.
    pub fn toolbox_keyring_merge<'a, P, Q>(&self,
                                           input_files: Vec<P>,
                                           input_bytes: Option<&[u8]>,
                                           output_file: Q)
        -> Vec<Cert>
    where P: AsRef<Path>,
          Q: Into<Option<&'a Path>>,
    {
        let output_file = output_file.into();

        let mut cmd = self.command();
        cmd.args([ "toolbox", "keyring", "merge" ]);

        for input_file in input_files.into_iter() {
            cmd.arg(input_file.as_ref());
        }
        if let Some(input_bytes) = input_bytes {
            cmd.arg("-");
            cmd.write_stdin(input_bytes);
        }

        if let Some(output_file) = output_file {
            cmd.arg("--output").arg(output_file);
        }

        let output = self.run(cmd, Some(true));

        let parser = None;
        if let Some(output_file) = output_file {
            if PathBuf::from("-").as_path() != output_file {
                CertParser::from_file(&output_file)
                    .expect("can parse certificate");
            }
        };
        let parser = if let Some(parser) = parser {
            parser
        } else {
            // Read from stdout.
            CertParser::from_bytes(&output.stdout)
                .expect("can parse certificate")
        };

        parser.collect::<Result<Vec<_>>>()
            .expect("valid certificates")
    }
}

/// Ensure notations can be found in a Signature
///
/// ## Errors
///
/// Returns an error if a notation can not be found in the Signature
pub fn compare_notations(
    signature: &Signature,
    notations: &[(&str, &str)],
) -> Result<()> {
    if ! notations.is_empty() {
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
