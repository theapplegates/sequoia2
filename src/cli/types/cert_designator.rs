use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Context;
use anyhow::Result;

use typenum::Unsigned;

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;
use openpgp::packet::UserID;

/// The prefix for the designators.
///
/// See [`NoPrefix`], [`CertPrefix`], etc.
pub trait ArgumentPrefix {
    fn prefix() -> &'static str;
}

pub struct ConcreteArgumentPrefix<T>(std::marker::PhantomData<T>)
where T: typenum::Unsigned;

// "--cert", "--userid", "--file", etc.
pub type NoPrefix = ConcreteArgumentPrefix<typenum::U0>;
// "--cert", "--cert-userid", "--cert-file", etc.
pub type CertPrefix = ConcreteArgumentPrefix<typenum::U1>;

/// "--for", "--for-userid", "--for-file", etc.
pub type RecipientPrefix = ConcreteArgumentPrefix<typenum::U2>;

impl ArgumentPrefix for NoPrefix {
    fn prefix() -> &'static str {
        ""
    }
}

impl ArgumentPrefix for CertPrefix {
    fn prefix() -> &'static str {
        "cert-"
    }
}

impl ArgumentPrefix for RecipientPrefix {
    fn prefix() -> &'static str {
        "for-"
    }
}

/// Adds a `--file` argument.
pub type FileArg = typenum::U1;

/// Adds a `--cert` argument.
pub type CertArg = typenum::U2;

/// Adds a `--userid` argument.
pub type UserIDArg = typenum::U8;

/// Adds a `--email` argument.
pub type EmailArg = typenum::U16;

/// Adds a `--domain` argument.
pub type DomainArg = typenum::U32;

/// Adds a `--grep` argument.
pub type GrepArg = typenum::U64;

/// Enables --cert, --userid, --email, --domain, and --grep (i.e., not
/// --file).
pub type CertUserIDEmailDomainGrepArgs
    = <<<<CertArg as std::ops::BitOr<UserIDArg>>::Output
         as std::ops::BitOr<EmailArg>>::Output
        as std::ops::BitOr<DomainArg>>::Output
       as std::ops::BitOr<GrepArg>>::Output;

/// Enables --cert, --userid, --email, and --file (i.e., not --domain,
/// or --grep).
pub type CertUserIDEmailFileArgs
    = <<<CertArg as std::ops::BitOr<UserIDArg>>::Output
        as std::ops::BitOr<EmailArg>>::Output
       as std::ops::BitOr<FileArg>>::Output;

/// Enables --userid, and --email (i.e., not --cert, --file, --domain,
/// or --grep).
pub type UserIDEmailArgs
    = <UserIDArg as std::ops::BitOr<EmailArg>>::Output;

/// A certificate designator.
#[derive(Debug)]
pub enum CertDesignator {
    /// Reads certificates from stdin.
    ///
    /// This is translated from `--file -`.
    Stdin,

    /// Reads certificates from a file.
    ///
    /// `--file`.
    File(PathBuf),

    /// Looks up certificates on the cert store by key handle.
    ///
    /// By default, this matches on both the primary key, and the
    /// subkeys (whether they have a back sig or not).
    ///
    /// `--cert`.
    Cert(KeyHandle),

    /// Looks up certificates on the cert store by user ID.
    ///
    /// By default, this matches on fully authenticated user IDs
    /// (trust amount >= 120).  The user IDs don't need to be
    /// self-signed.
    ///
    /// `--userid`.
    UserID(String),

    /// Looks up certificates on the cert store by email.
    ///
    /// By default, this matches on fully authenticated user IDs
    /// (trust amount >= 120) with the specified email address.  The
    /// user IDs don't need to be self-signed.
    ///
    /// `--email`.
    Email(String),

    /// Looks up certificates on the cert store by email domain.
    ///
    /// By default, this matches on fully authenticated user IDs
    /// (trust amount >= 120) with an email address in the specified
    /// domain.  The user IDs don't need to be self-signed.
    ///
    /// `--domain`.
    Domain(String),

    /// Looks up certificates on the cert store by substring.
    ///
    /// By default, this matches on fully authenticated user IDs
    /// (trust amount >= 120) that contain the specified string.  The
    /// string is matched case insentively.  The user IDs don't need
    /// to be self-signed.
    ///
    /// `--grep`.
    Grep(String),
}

impl CertDesignator {
    /// Returns the argument's name, e.g., `--cert`.
    pub fn argument_name<Prefix>(&self) -> String
    where Prefix: ArgumentPrefix
    {
        let prefix = Prefix::prefix();

        use CertDesignator::*;
        match self {
            Stdin => format!("--{}file", prefix),
            File(_path) => format!("--{}file", prefix),
            Cert(_kh) => {
                if ! prefix.is_empty() {
                    // We want `--cert`, not `--cert-cert`, or
                    // `--for` instead of `--for-cert`.
                    format!("--{}", prefix.strip_suffix("-")
                            .expect("prefix must end with -"))
                } else {
                    format!("--{}cert", prefix)
                }
            },
            UserID(_userid) => format!("--{}userid", prefix),
            Email(_email) => format!("--{}email", prefix),
            Domain(_domain) => format!("--{}domain", prefix),
            Grep(_pattern) => format!("--{}grep", prefix),
        }
    }

    /// Returns the argument's name and value, e.g., `--cert-file
    /// file`.
    pub fn argument<Prefix>(&self) -> String
    where Prefix: ArgumentPrefix,
    {
        let argument_name = self.argument_name::<Prefix>();

        use CertDesignator::*;
        match self {
            Stdin => format!("{} -", argument_name),
            File(path) => format!("{} {}", argument_name, path.display()),
            Cert(kh) => format!("{} {}", argument_name, kh),
            UserID(userid) => format!("{} {:?}", argument_name, userid),
            Email(email) => format!("{} {:?}", argument_name, email),
            Domain(domain) => format!("{} {:?}", argument_name, domain),
            Grep(pattern) => format!("{} {:?}", argument_name, pattern),
        }
    }
}

/// A data structure that can be flattened into a clap `Command`, and
/// adds arguments to address certificates.
///
/// Depending on `Options`, it adds zero or more arguments to the
/// subcommand.  If `CertArg` is selected, for instance, then a
/// `--cert` argument is added.
///
/// `Options` are the set of options to enable.
///
/// `Prefix` is a prefix to use.  Using `RecipientPrefix` will
/// change, e.g., `--email` to `--for-email`.
pub struct CertDesignators<Options, Prefix=NoPrefix>
{
    /// The set of certificate designators.
    pub designators: Vec<CertDesignator>,

    options: std::marker::PhantomData<(Options, Prefix)>,
}

impl<Options, Prefix> std::fmt::Debug for CertDesignators<Options, Prefix> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertDesignators")
            .field("designators", &self.designators)
            .finish()
    }
}

impl<Options, Prefix> CertDesignators<Options, Prefix> {
    /// Like `Vec::push`.
    pub fn push(&mut self, designator: CertDesignator) {
        self.designators.push(designator)
    }

    /// Like `Vec::is_empty`.
    pub fn is_empty(&mut self) -> bool {
        self.designators.is_empty()
    }

    /// Iterates over the certificate designators.
    pub fn iter(&self) -> impl Iterator<Item=&CertDesignator> {
        self.designators.iter()
    }
}

impl<Options, Prefix> clap::Args for CertDesignators<Options, Prefix>
where
    Options: typenum::Unsigned,
    Prefix: ArgumentPrefix,
{
    fn augment_args(mut cmd: clap::Command) -> clap::Command
    {
        let options = Options::to_usize();
        let file_arg = (options & FileArg::to_usize()) > 0;
        let cert_arg = (options & CertArg::to_usize()) > 0;
        let userid_arg = (options & UserIDArg::to_usize()) > 0;
        let email_arg = (options & EmailArg::to_usize()) > 0;
        let domain_arg = (options & DomainArg::to_usize()) > 0;
        let grep_arg = (options & GrepArg::to_usize()) > 0;

        // Converts a string to a valid `KeyHandle`.
        //
        // Note: `<KeyHandle as FromStr>::from_str` is not enough, as
        // we also want to bail if the fingerprint format is unknown.
        // That is, KeyHandle will happily parse a 24 character hex
        // string, but v4 fignerprints are 20 characters, and v6
        // fingerprints are 32 characters.
        fn parse_as_key_handle(s: &str) -> Result<KeyHandle> {
            let kh = KeyHandle::from_str(s)?;
            if kh.is_invalid() {
                Err(anyhow::anyhow!(
                    "{:?} is not a valid fingerprint or key ID \
                     (hint: v4 fingerprints are 20 hex characters, \
                     key IDs are 16 hex characters, you provided {} \
                     characters)",
                    s, s.chars().count()))
            } else {
                Ok(kh)
            }
        }

        fn parse_as_email(s: &str) -> Result<String> {
            let userid = UserID::from(format!("<{}>", s));
            match userid.email_normalized() {
                Ok(Some(email)) => {
                    Ok(email)
                }
                Ok(None) => {
                    Err(anyhow::anyhow!(
                        "{:?} is not a valid email address", s))
                }
                Err(err) => {
                    Err(err).context(format!(
                        "{:?} is not a valid email address", s))
                }
            }
        }

        fn parse_as_domain(s: &str) -> Result<String> {
            let email = format!("localpart@{}", s);
            match parse_as_email(&email) {
                Ok(_) => Ok(s.to_string()),
                Err(err) => Err(err),
            }
        }

        let prefix = Prefix::prefix();
        let full_name = |name| {
            if ! prefix.is_empty() && name == "cert" {
                // We want `--cert`, not `--cert-cert`, or
                // `--for` instead of `--for-cert`.
                prefix.strip_suffix("-").expect("prefix must end with -").into()
            } else {
                format!("{}{}", prefix, name)
            }
        };

        if cert_arg {
            let full_name = full_name("cert");
            cmd = cmd.arg(
                clap::Arg::new(&full_name)
                    .long(full_name)
                    .value_name("FINGERPRINT|KEYID")
                    .value_parser(parse_as_key_handle)
                    .action(clap::ArgAction::Append)
                    .help("Uses certificates with the specified \
                           fingerprint or key ID"));
        }

        if userid_arg {
            let full_name = full_name("userid");
            cmd = cmd.arg(
                clap::Arg::new(&full_name)
                    .long(full_name)
                    .value_name("USERID")
                    .action(clap::ArgAction::Append)
                    .help("Uses certificates with the specified user ID"));
        }

        if email_arg {
            let full_name = full_name("email");
            cmd = cmd.arg(
                clap::Arg::new(&full_name)
                    .long(full_name)
                    .value_name("EMAIL")
                    .value_parser(parse_as_email)
                    .action(clap::ArgAction::Append)
                    .help("Uses certificates where a user ID includes \
                           the specified email address"));
        }

        if domain_arg {
            let full_name = full_name("domain");
            cmd = cmd.arg(
                clap::Arg::new(&full_name)
                    .long(full_name)
                    .value_name("DOMAIN")
                    .value_parser(parse_as_domain)
                    .action(clap::ArgAction::Append)
                    .help("Uses certificates where a user ID includes \
                           an email address for the specified domain"));
        }

        if grep_arg {
            let full_name = full_name("grep");
            cmd = cmd.arg(
                clap::Arg::new(&full_name)
                    .long(full_name)
                    .value_name("PATTERN")
                    .action(clap::ArgAction::Append)
                    .help("Uses certificates with a user ID that \
                           matches the pattern, case insensitively"));
        }

        // Add all of the variants that are enabled.
        if file_arg {
            let full_name = full_name("file");
            cmd = cmd.arg(
                clap::Arg::new(&full_name)
                    .long(full_name)
                    .value_name("PATH")
                    .value_parser(clap::value_parser!(PathBuf))
                    .action(clap::ArgAction::Append)
                    .help("Reads certificates from PATH"));
        }

        cmd
    }

    fn augment_args_for_update(cmd: clap::Command) -> clap::Command
    {
        Self::augment_args(cmd)
    }
}

impl<Options, Prefix> clap::FromArgMatches for CertDesignators<Options, Prefix>
where
    Options: typenum::Unsigned,
    Prefix: ArgumentPrefix,
{
    fn update_from_arg_matches(&mut self, matches: &clap::ArgMatches)
        -> Result<(), clap::Error>
    {
        // eprintln!("matches: {:#?}", matches);

        let options = Options::to_usize();
        let file_arg = (options & FileArg::to_usize()) > 0;
        let cert_arg = (options & CertArg::to_usize()) > 0;
        let userid_arg = (options & UserIDArg::to_usize()) > 0;
        let email_arg = (options & EmailArg::to_usize()) > 0;
        let domain_arg = (options & DomainArg::to_usize()) > 0;
        let grep_arg = (options & GrepArg::to_usize()) > 0;

        let mut designators = Vec::new();

        let prefix = Prefix::prefix();

        if let Some(Some(certs))
            = matches.try_get_many::<KeyHandle>(
                if prefix.is_empty() {
                    "cert"
                } else {
                    prefix.strip_suffix("-").expect("prefix must end with -")
                })
            .ok().filter(|_| cert_arg)
        {
            for cert in certs.cloned() {
                designators.push(CertDesignator::Cert(cert));
            }
        }

        if let Some(Some(userids))
            = matches.try_get_many::<String>(&format!("{}userid", prefix))
            .ok().filter(|_| userid_arg)
        {
            for userid in userids.cloned() {
                designators.push(
                    CertDesignator::UserID(userid));
            }
        }

        if let Some(Some(emails))
            = matches.try_get_many::<String>(&format!("{}email", prefix))
            .ok().filter(|_| email_arg)
        {
            for email in emails.cloned() {
                designators.push(CertDesignator::Email(email));
            }
        }

        if let Some(Some(domains))
            = matches.try_get_many::<String>(&format!("{}domain", prefix))
            .ok().filter(|_| domain_arg)
        {
            for domain in domains.cloned() {
                designators.push(CertDesignator::Domain(domain));
            }
        }

        if let Some(Some(patterns))
            = matches.try_get_many::<String>(&format!("{}grep", prefix))
            .ok().filter(|_| grep_arg)
        {
            for pattern in patterns.cloned() {
                designators.push(CertDesignator::Grep(pattern));
            }
        }

        if let Some(Some(paths))
            = matches.try_get_many::<PathBuf>(&format!("{}file", prefix))
            .ok().filter(|_| file_arg)
        {
            for path in paths.cloned() {
                if let Some("-") = path.to_str() {
                    designators.push(CertDesignator::Stdin);
                } else {
                    designators.push(CertDesignator::File(path));
                }
            }
        }

        self.designators = designators;
        Ok(())
    }

    fn from_arg_matches(matches: &clap::ArgMatches)
        -> Result<Self, clap::Error>
    {
        let mut designators = Self {
            designators: Vec::new(),
            options: std::marker::PhantomData,
        };

        // The way we use clap, this is never called.
        designators.update_from_arg_matches(matches)?;
        Ok(designators)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // Check that flattening CertDesignators works as expected.
    #[test]
    fn cert_designators() {
        use clap::Parser;
        use clap::CommandFactory;
        use clap::FromArgMatches;

        macro_rules! check {
            ($t:ty,
             $cert:expr, $userid:expr, $email:expr,
             $domain:expr, $grep:expr, $file:expr) =>
            {{
                #[derive(Parser, Debug)]
                #[clap(name = "prog")]
                struct CLI {
                    #[command(flatten)]
                    pub certs: CertDesignators<$t>,
                }

                let command = CLI::command();

                // Check if --cert is recognized.
                let m = command.clone().try_get_matches_from(vec![
                    "prog",
                    "--cert", "C2B819056C652598",
                    "--cert", "C2B819056C652598",
                ]);
                if $cert {
                    let m = m.expect("valid arguments");
                    let c = CLI::from_arg_matches(&m).expect("ok");
                    assert_eq!(c.certs.designators.len(), 2);
                } else {
                    assert!(m.is_err());
                }

                // Either --cert is unknown, or the --cert's value
                // is invalid.
                let m = command.clone().try_get_matches_from(vec![
                    "prog",
                    "--cert", "alice",
                ]);
                assert!(m.is_err());


                // Check if --userid is recognized.
                let m = command.clone().try_get_matches_from(vec![
                    "prog", "--userid", "alice", "--userid", "bob",
                ]);
                if $userid {
                    let m = m.expect("valid arguments");
                    let c = CLI::from_arg_matches(&m).expect("ok");
                    assert_eq!(c.certs.designators.len(), 2);
                } else {
                    assert!(m.is_err());
                }


                // Check if --email is recognized.
                let m = command.clone().try_get_matches_from(vec![
                    "prog",
                    "--email", "alice@example.org",
                    "--email", "bob@example.org",
                ]);
                if $email {
                    let m = m.expect("valid arguments");
                    let c = CLI::from_arg_matches(&m).expect("ok");
                    assert_eq!(c.certs.designators.len(), 2);
                } else {
                    assert!(m.is_err());
                }

                // Either --email is unknown, or the --email's value
                // is invalid.
                let m = command.clone().try_get_matches_from(vec![
                    "prog",
                    "--email", "alice@invalid@example.org",
                ]);
                assert!(m.is_err());


                // Check if --domain is recognized.
                let m = command.clone().try_get_matches_from(vec![
                    "prog",
                    "--domain", "example.org",
                    "--domain", "some.org",
                ]);
                if $domain {
                    let m = m.expect("valid arguments");
                    let c = CLI::from_arg_matches(&m).expect("ok");
                    assert_eq!(c.certs.designators.len(), 2);
                } else {
                    assert!(m.is_err());
                }

                // Either --domain is unknown, or the --domain's value
                // is invalid.
                let m = command.clone().try_get_matches_from(vec![
                    "prog",
                    "--domain", "@example.org",
                ]);
                assert!(m.is_err());


                // Check if --grep is recognized.
                let m = command.clone().try_get_matches_from(vec![
                    "prog",
                    "--grep", "a@b@c",
                    "--grep", "@some.org",
                ]);
                if $grep {
                    let m = m.expect("valid arguments");
                    let c = CLI::from_arg_matches(&m).expect("ok");
                    assert_eq!(c.certs.designators.len(), 2);
                } else {
                    assert!(m.is_err());
                }


                // Check if --file is recognized.
                let m = command.clone().try_get_matches_from(vec![
                    "prog",
                    "--file", "filename",
                    "--file", "./foo/bar",
                ]);
                if $file {
                    let m = m.expect("valid arguments");
                    let c = CLI::from_arg_matches(&m).expect("ok");
                    assert_eq!(c.certs.designators.len(), 2);
                } else {
                    assert!(m.is_err());
                }


                // Check that stdin is recognized.
                let m = command.clone().try_get_matches_from(vec![
                    "prog",
                    "--file", "-",
                ]);
                if $file {
                    let m = m.expect("valid arguments");
                    let c = CLI::from_arg_matches(&m).expect("ok");
                    assert_eq!(c.certs.designators.len(), 1);
                    if let CertDesignator::Stdin
                        = c.certs.designators[0]
                    {
                    } else {
                        panic!("Expected stdin, got {:?}",
                               c.certs.designators[0]);
                    }
                } else {
                    assert!(m.is_err());
                }
            }}
        }

        check!(CertUserIDEmailDomainGrepArgs,
               true,  true,  true,  true,  true,  false);
        check!(CertUserIDEmailFileArgs,
               true,  true,  true, false, false, true);
        // No Args.
        check!(typenum::U0,false, false, false, false, false, false);
        check!(CertArg,     true, false, false, false, false, false);
        check!(UserIDArg,  false,  true, false, false, false, false);
        check!(EmailArg,   false, false,  true, false, false, false);
        check!(DomainArg,  false, false, false,  true, false, false);
        check!(GrepArg,    false, false, false, false,  true, false);
        check!(FileArg,    false, false, false, false, false,  true);
    }
}
