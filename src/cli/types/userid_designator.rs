use anyhow::Context;
use anyhow::Result;

use typenum::Unsigned;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::cert::ValidCert;
use openpgp::packet::UserID;

/// Adds a `--all` argument.
pub type AllUserIDsArg = typenum::U1;

/// Adds a `--userid` argument.  The value must correspond to a
/// self-signed user ID.  Conflicts with `AnyUserIDArg`.
pub type ExistingUserIDArg = typenum::U2;

/// Adds a `--email` argument.  The value must correspond to a
/// self-signed user ID.  Conflicts with `AnyEmailArg`.
pub type ExistingEmailArg = typenum::U4;

/// Adds a `--name` argument.  The value need not correspond to a
/// self-signed user ID.
pub type ExistingNameArg = typenum::U8;

/// Adds a `--userid` argument.  Unlike ExistingUserIDArg, the value
/// need not correspond to a self-signed user ID.  Conflicts with
/// `ExistingUserIDArg`.
pub type AnyUserIDArg = typenum::U16;

/// Adds a `--email` argument.  Unlike ExistingEmailArg, the value
/// need not correspond to a self-signed user ID.  Conflicts with
/// `ExistingEmailArg`.
pub type AnyEmailArg = typenum::U32;

/// Adds a `--add-userid` argument.
pub type AddUserIDArg = typenum::U64;

/// Adds a `--add-email` argument.
pub type AddEmailArg = typenum::U128;

/// Enables --userid, and --email (but not --name, --add-userid or
/// --add-email).
pub type ExistingUserIDEmailArgs
    = <ExistingUserIDArg as std::ops::BitOr<ExistingEmailArg>>::Output;

/// Enables --userid, --email, --name (but not --add-userid or
/// --add-email).
pub type ExistingUserIDEmailNameArgs
    = <ExistingUserIDEmailArgs as std::ops::BitOr<ExistingNameArg>>::Output;

/// Enables --userid, and --email (but not --name, --add-userid or
/// --add-email).
pub type AnyUserIDEmailArgs
    = <AnyUserIDArg as std::ops::BitOr<AnyEmailArg>>::Output;

/// Enables --add-userid, and --add-email (but not --name, --userid or
/// --email).
pub type AddUserIDEmailArgs
    = <AddUserIDArg as std::ops::BitOr<AddEmailArg>>::Output;

/// Enables --userid, --email, --add-userid, and --add-email (but not
/// --name).
pub type ExistingAndAddXUserIDEmailArgs
    = <ExistingUserIDEmailArgs
       as std::ops::BitOr<AddUserIDEmailArgs>>::Output;

/// Enables --all, --userid, --email, --add-userid, and --add-email
/// (but not --name).
pub type AllExistingAndAddXUserIDEmailArgs
    = <AllUserIDsArg
       as std::ops::BitOr<ExistingAndAddXUserIDEmailArgs>>::Output;

/// Argument parser options.

/// Normally it is possible to designate multiple certificates.  This
/// errors out if there is more than one value.
pub type OneValue = typenum::U1;

/// Normally a certificate designator is required, and errors out if
/// there isn't at least one value.  This makes the cert designator
/// completely optional.
pub type OptionalValue = typenum::U2;

/// A user ID designator.
#[derive(Debug, Clone)]
pub enum UserIDDesignator {
    /// A self-signed user ID.
    UserID(String),

    /// A self-signed email address.
    Email(String),

    /// A self-signed display name.
    Name(String),

    /// A user ID.
    AnyUserID(String),

    /// An email address.
    AnyEmail(String),

    /// A user ID.
    AddUserID(String),

    /// An email address.
    AddEmail(String),
}

#[allow(dead_code)]
impl UserIDDesignator {
    /// Returns the argument's name, e.g., `--userid`.
    pub fn argument_name(&self) -> &str
    {
        use UserIDDesignator::*;
        match self {
            UserID(_userid) => "--userid",
            Email(_email) => "--email",
            Name(_name) => "--name",
            AnyUserID(_userid) => "--userid",
            AnyEmail(_email) => "--email",
            AddUserID(_userid) => "--add-userid",
            AddEmail(_email) => "--add-email",
        }
    }

    /// Returns the argument's value.
    pub fn argument_value(&self) -> String
    {
        use UserIDDesignator::*;
        match self {
            UserID(userid) => format!("{:?}", userid),
            Email(email) => format!("{:?}", email),
            Name(name) => format!("{:?}", name),
            AnyUserID(userid) => format!("{:?}", userid),
            AnyEmail(email) => format!("{:?}", email),
            AddUserID(userid) => format!("{:?}", userid),
            AddEmail(email) => format!("{:?}", email),
        }
    }

    /// Returns the argument's name and value, e.g., `--add-userid
    /// userid`.
    pub fn argument(&self) -> String
    {
        let argument_name = self.argument_name();

        use UserIDDesignator::*;
        match self {
            UserID(userid) => format!("{} {:?}", argument_name, userid),
            Email(email) => format!("{} {:?}", argument_name, email),
            Name(name) => format!("{} {:?}", argument_name, name),
            AnyUserID(userid) => format!("{} {:?}", argument_name, userid),
            AnyEmail(email) => format!("{} {:?}", argument_name, email),
            AddUserID(userid) => format!("{} {:?}", argument_name, userid),
            AddEmail(email) => format!("{} {:?}", argument_name, email),
        }
    }

    /// Resolves to the specified user IDs.
    pub fn resolve_to(&self, userid: UserID) -> ResolvedUserID {
        ResolvedUserID {
            designator: Some(self.clone()),
            userid,
        }
    }
}

/// A data structure that can be flattened into a clap `Command`, and
/// adds arguments to address user IDs.
///
/// Depending on `Arguments`, it adds zero or more arguments to the
/// subcommand.  If `UserIDArg` is selected, for instance, then a
/// `--userid` argument is added.
///
/// `Options` are the set of options to the argument parser.  By
/// default, at least one user ID designator must be specified.
pub struct UserIDDesignators<Arguments, Options=typenum::U0>
{
    /// The set of certificate designators.
    pub designators: Vec<UserIDDesignator>,

    /// Use all self-signed user IDs.
    pub all: Option<bool>,

    arguments: std::marker::PhantomData<(Arguments, Options)>,
}

impl<Arguments, Options> std::fmt::Debug
    for UserIDDesignators<Arguments, Options>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserIDDesignators")
            .field("designators", &self.designators)
            .field("all", &self.all)
            .finish()
    }
}

#[allow(dead_code)]
impl<Arguments, Options> UserIDDesignators<Arguments, Options> {
    /// Like `Vec::push`.
    pub fn push(&mut self, designator: UserIDDesignator) {
        self.designators.push(designator)
    }

    /// Like `Vec::is_empty`.
    pub fn is_empty(&self) -> bool {
        self.designators.is_empty()
    }

    /// Iterates over the user ID designators.
    pub fn iter(&self) -> impl Iterator<Item=&UserIDDesignator> {
        self.designators.iter()
    }

    /// Returns whether the all flag was set.
    ///
    /// If the flag was not enabled, returns `None`.
    pub fn all(&self) -> Option<bool> {
        self.all
    }
}

impl<Arguments, Options> clap::Args
    for UserIDDesignators<Arguments, Options>
where
    Arguments: typenum::Unsigned,
    Options: typenum::Unsigned,
{
    fn augment_args(mut cmd: clap::Command) -> clap::Command
    {
        let arguments = Arguments::to_usize();
        let all_arg = (arguments & AllUserIDsArg::to_usize()) > 0;
        let userid_arg = (arguments & ExistingUserIDArg::to_usize()) > 0;
        let email_arg = (arguments & ExistingEmailArg::to_usize()) > 0;
        let name_arg = (arguments & ExistingNameArg::to_usize()) > 0;
        let any_userid_arg = (arguments & AnyUserIDArg::to_usize()) > 0;
        let any_email_arg = (arguments & AnyEmailArg::to_usize()) > 0;
        let add_userid_arg = (arguments & AddUserIDArg::to_usize()) > 0;
        let add_email_arg = (arguments & AddEmailArg::to_usize()) > 0;

        // Can't provide both ExistingUserIDArg and AnyUserIDArg.
        assert!(! (userid_arg && any_userid_arg));
        assert!(! (email_arg && any_email_arg));

        let options = Options::to_usize();
        let one_value = (options & OneValue::to_usize()) > 0;
        let optional_value = (options & OptionalValue::to_usize()) > 0;

        let group = format!("userid-designator-{:X}-{:X}",
                            arguments,
                            options);
        let mut arg_group = clap::ArgGroup::new(&group);
        if one_value {
            arg_group = arg_group.multiple(false);
        } else {
            arg_group = arg_group.multiple(true);
        }

        if optional_value {
            arg_group = arg_group.required(false);
        } else {
            arg_group = arg_group.required(true);
        }

        let action = if one_value {
            clap::ArgAction::Set
        } else {
            clap::ArgAction::Append
        };

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

        if all_arg {
            let full_name = "all";
            cmd = cmd.arg(
                clap::Arg::new(&full_name)
                    .long(&full_name)
                    .requires(&group)
                    .action(clap::ArgAction::SetTrue)
                    .help("\
Use all self-signed user IDs"));
            arg_group = arg_group.arg(full_name);
        }

        if userid_arg {
            let full_name = "userid";
            cmd = cmd.arg(
                clap::Arg::new(&full_name)
                    .long(&full_name)
                    .value_name("USERID")
                    .action(action.clone())
                    .help("Use the specified self-signed user ID")
                    .long_help("\
Use the specified self-signed user ID.

The specified user ID must be self signed."));
            arg_group = arg_group.arg(full_name);
        }

        if email_arg {
            let full_name = "email";
            cmd = cmd.arg(
                clap::Arg::new(&full_name)
                    .long(&full_name)
                    .value_name("EMAIL")
                    .value_parser(parse_as_email)
                    .action(action.clone())
                    .help("\
Use the self-signed user ID with the specified email address"));
            arg_group = arg_group.arg(full_name);
        }

        if name_arg {
            let full_name = "name";
            cmd = cmd.arg(
                clap::Arg::new(&full_name)
                    .long(&full_name)
                    .value_name("DISPLAY_NAME")
                    .action(action.clone())
                    .help("\
Use the self-signed user ID with the specified display name"));
            arg_group = arg_group.arg(full_name);
        }

        if any_userid_arg {
            let full_name = "userid";
            cmd = cmd.arg(
                clap::Arg::new(&full_name)
                    .long(&full_name)
                    .value_name("USERID")
                    .action(action.clone())
                    .help("Use the specified user ID")
                    .long_help("\
Use the specified user ID.

The specified user ID does not need to be self signed."));
            arg_group = arg_group.arg(full_name);
        }

        if any_email_arg {
            let full_name = "email";
            cmd = cmd.arg(
                clap::Arg::new(&full_name)
                    .long(&full_name)
                    .value_name("EMAIL")
                    .value_parser(parse_as_email)
                    .action(action.clone())
                    .help("\
Use a user ID with the specified email address")
                    .long_help("\
Use a user ID with the specified email address.

This first searches for a matching self-signed user ID.  If there is \
no self-signed user ID with the specified, it uses a new user ID with \
the specified email address, and no display name."));
            arg_group = arg_group.arg(full_name);
        }

        if add_userid_arg {
            let full_name = "add-userid";
            cmd = cmd.arg(
                clap::Arg::new(&full_name)
                    .long(&full_name)
                    .value_name("USERID")
                    .action(action.clone())
                    .help("Use the specified user ID")
                    .long_help("\
Use the specified user ID.

The specified user ID does not need to be self signed.

Because using a user ID that is not self-signed is often a mistake, \
you need to use this option to explicitly opt in.  That said, \
certifying a user ID that is not self-signed is useful.  For instance, \
you can associate an alternate email address with a certificate, or \
you can add a petname, i.e., a memorable, personal name like \"mom\"."));
            arg_group = arg_group.arg(full_name);
        }

        if add_email_arg {
            let full_name = "add-email";
            cmd = cmd.arg(
                clap::Arg::new(&full_name)
                    .long(&full_name)
                    .value_name("EMAIL")
                    .value_parser(parse_as_email)
                    .action(action.clone())
                    .help("Use a user ID with the specified email address")
                    .long_help("\
Use a user ID with the specified email address.

This first searches for a matching self-signed user ID.  If there is \
no self-signed user ID with the specified, it uses a new user ID with \
the specified email address, and no display name."));
            arg_group = arg_group.arg(full_name);
        }

        cmd = cmd.group(arg_group);

        cmd
    }

    fn augment_args_for_update(cmd: clap::Command) -> clap::Command
    {
        Self::augment_args(cmd)
    }
}

impl<Arguments, Options> clap::FromArgMatches
    for UserIDDesignators<Arguments, Options>
where
    Arguments: typenum::Unsigned,
    Options: typenum::Unsigned,
{
    fn update_from_arg_matches(&mut self, matches: &clap::ArgMatches)
        -> Result<(), clap::Error>
    {
        // eprintln!("matches: {:#?}", matches);

        let arguments = Arguments::to_usize();
        let all_arg = (arguments & AllUserIDsArg::to_usize()) > 0;
        let userid_arg = (arguments & ExistingUserIDArg::to_usize()) > 0;
        let email_arg = (arguments & ExistingEmailArg::to_usize()) > 0;
        let name_arg = (arguments & ExistingNameArg::to_usize()) > 0;
        let any_userid_arg = (arguments & AnyUserIDArg::to_usize()) > 0;
        let any_email_arg = (arguments & AnyEmailArg::to_usize()) > 0;
        let add_userid_arg = (arguments & AddUserIDArg::to_usize()) > 0;
        let add_email_arg = (arguments & AddEmailArg::to_usize()) > 0;

        // Can't provide both ExistingUserIDArg and AnyUserIDArg.
        assert!(! (userid_arg && any_userid_arg));
        assert!(! (email_arg && any_email_arg));

        let mut designators = Vec::new();

        self.all = if all_arg {
            if matches.get_flag("all") {
                Some(true)
            } else {
                Some(false)
            }
        } else {
            None
        };

        if let Some(Some(userids))
            = matches.try_get_many::<String>("userid")
            .ok().filter(|_| userid_arg)
        {
            for userid in userids.cloned() {
                designators.push(
                    UserIDDesignator::UserID(userid));
            }
        }

        if let Some(Some(emails))
            = matches.try_get_many::<String>("email")
            .ok().filter(|_| email_arg)
        {
            for email in emails.cloned() {
                designators.push(UserIDDesignator::Email(email));
            }
        }

        if let Some(Some(names))
            = matches.try_get_many::<String>("name")
            .ok().filter(|_| name_arg)
        {
            for name in names.cloned() {
                designators.push(UserIDDesignator::Name(name));
            }
        }

        if let Some(Some(userids))
            = matches.try_get_many::<String>("userid")
            .ok().filter(|_| any_userid_arg)
        {
            for userid in userids.cloned() {
                designators.push(
                    UserIDDesignator::AnyUserID(userid));
            }
        }

        if let Some(Some(emails))
            = matches.try_get_many::<String>("email")
            .ok().filter(|_| any_email_arg)
        {
            for email in emails.cloned() {
                designators.push(UserIDDesignator::AnyEmail(email));
            }
        }

        if let Some(Some(add_userids))
            = matches.try_get_many::<String>("add-userid")
            .ok().filter(|_| add_userid_arg)
        {
            for add_userid in add_userids.cloned() {
                designators.push(
                    UserIDDesignator::AddUserID(add_userid));
            }
        }

        if let Some(Some(add_emails))
            = matches.try_get_many::<String>("add-email")
            .ok().filter(|_| add_email_arg)
        {
            for add_email in add_emails.cloned() {
                designators.push(UserIDDesignator::AddEmail(add_email));
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
            arguments: std::marker::PhantomData,
            all: None,
        };

        // The way we use clap, this is never called.
        designators.update_from_arg_matches(matches)?;
        Ok(designators)
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedUserID {
    designator: Option<UserIDDesignator>,
    userid: UserID,
}

use crate::cli::types::MyAsRef;
impl MyAsRef<UserID> for &ResolvedUserID {
    fn as_ref(&self) -> &UserID {
        &self.userid
    }
}

impl ResolvedUserID {
    /// Return a new implicitly resolved user ID (i.e., it was
    /// resolved via `--add`).
    pub fn implicit(userid: UserID)
        -> Self
    {
        Self {
            designator: None,
            userid,
        }
    }

    /// Return implicitly resolved user IDs for all user IDs
    /// associated with a certificate.
    pub fn implicit_for_cert(cert: &Cert) -> Vec<Self> {
        cert.userids()
            .map(|ua| Self::implicit(ua.userid().clone()))
            .collect::<Vec<_>>()
    }

    /// Return implicitly resolved user IDs for of a certificate's
    /// self-signed user IDs.
    pub fn implicit_for_valid_cert(vc: &ValidCert) -> Vec<Self> {
        vc.userids()
            .map(|ua| Self::implicit(ua.userid().clone()))
            .collect::<Vec<_>>()
    }

    /// The user ID designator.
    ///
    /// The designator is what the user provided.  If the user ID was
    /// not explicitly designator (i.e., it was resolved via `--all`),
    /// this is `None`.
    #[allow(unused)]
    pub fn designator(&self) -> Option<&UserIDDesignator> {
        self.designator.as_ref()
    }

    /// The resolved user ID.
    pub fn userid(&self) -> &UserID {
        &self.userid
    }

    /// Whether the user ID was designated with --userid, --email or
    /// --name.
    pub fn existing(&self) -> bool {
        use UserIDDesignator::*;
        match self.designator.as_ref() {
            Some(UserID(_userid)) => true,
            Some(Email(_email)) => true,
            Some(Name(_email)) => true,
            Some(AnyUserID(_userid)) => true,
            Some(AnyEmail(_email)) => true,

            Some(AddUserID(_userid)) => false,
            Some(AddEmail(_email)) => false,

            None => false,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // Check that flattening UserIDDesignators works as expected.
    #[test]
    fn userid_designators() {
        use clap::Parser;
        use clap::CommandFactory;
        use clap::FromArgMatches;

        macro_rules! check {
            ($t:ty,
             $userid:expr, $email:expr, $name:expr,
             $any_userid:expr, $any_email:expr,
             $add_userid:expr, $add_email:expr) =>
            {{
                #[derive(Parser, Debug)]
                #[clap(name = "prog")]
                struct CLI {
                    #[command(flatten)]
                    pub userids: UserIDDesignators<$t>,
                }

                let command = CLI::command();

                // Check if --userid is recognized.
                let m = command.clone().try_get_matches_from(vec![
                    "prog", "--userid", "alice", "--userid", "bob",
                ]);
                if $userid || $any_userid {
                    let m = m.expect("valid arguments");
                    let c = CLI::from_arg_matches(&m).expect("ok");
                    assert_eq!(c.userids.designators.len(), 2);
                } else {
                    assert!(m.is_err());
                }


                // Check if --email is recognized.
                let m = command.clone().try_get_matches_from(vec![
                    "prog",
                    "--email", "alice@example.org",
                    "--email", "bob@example.org",
                ]);
                if $email || $any_email {
                    let m = m.expect("valid arguments");
                    let c = CLI::from_arg_matches(&m).expect("ok");
                    assert_eq!(c.userids.designators.len(), 2);
                } else {
                    assert!(m.is_err());
                }

                // Check if --name is recognized.
                let m = command.clone().try_get_matches_from(vec![
                    "prog",
                    "--name", "alice",
                    "--name", "bob",
                ]);
                if $name {
                    let m = m.expect("valid arguments");
                    let c = CLI::from_arg_matches(&m).expect("ok");
                    assert_eq!(c.userids.designators.len(), 2);
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

                // Check if --add-userid is recognized.
                let m = command.clone().try_get_matches_from(vec![
                    "prog",
                    "--add-userid", "alice",
                    "--add-userid", "bob",
                ]);
                if $add_userid {
                    let m = m.expect("valid arguments");
                    let c = CLI::from_arg_matches(&m).expect("ok");
                    assert_eq!(c.userids.designators.len(), 2);
                } else {
                    assert!(m.is_err());
                }

                // Check if --add-email is recognized.
                let m = command.clone().try_get_matches_from(vec![
                    "prog",
                    "--add-email", "alice@example.org",
                    "--add-email", "bob@example.org",
                ]);
                if $add_email {
                    let m = m.expect("valid arguments");
                    let c = CLI::from_arg_matches(&m).expect("ok");
                    assert_eq!(c.userids.designators.len(), 2);
                } else {
                    assert!(m.is_err());
                }
            }}
        }

        // No Args.
        check!(typenum::U0,             false, false, false, false, false, false, false);
        check!(ExistingUserIDArg,        true, false, false, false, false, false, false);
        check!(ExistingEmailArg,        false,  true, false, false, false, false, false);
        check!(ExistingNameArg,         false, false,  true, false, false, false, false);
        check!(ExistingUserIDEmailArgs,  true,  true, false, false, false, false, false);
        check!(AnyUserIDArg,            false, false, false,  true, false, false, false);
        check!(AnyEmailArg,             false, false, false, false,  true, false, false);
        check!(AnyUserIDEmailArgs,      false, false, false,  true,  true, false, false);
        check!(AddUserIDArg,            false, false, false, false, false,  true, false);
        check!(AddEmailArg,             false, false, false, false, false, false,  true);
        check!(AddUserIDEmailArgs,      false, false, false, false, false,  true,  true);
        check!(ExistingUserIDEmailNameArgs,true,true, true, false, false,  false, false);
        check!(ExistingAndAddXUserIDEmailArgs,
                                         true,  true, false, false, false,  true,  true);
    }

    #[test]
    fn userid_designators_one() {
        use clap::Parser;
        use clap::CommandFactory;
        use clap::FromArgMatches;

        #[derive(Parser, Debug)]
        #[clap(name = "prog")]
        struct CLI {
            #[command(flatten)]
            pub userids: UserIDDesignators<ExistingUserIDEmailArgs,
                                           OneValue>,
        }

        let command = CLI::command();

        // Check if --userid is recognized.
        let m = command.clone().try_get_matches_from(vec![
            "prog",
            "--userid", "userid",
        ]);
        let m = m.expect("valid arguments");
        let c = CLI::from_arg_matches(&m).expect("ok");
        assert_eq!(c.userids.designators.len(), 1);

        // Make sure that we can't give it twice.
        let m = command.clone().try_get_matches_from(vec![
            "prog",
            "--userid", "alice",
            "--userid", "bob",
        ]);
        assert!(m.is_err());

        // Make sure that we can't give it zero times.
        let m = command.clone().try_get_matches_from(vec![
            "prog",
        ]);
        assert!(m.is_err());

        // Mixing is also not allowed.
        let m = command.clone().try_get_matches_from(vec![
            "prog",
            "--userid", "carol",
            "--email", "localpart@example.org",
        ]);
        assert!(m.is_err());
    }

    #[test]
    fn userid_designators_optional() {
        use clap::Parser;
        use clap::CommandFactory;
        use clap::FromArgMatches;

        #[derive(Parser, Debug)]
        #[clap(name = "prog")]
        struct CLI {
            #[command(flatten)]
            pub userids: UserIDDesignators<ExistingUserIDEmailArgs,
                                           OptionalValue>,
        }

        let command = CLI::command();

        // Check if --userid is recognized.
        let m = command.clone().try_get_matches_from(vec![
            "prog",
            "--userid", "alice",
        ]);
        let m = m.expect("valid arguments");
        let c = CLI::from_arg_matches(&m).expect("ok");
        assert_eq!(c.userids.designators.len(), 1);

        // Make sure that we can give it twice.
        let m = command.clone().try_get_matches_from(vec![
            "prog",
            "--userid", "alice",
            "--userid", "bob",
        ]);
        let m = m.expect("valid arguments");
        let c = CLI::from_arg_matches(&m).expect("ok");
        assert_eq!(c.userids.designators.len(), 2);

        // Make sure that we can give it zero times.
        let m = command.clone().try_get_matches_from(vec![
            "prog",
        ]);
        let m = m.expect("valid arguments");
        let c = CLI::from_arg_matches(&m).expect("ok");
        assert_eq!(c.userids.designators.len(), 0);

        // Make sure mixing is allowed.
        let m = command.clone().try_get_matches_from(vec![
            "prog",
            "--userid", "alice",
            "--email", "localpart@example.org",
        ]);
        let m = m.expect("valid arguments");
        let c = CLI::from_arg_matches(&m).expect("ok");
        assert_eq!(c.userids.designators.len(), 2);
    }

    #[test]
    fn userid_designators_all() {
        use clap::Parser;
        use clap::CommandFactory;
        use clap::FromArgMatches;

        #[derive(Parser, Debug)]
        #[clap(name = "prog")]
        struct CLI {
            #[command(flatten)]
            pub userids: UserIDDesignators<AllExistingAndAddXUserIDEmailArgs>,
        }

        let command = CLI::command();

        // Check if --all is recognized.
        let m = command.clone().try_get_matches_from(vec![
            "prog",
            "--userid", "alice",
        ]);
        let m = m.expect("valid arguments");
        let c = CLI::from_arg_matches(&m).expect("ok");
        assert_eq!(c.userids.designators.len(), 1);
        assert_eq!(c.userids.all(), Some(false));

        let m = command.clone().try_get_matches_from(vec![
            "prog",
            "--all"
        ]);
        let m = m.expect("valid arguments");
        let c = CLI::from_arg_matches(&m).expect("ok");
        assert_eq!(c.userids.designators.len(), 0);
        assert_eq!(c.userids.all(), Some(true));

        let m = command.clone().try_get_matches_from(vec![
            "prog",
            "--userid", "alice",
            "--all",
        ]);
        let m = m.expect("valid arguments");
        let c = CLI::from_arg_matches(&m).expect("ok");
        assert_eq!(c.userids.designators.len(), 1);
        assert_eq!(c.userids.all(), Some(true));
    }
}
