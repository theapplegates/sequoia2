use anyhow::Context;
use anyhow::Result;

use typenum::Unsigned;

use sequoia_openpgp as openpgp;
use openpgp::packet::UserID;

/// Adds a `--userid` argument.
pub type UserIDArg = typenum::U1;

/// Adds a `--email` argument.
pub type EmailArg = typenum::U2;

/// Adds a `--add-userid` argument.
pub type AddUserIDArg = typenum::U4;

/// Enables --userid, --email, and --add-userid.
pub type MaybeSelfSignedUserIDEmailArgs
    = <<UserIDArg as std::ops::BitOr<EmailArg>>::Output
       as std::ops::BitOr<AddUserIDArg>>::Output;

/// Argument parser options.

/// Normally it is possible to designate multiple certificates.  This
/// errors out if there is more than one value.
pub type OneValue = typenum::U1;

/// Normally a certificate designator is required, and errors out if
/// there isn't at least one value.  This makes the cert designator
/// completely optional.
pub type OptionalValue = typenum::U2;

/// A user ID designator.
#[derive(Debug)]
pub enum UserIDDesignator {
    /// A user ID.
    UserID(String),

    /// An email address.
    Email(String),
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
        }
    }

    /// Returns the argument's name and value, e.g., `--cert-file
    /// file`.
    pub fn argument<Prefix>(&self) -> String
    {
        let argument_name = self.argument_name();

        use UserIDDesignator::*;
        match self {
            UserID(userid) => format!("{} {:?}", argument_name, userid),
            Email(email) => format!("{} {:?}", argument_name, email),
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

    pub add_userid: Option<bool>,

    arguments: std::marker::PhantomData<(Arguments, Options)>,
}

impl<Arguments, Options> std::fmt::Debug
    for UserIDDesignators<Arguments, Options>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserIDDesignators")
            .field("designators", &self.designators)
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
    pub fn is_empty(&mut self) -> bool {
        self.designators.is_empty()
    }

    /// Iterates over the user ID designators.
    pub fn iter(&self) -> impl Iterator<Item=&UserIDDesignator> {
        self.designators.iter()
    }

    /// Returns whether the add user ID flag was set.
    ///
    /// If the flag was not enabled, returns `None`.
    pub fn add_userid(&self) -> Option<bool> {
        self.add_userid
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
        let userid_arg = (arguments & UserIDArg::to_usize()) > 0;
        let email_arg = (arguments & EmailArg::to_usize()) > 0;
        let add_userid_arg = (arguments & AddUserIDArg::to_usize()) > 0;

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

        if userid_arg {
            let full_name = "userid";
            cmd = cmd.arg(
                clap::Arg::new(&full_name)
                    .long(&full_name)
                    .value_name("USERID")
                    .action(action.clone())
                    .help("Uses the specified user ID"));
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
                    .help("Uses the specified email address"));
            arg_group = arg_group.arg(full_name);
        }

        if add_userid_arg {
            let full_name = "add-userid";
            cmd = cmd.arg(
                clap::Arg::new(&full_name)
                    .long(&full_name)
                    .requires(&group)
                    .action(clap::ArgAction::SetTrue)
                    .help("\
Uses the given user ID even if it isn't a self-signed user ID")
                    .long_help("\
Uses the given user ID even if it isn't a self-signed user ID.

Because certifying a user ID that is not self-signed is often a \
mistake, you need to use this option to explicitly opt in.  That said, \
certifying a user ID that is not self-signed is useful.  For instance, \
you can associate an alternate email address with a certificate, or \
you can add a petname, i.e., a memorable, personal name like \
\"mom\"."));
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
        let userid_arg = (arguments & UserIDArg::to_usize()) > 0;
        let email_arg = (arguments & EmailArg::to_usize()) > 0;
        let add_userid_arg = (arguments & AddUserIDArg::to_usize()) > 0;

        let mut designators = Vec::new();

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

        self.add_userid = if add_userid_arg {
            if matches.get_flag("add-userid") {
                Some(true)
            } else {
                Some(false)
            }
        } else {
            None
        };

        self.designators = designators;
        Ok(())
    }

    fn from_arg_matches(matches: &clap::ArgMatches)
        -> Result<Self, clap::Error>
    {
        let mut designators = Self {
            designators: Vec::new(),
            arguments: std::marker::PhantomData,
            add_userid: None,
        };

        // The way we use clap, this is never called.
        designators.update_from_arg_matches(matches)?;
        Ok(designators)
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
             $userid:expr, $email:expr, $add_userid:expr) =>
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
                if $userid {
                    let m = m.expect("valid arguments");
                    let c = CLI::from_arg_matches(&m).expect("ok");
                    assert_eq!(c.userids.designators.len(), 2);

                    if $add_userid {
                        assert_eq!(c.userids.add_userid(), Some(false));
                    } else {
                        assert_eq!(c.userids.add_userid(), None);
                    }
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
                    assert_eq!(c.userids.designators.len(), 2);

                    if $add_userid {
                        assert_eq!(c.userids.add_userid(), Some(false));
                    } else {
                        assert_eq!(c.userids.add_userid(), None);
                    }
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
                    "--userid", "alice",
                    "--add-userid"
                ]);
                if $userid && $add_userid {
                    let m = m.expect("valid arguments");
                    let c = CLI::from_arg_matches(&m).expect("ok");
                    assert_eq!(c.userids.designators.len(), 1);
                    assert_eq!(c.userids.add_userid(), Some(true));
                } else {
                    assert!(m.is_err());
                }
            }}
        }

        // No Args.
        check!(typenum::U0,false, false, false);
        check!(UserIDArg,   true, false, false);
        check!(EmailArg,   false,  true, false);
        check!(MaybeSelfSignedUserIDEmailArgs, true,  true, true);
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
            pub userids: UserIDDesignators<MaybeSelfSignedUserIDEmailArgs,
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
            pub userids: UserIDDesignators<MaybeSelfSignedUserIDEmailArgs,
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

        // Make sure we can only provide --add-userid if a designator
        // is also specified.
        let m = command.clone().try_get_matches_from(vec![
            "prog",
            "--add-userid",
        ]);
        assert!(m.is_err());
    }
}
