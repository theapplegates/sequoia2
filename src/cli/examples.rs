//! A framework to format and check examples.
//!
//! The help text for subcommands includes examples.  That's great.
//! But, it is even better when they are tested.  This module defines
//! data structures to describe the examples, mechanisms to format the
//! examples, and infrastructure to execute the examples.

use clap::builder::IntoResettable;
use clap::builder::Resettable;

/// A command that is executed by the integration test, but not shown
/// in the manual pages.
pub struct Setup<'a> {
    pub command: &'a [ &'a str ],
}

/// A command that is executed by the integration test, and shown in
/// the manual pages.
pub struct Example<'a> {
    // A human-readable comment.
    pub comment: &'a str,
    pub command: &'a [ &'a str ],
}

/// An action to execute.
#[allow(dead_code)]
pub enum Action<'a> {
    /// A command that is executed by the integration test, but not
    /// shown in the manual pages.
    Setup(Setup<'a>),

    /// A command that is executed by the integration test, and shown
    /// in the manual pages.
    Example(Example<'a>),
}

impl<'a> Action<'a> {
    /// Return the action's command, if any.
    #[allow(dead_code)]
    pub fn command(&self) -> Option<&'a [ &'a str ]> {
        match self {
            Action::Setup(Setup { command, .. }) => Some(command),
            Action::Example(Example { command, .. }) => Some(command),
        }
    }
}

/// A sequence of actions to execute.
pub struct Actions<'a> {
    pub actions: &'a [Action<'a>],
}

impl<'a> IntoResettable<clap::builder::StyledStr> for Actions<'a> {
    fn into_resettable(self) -> Resettable<clap::builder::StyledStr> {
        // Default width when we aren't connected to a terminal.
        let default_width = 72;

        let terminal_size = terminal_size::terminal_size();
        let width = if let Some((width, _height)) = terminal_size {
            let width = width.0 as usize;

            if width < 40 {
                // If the terminal is too narrow, then give up and use
                // the default.
                default_width
            } else {
                std::cmp::max(40, width)
            }
        } else {
            72
        };

        let mut lines = vec![ "EXAMPLES:".to_string() ];

        lines.extend(self.actions
            .iter()
            .filter_map(|action| {
                let example = if let Action::Example(example) = action {
                    example
                } else {
                    return None;
                };

                let comment = textwrap::indent(
                    &textwrap::wrap(example.comment, width).join("\n"),
                    "# ");

                let command = example.command.iter()
                    .fold(vec!["$".to_string()], |mut s, arg| {
                        // Quote the argument, if necessary.
                        let arg = if arg.contains(&[
                            '\"',
                        ]) {
                            format!("'{}'", arg)
                        } else if arg.chars().any(char::is_whitespace)
                            || arg.contains(&[
                                '`', '#', '$', '&', '*', '(', ')',
                                '\\', '|', '[', ']', '{', '}',
                                ';', '\'', '<', '>', '?', '!',
                            ])
                        {
                            format!("\"{}\"", arg)
                        } else {
                            arg.to_string()
                        };

                        let last = s.last_mut().expect("have one");

                        let last_chars = last.chars().count();
                        let arg_chars = arg.chars().count();

                        // Our manpage generate complains if an
                        // example is too long:
                        //
                        // warning: Command in example exceeds 64 chars:
                        if last_chars + 1 + arg_chars <= width.min(64) {
                            *last = format!("{} {}", last, arg);
                        } else {
                            *last = format!("{} \\", last);
                            s.push(format!("  {}", arg));
                        }

                        s
                    })
                    .join("\n");

                Some(format!("{}\n{}", comment, command))
            }));

        let text = lines.join("\n\n").into();

        Resettable::Value(text)
    }
}

macro_rules! test_examples {
    ($ident:ident, $actions:expr) => {
        #[test]
        fn $ident() {
            use std::path::PathBuf;

            use tempfile::TempDir;
            use assert_cmd::Command;


            let fixtures = PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/data/examples"));

            let tmp_dir = TempDir::new().unwrap();

            dircpy::copy_dir(&fixtures, &tmp_dir)
                .expect(&format!("Copying {:?} to {:?}",
                                 fixtures, &tmp_dir));

            let cert_store = tmp_dir.path().join("cert-store");
            let key_store = tmp_dir.path().join("key-store");

            for action in $actions.actions {
                let command = if let Some(command) = action.command() {
                    command
                } else {
                    continue;
                };

                eprintln!("Executing: {:?}", command);

                Command::cargo_bin(command[0]).unwrap()
                    .current_dir(&tmp_dir)
                    .env("SQ_CERT_STORE", &cert_store)
                    .env("SQ_KEY_STORE", &key_store)
                    .args(&command[1..])
                    .assert()
                    .success();
            }
        }
    };
}
