//! Formats hints for users.

use std::fmt;

/// Formats a hint for the user.
pub struct Hint {
    /// Whether to suppress printing the hint.
    quiet: bool,

    /// Whether this is the first hint in this hint block.
    first: bool,
}

impl Hint {
    /// Constructs a new hint, optionally suppressing it.
    pub fn new(quiet: bool) -> Self {
        Hint {
            quiet,
            first: true,
        }
    }

    /// Displays a message to the user.
    ///
    /// It will be prefixed with "Hint: ", and should either end in a
    /// full stop or colon, depending on whether or not a command hint
    /// follows.
    pub fn hint(mut self, msg: fmt::Arguments) -> Self {
        if ! self.quiet {
            wprintln!();
            wprintln!(
                initial_indent=if self.first { "Hint: " } else { "      " },
                subsequent_indent="      ",
                "{}", msg);
            self.first = false;
        }
        self
    }

    /// Suggests an `sq` command to the user.
    pub fn sq(self) -> Command {
        Command::new(self, "sq")
    }

    /// Suggests a free-form command to the user.
    pub fn command(self, cmd: fmt::Arguments) -> Self {
        if ! self.quiet {
            wprintln!();

            // XXX: Don't wrap the command, so that if it wraps hard,
            // at least users can still copy and paste it.  It'd be
            // nice to wrap it nicely, but that would either require
            // parsing the command, or changing the hint framework to
            // hand in an argument vectors, and doing some smarter
            // line wrapping.
            eprintln!("  {}", cmd);
        }
        self
    }
}

/// A structured command hint.
pub struct Command {
    hint: Hint,
    args: Vec<String>,
}

impl Command {
    fn new(hint: Hint, argv0: &str) -> Self {
        Command {
            hint,
            args: vec![argv0.into()],
        }
    }

    /// Adds `arg` to the command.
    pub fn arg<S: ToString>(mut self, arg: S) -> Self {
        self.args.push(arg.to_string());
        self
    }

    /// Adds an argument `arg` with value to the command.
    pub fn arg_value<S: ToString, V: ToString>(mut self, arg: S, value: V)
                                               -> Self
    {
        self.args.push(format!("{}={}", arg.to_string(), value.to_string()));
        self
    }

    /// Emits the command hint.
    pub fn done(self) -> Hint {
        if ! self.hint.quiet {
            let width = crate::output::wrapping::terminal_width();

            eprintln!();
            eprintln!("{}", crate::cli::examples::wrap_command(
                &self.args, width, width));
        }

        self.hint
    }
}
