//! Formats hints for users.

use std::fmt;

/// Formats a hint for the user.
pub struct Hint {
    /// Whether to suppress printing the hint.
    quiet: bool,
}

impl Hint {
    /// Constructs a new hint, optionally suppressing it.
    pub fn new(quiet: bool) -> Self {
        Hint { quiet }
    }

    /// Displays a message to the user.
    ///
    /// It will be prefixed with "Hint: ", and should either end in a
    /// full stop or colon, depending on whether or not a command hint
    /// follows.
    pub fn hint(self, msg: fmt::Arguments) -> Self {
        if ! self.quiet {
            wprintln!(initial_indent="Hint: ",
                      subsequent_indent="      ",
                      "{}", msg);
        }
        self
    }

    /// Suggests a command to the user.
    pub fn command(self, cmd: fmt::Arguments) -> Self {
        if ! self.quiet {
            wprintln!();
            wprintln!(indent="  ", "{}", cmd);
        }
        self
    }
}
