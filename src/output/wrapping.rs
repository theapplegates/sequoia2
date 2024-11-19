//! Line wrapping human-readable output.

use std::fmt;
use std::sync::OnceLock;

/// A non-breaking space.
pub const NBSP: char = '\u{00A0}';

/// Prints the given message to stderr.
///
/// Hint: Use `wprintln!(..)` instead of invoking this function
/// directly.
pub fn wprintln(msg: fmt::Arguments) {
    let m = format!("{}", msg);
    for l in textwrap::wrap(&m, options()) {
        eprintln!("{}", l);
    }
}

/// Prints the given message to stderr, indenting continuations.
///
/// Hint: Use `wprintln!(indent="...", ..)` or
/// `wprintln!(initial_indent="...", subsequent_indent="...", ..)`
/// instead of invoking this function directly.
pub fn iwprintln(initial_indent: &str,
                 subsequent_indent: &str,
                 msg: fmt::Arguments) {
    let m = format!("{}", msg);
    for l in textwrap::wrap(&m,
                            options()
                            .initial_indent(initial_indent)
                            .subsequent_indent(subsequent_indent)) {
        eprintln!("{}", l);
    }
}

/// Returns options for text-wrapping.
fn options() -> textwrap::Options<'static> {
    static OPTIONS: OnceLock<textwrap::Options> = OnceLock::new();
    OPTIONS.get_or_init(|| {
        // It is better to use terminal_size instead of letting
        // textwrap do it, because textwrap uses an older version,
        // leading to duplicate crates.
        textwrap::Options::new(stderr_terminal_width())
    }).clone()
}

/// Returns the terminal width we assume for wrapping.
pub fn stderr_terminal_width() -> usize {
    // XXX: For compatibility with terminal_size 0.2 and 0.3.  Once we
    // depend on 0.4, use terminal_size_of instead.
    platform! {
        unix => {
            use std::os::fd::AsRawFd;
            #[allow(deprecated)]
            unsafe {
                terminal_size::terminal_size_using_fd(std::io::stderr().as_raw_fd())
            }
        },
        windows => {
            terminal_size::terminal_size()
        },
    }
        .map(|(w, _h)| w.0)
        .map(Into::into)
        .unwrap_or(usize::MAX)
}
