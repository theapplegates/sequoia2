macro_rules! platform {
    { unix => { $($unix:tt)* }, windows => { $($windows:tt)* }, } => {
        if cfg!(unix) {
            #[cfg(unix)] { $($unix)* }
            #[cfg(not(unix))] { unreachable!() }
        } else if cfg!(windows) {
            #[cfg(windows)] { $($windows)* }
            #[cfg(not(windows))] { unreachable!() }
        } else {
            #[cfg(not(any(unix, windows)))] compile_error!("Unsupported platform");
            unreachable!()
        }
    }
}

/// Like eprintln, but nicely wraps lines.
macro_rules! wprintln {
    {} => {
        eprintln!();
    };
    { $($arg: expr),* } => {
        crate::output::wrapping::wprintln(format_args!($($arg),*))
    };
}
