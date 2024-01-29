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

/// Like wprintln, but doesn't emit anything in quiet mode.
macro_rules! make_qprintln {
    ($quiet: expr) => {
        macro_rules! qprintln {
            {} => {
                if ! $quiet {
                    wprintln!();
                }
            };
            { $a0: expr } => {
                if ! $quiet {
                    wprintln!($a0);
                }
            };
            { $a0: expr, $a1: expr } => {
                if ! $quiet {
                    wprintln!($a0, $a1);
                }
            };
            { $a0: expr, $a1: expr, $a2: expr } => {
                if ! $quiet {
                    wprintln!($a0, $a1, $a2);
                }
            };
            { $a0: expr, $a1: expr, $a2: expr, $a3: expr } => {
                if ! $quiet {
                    wprintln!($a0, $a1, $a2, $a3);
                }
            };
            { $a0: expr, $a1: expr, $a2: expr, $a3: expr, $a4: expr } => {
                if ! $quiet {
                    wprintln!($a0, $a1, $a2, $a3, $a4);
                }
            };
            { $a0: expr, $a1: expr, $a2: expr, $a3: expr, $a4: expr, $a5: expr } => {
                if ! $quiet {
                    wprintln!($a0, $a1, $a2, $a3, $a4, $a5);
                }
            };
            { $a0: expr, $a1: expr, $a2: expr, $a3: expr, $a4: expr, $a5: expr, $a6: expr } => {
                if ! $quiet {
                    wprintln!($a0, $a1, $a2, $a3, $a4, $a5, $a6);
                }
            };
        }
    };
}
