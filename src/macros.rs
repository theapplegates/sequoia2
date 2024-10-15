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

    { indent=$i: expr, $($arg: expr),* } => {{
        let i = $i;
        crate::output::wrapping::iwprintln(i.as_ref(), i.as_ref(),
                                           format_args!($($arg),*))
    }};

    {
        initial_indent=$ii: expr,
        subsequent_indent=$si: expr,
        $($arg: expr),*
    } => {{
        let ii = $ii;
        let si = $si;
        crate::output::wrapping::iwprintln(ii.as_ref(), si.as_ref(),
                                           format_args!($($arg),*))
    }};

    {
        initial_indent=$ii: expr,
        $($arg: expr),*
    } => {{
        let ii = $ii;
        let si = format!("{:1$}", "", ii.len());
        crate::output::wrapping::iwprintln(ii.as_ref(), si.as_ref(),
                                           format_args!($($arg),*))
    }};

    { $($arg: expr),* } => {
        crate::output::wrapping::wprintln(format_args!($($arg),*))
    };
}

/// Like wprintln, but doesn't emit anything in quiet mode.
macro_rules! make_qprintln {
    ($quiet: expr) => {
        macro_rules! qprintln {
            // XXX: Lot's of repetition due to the fact that nested
            // macros still cannot have repetitions:
            // https://github.com/rust-lang/rust/issues/83527

            // First, with `indent`.
            { indent=$i: expr } => {
                if ! $quiet {
                    wprintln!(indent=$i);
                }
            };
            { indent=$i: expr, $a0: expr } => {
                if ! $quiet {
                    wprintln!(indent=$i, $a0);
                }
            };
            { indent=$i: expr, $a0: expr, $a1: expr } => {
                if ! $quiet {
                    wprintln!(indent=$i, $a0, $a1);
                }
            };
            { indent=$i: expr, $a0: expr, $a1: expr, $a2: expr } => {
                if ! $quiet {
                    wprintln!(indent=$i, $a0, $a1, $a2);
                }
            };
            { indent=$i: expr, $a0: expr, $a1: expr, $a2: expr, $a3: expr } => {
                if ! $quiet {
                    wprintln!(indent=$i, $a0, $a1, $a2, $a3);
                }
            };
            { indent=$i: expr, $a0: expr, $a1: expr, $a2: expr, $a3: expr, $a4: expr } => {
                if ! $quiet {
                    wprintln!(indent=$i, $a0, $a1, $a2, $a3, $a4);
                }
            };
            { indent=$i: expr, $a0: expr, $a1: expr, $a2: expr, $a3: expr, $a4: expr, $a5: expr } => {
                if ! $quiet {
                    wprintln!(indent=$i, $a0, $a1, $a2, $a3, $a4, $a5);
                }
            };
            { indent=$i: expr, $a0: expr, $a1: expr, $a2: expr, $a3: expr, $a4: expr, $a5: expr, $a6: expr } => {
                if ! $quiet {
                    wprintln!(indent=$i, $a0, $a1, $a2, $a3, $a4, $a5, $a6);
                }
            };
            // Again, with `initial_indent` and `subsequent_indent`.
            { initial_indent=$ii: expr, subsequent_indent=$si: expr } => {
                if ! $quiet {
                    wprintln!(initial_indent=$ii, subsequent_indent=$si);
                }
            };
            { initial_indent=$ii: expr, subsequent_indent=$si: expr, $a0: expr } => {
                if ! $quiet {
                    wprintln!(initial_indent=$ii, subsequent_indent=$si, $a0);
                }
            };
            { initial_indent=$ii: expr, subsequent_indent=$si: expr, $a0: expr, $a1: expr } => {
                if ! $quiet {
                    wprintln!(initial_indent=$ii, subsequent_indent=$si, $a0, $a1);
                }
            };
            { initial_indent=$ii: expr, subsequent_indent=$si: expr, $a0: expr, $a1: expr, $a2: expr } => {
                if ! $quiet {
                    wprintln!(initial_indent=$ii, subsequent_indent=$si, $a0, $a1, $a2);
                }
            };
            { initial_indent=$ii: expr, subsequent_indent=$si: expr, $a0: expr, $a1: expr, $a2: expr, $a3: expr } => {
                if ! $quiet {
                    wprintln!(initial_indent=$ii, subsequent_indent=$si, $a0, $a1, $a2, $a3);
                }
            };
            { initial_indent=$ii: expr, subsequent_indent=$si: expr, $a0: expr, $a1: expr, $a2: expr, $a3: expr, $a4: expr } => {
                if ! $quiet {
                    wprintln!(initial_indent=$ii, subsequent_indent=$si, $a0, $a1, $a2, $a3, $a4);
                }
            };
            { initial_indent=$ii: expr, subsequent_indent=$si: expr, $a0: expr, $a1: expr, $a2: expr, $a3: expr, $a4: expr, $a5: expr } => {
                if ! $quiet {
                    wprintln!(initial_indent=$ii, subsequent_indent=$si, $a0, $a1, $a2, $a3, $a4, $a5);
                }
            };
            { initial_indent=$ii: expr, subsequent_indent=$si: expr, $a0: expr, $a1: expr, $a2: expr, $a3: expr, $a4: expr, $a5: expr, $a6: expr } => {
                if ! $quiet {
                    wprintln!(initial_indent=$ii, subsequent_indent=$si, $a0, $a1, $a2, $a3, $a4, $a5, $a6);
                }
            };

            // Again, with `initial_indent`.
            { initial_indent=$ii: expr } => {
                if ! $quiet {
                    wprintln!(initial_indent=$ii);
                }
            };
            { initial_indent=$ii: expr, $a0: expr } => {
                if ! $quiet {
                    wprintln!(initial_indent=$ii, $a0);
                }
            };
            { initial_indent=$ii: expr, $a0: expr, $a1: expr } => {
                if ! $quiet {
                    wprintln!(initial_indent=$ii, $a0, $a1);
                }
            };
            { initial_indent=$ii: expr, $a0: expr, $a1: expr, $a2: expr } => {
                if ! $quiet {
                    wprintln!(initial_indent=$ii, $a0, $a1, $a2);
                }
            };
            { initial_indent=$ii: expr, $a0: expr, $a1: expr, $a2: expr, $a3: expr } => {
                if ! $quiet {
                    wprintln!(initial_indent=$ii, $a0, $a1, $a2, $a3);
                }
            };
            { initial_indent=$ii: expr, $a0: expr, $a1: expr, $a2: expr, $a3: expr, $a4: expr } => {
                if ! $quiet {
                    wprintln!(initial_indent=$ii, $a0, $a1, $a2, $a3, $a4);
                }
            };
            { initial_indent=$ii: expr, $a0: expr, $a1: expr, $a2: expr, $a3: expr, $a4: expr, $a5: expr } => {
                if ! $quiet {
                    wprintln!(initial_indent=$ii, $a0, $a1, $a2, $a3, $a4, $a5);
                }
            };
            { initial_indent=$ii: expr, $a0: expr, $a1: expr, $a2: expr, $a3: expr, $a4: expr, $a5: expr, $a6: expr } => {
                if ! $quiet {
                    wprintln!(initial_indent=$ii, $a0, $a1, $a2, $a3, $a4, $a5, $a6);
                }
            };

            // Again, without any indent.
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
