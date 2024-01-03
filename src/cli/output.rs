use clap::{ValueEnum, Parser};

#[derive(Parser, Debug)]
#[clap(
    name = "output-versions",
    display_order = 110,
    about = "List supported output versions",
)]
pub struct Command {
    /// List only the default output version.
    #[clap(long)]
    pub default: bool,
}

/// What output format to prefer, when there's an option?
#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum OutputFormat {
    /// Output that is meant to be read by humans, instead of programs.
    ///
    /// This type of output has no version, and is not meant to be
    /// parsed by programs.
    HumanReadable,

    /// Output as JSON.
    Json,

    /// Output as DOT.
    ///
    /// This format is supported by a few commands that emit a
    /// graphical network.  In particular, the \"sq wot\" subcommands
    /// can emit this format.
    #[cfg(feature = "dot-writer")]
    DOT,
}
