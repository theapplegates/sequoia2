//! Command-line parser for `sq config`.

use std::{
    collections::BTreeMap,
    sync::OnceLock,
};

use clap::{
    Parser,
    Subcommand,
};

use sequoia_directories::Home;

pub mod get;
pub mod inspect;
pub mod set;
pub mod template;

/// Computes the path to the config file even if argument parsing
/// failed.
///
/// This happens notably if `--help` is given.
pub fn find_home() -> Option<Home> {
    let args = std::env::args().collect::<Vec<_>>();

    for (i, arg) in args.iter().enumerate() {
        if arg == "--" {
            break;
        }

        if arg.starts_with("--home=") {
            return handle(Some(arg["--home=".len()..].into()));
        }

        if arg == "--home" {
            if let Some(home) = args.get(i + 1) {
                return handle(Some(home.into()));
            }
        }
    }

    /// Handle the argument to `--home`.
    fn handle(arg: Option<String>) -> Option<Home> {
        if let Some(arg) = arg {
            match arg.as_str() {
                "default" => Home::default().cloned(),
                "none" => None,
                _ => Home::new(Some(arg.into())).ok(),
            }
        } else {
            // No argument to `--home` is a syntax error.
            None
        }
    }

    // No `--home` argument, select the default, possibly overridden
    // by SEQUOIA_HOME.
    Home::new(None).ok()
}

/// Values read from the config file to be included in help messages.
pub type Augmentations = BTreeMap<&'static str, String>;

/// Includes values from the config file in help messages.
pub fn augment_help(key: &'static str, text: &str) -> String {
    if let Some(a) = get_augmentation(key) {
        format!("{}\n\
                 \n\
                 The default can be changed in the configuration \
                 file using the setting `{}`.
                 \n\
                 [config: {}] (overrides default)",
                text.trim_end(), key, a)
    } else {
        format!("{}\n\
                 \n\
                 The default can be changed in the configuration \
                 file using the setting `{}`.",
                text.trim_end(), key)
    }
}

/// Returns the value of an augmentation, if any.
pub fn get_augmentation(key: &str) -> Option<&str> {
    AUGMENTATIONS.get().and_then(|a| a.get(key).map(|v| v.as_str()))
}

/// Includes values from the config file in help messages.
pub fn set_augmentations(augmentations: Augmentations) {
    AUGMENTATIONS.set(augmentations)
        .expect("augmentations must only be set once");
}

/// Values read from the config file to be included in help messages.
static AUGMENTATIONS: OnceLock<Augmentations> = OnceLock::new();

#[derive(Debug, Parser)]
#[clap(
    name = "config",
    about = "Get configuration options",
    long_about = format!("\
Get configuration options

This subcommand can be used to inspect the configuration \
file{}, and to create a template that can be edited to your liking.

Configuration file: {}
",
        sequoia_directories::Home::default()
        .map(|home| {
            let p = home.config_dir(sequoia_directories::Component::Sq);
            let p = p.join("config.toml");
            let p = p.display().to_string();
            if let Some(home) = dirs::home_dir() {
                let home = home.display().to_string();
                if let Some(rest) = p.strip_prefix(&home) {
                    return format!(" (default location: $HOME{})",
                                   rest);
                }
            }
            format!(" (default location: {})", p)
        })
        .unwrap_or("".to_string()),
        find_home()
        .map(|home| {
            let p = home.config_dir(sequoia_directories::Component::Sq);
            let p = p.join("config.toml");
            let p = p.display().to_string();
            if let Some(home) = dirs::home_dir() {
                let home = home.display().to_string();
                if let Some(rest) = p.strip_prefix(&home) {
                    return format!("$HOME{}", rest);
                }
            }
            p
        })
        .unwrap_or("".to_string())),
    subcommand_required = true,
    arg_required_else_help = true,
    disable_help_subcommand = true,
)]
pub struct Command {
    #[clap(subcommand)]
    pub subcommand: Subcommands,
}

#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum Subcommands {
    Get(get::Command),
    Inspect(inspect::Command),
    Template(template::Command),
}
