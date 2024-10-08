//! A type for absolute paths or default paths, and a clap parser.

use std::path::PathBuf;

/// Either an absolute path, or a default path.
///
/// Even though this type is homomorphic to [`Option<PathBuf>`], we
/// need a new type for this, because clap handles [`Option`]s
/// differently, and we cannot return [`Option<PathBuf>`] from
/// `TypedValueParser::parse_ref`.
#[derive(Clone, Debug)]
pub enum AbsolutePathOrDefault {
    /// An absolute path.
    Absolute(PathBuf),

    /// The default path.
    Default,
}

impl AbsolutePathOrDefault {
    /// Returns the absolute path, or `None` if the default path is to
    /// be used.
    pub fn path(&self) -> Option<PathBuf> {
        match self {
            AbsolutePathOrDefault::Absolute(p) => Some(p.clone()),
            AbsolutePathOrDefault::Default => None,
        }
    }
}

/// A value parser for absolute directories with explicit default.
///
/// If `default` is given, this parses to `None`.  If an empty path is
/// given, a hint is displayed to give `default` instead.
///
/// If a relative path is given, a hint is displayed to use an
/// absolute path instead.
#[derive(Clone, Default)]
pub struct AbsolutePathOrDefaultValueParser {}

impl clap::builder::TypedValueParser for AbsolutePathOrDefaultValueParser {
    type Value = AbsolutePathOrDefault;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::error::Error> {
        use clap::error::*;

        if value == "default" {
            return Ok(AbsolutePathOrDefault::Default);
        }

        if value.is_empty() {
            let mut err = Error::new(ErrorKind::InvalidValue)
                .with_cmd(cmd);
            if let Some(arg) = arg {
                err.insert(ContextKind::InvalidArg,
                           ContextValue::String(arg.to_string()));
            }
            err.insert(ContextKind::InvalidValue,
                       ContextValue::String("".into()));
            err.insert(ContextKind::SuggestedValue,
                       ContextValue::String("default".into()));
            err.insert(ContextKind::Suggested,
                       ContextValue::StyledStrs(vec![
                           "to use the default directory, use 'default'".into(),
                       ]));
            return Err(err);
        }

        let p = PathBuf::from(value);

        if ! p.is_absolute() {
            let mut err = Error::new(ErrorKind::InvalidValue)
                .with_cmd(cmd);
            if let Some(arg) = arg {
                err.insert(ContextKind::InvalidArg,
                           ContextValue::String(arg.to_string()));
            }
            err.insert(ContextKind::InvalidValue,
                       ContextValue::String(p.display().to_string()));
            err.insert(ContextKind::Suggested,
                       ContextValue::StyledStrs(vec![
                           "must be an absolute path".into(),
                       ]));
            return Err(err);
        }

        Ok(AbsolutePathOrDefault::Absolute(p))
    }
}
