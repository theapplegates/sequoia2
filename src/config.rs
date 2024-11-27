//! Configuration model and file parsing.

use std::{
    collections::HashSet,
    fs,
    io,
    path::PathBuf,
    time::SystemTime,
};

use aho_corasick::AhoCorasick;
use anyhow::Context;
use clap::{ValueEnum, parser::ValueSource};

use toml_edit::{
    DocumentMut,
    Item,
    Table,
    Value,
};

use sequoia_openpgp::policy::StandardPolicy;
use sequoia_net::reqwest::Url;
use sequoia_directories::{Component, Home};
use sequoia_policy_config::ConfiguredStandardPolicy;

use crate::{
    Result,
    cli,
    cli::config::Augmentations,
};

/// Represents configuration at runtime.
///
/// This struct is manipulated when parsing the configuration file.
/// It is available as `Sq::config`, with suitable accessors that
/// handle the precedence of the various sources.
pub struct Config {
    policy_path: Option<PathBuf>,
    policy_inline: Option<Vec<u8>>,
    cipher_suite: Option<sequoia_openpgp::cert::CipherSuite>,
    key_servers: Option<Vec<Url>>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            policy_path: None,
            policy_inline: None,
            cipher_suite: None,
            key_servers: None,
        }
    }
}

impl Config {
    /// Returns the cryptographic policy.
    ///
    /// We read in the default policy configuration, the configuration
    /// referenced in the configuration file, and the inline policy.
    pub fn policy(&mut self, at: SystemTime)
                  -> Result<StandardPolicy<'static>>
    {
        let mut policy = ConfiguredStandardPolicy::at(at);

        policy.parse_default_config()?;

        if let Some(p) = &self.policy_path {
            if ! policy.parse_config_file(p)? {
                return Err(anyhow::anyhow!(
                    "referenced policy file {:?} does not exist", p));
            }
        }

        if let Some(p) = &self.policy_inline {
            policy.parse_bytes(p)?;
        }

        Ok(policy.build())
    }

    /// Returns the cipher suite for generating new keys.
    ///
    /// Handles the precedence of the various sources:
    ///
    /// - If the flag is given, use the given value.
    /// - If the command line flag is not given, then
    ///   - use the value from the configuration file (if any),
    ///   - or use the default value.
    pub fn cipher_suite(&self, cli: &cli::key::CipherSuite,
                        source: Option<ValueSource>)
                        -> sequoia_openpgp::cert::CipherSuite
    {
        match source.expect("set by the cli parser") {
            ValueSource::DefaultValue =>
                self.cipher_suite.unwrap_or_else(
                    || cli.as_ciphersuite()),
            _ => cli.as_ciphersuite(),
        }
    }

    /// Returns the key servers to query or publish.
    ///
    /// Handles the precedence of the various sources:
    ///
    /// - If the flag is given, use the given value.
    /// - If the command line flag is not given, then
    ///   - use the value from the configuration file (if any),
    ///   - or use the default value.
    pub fn key_servers<'s>(&'s self, cli: &'s Vec<String>,
                           source: Option<ValueSource>)
                           -> impl Iterator<Item = &'s str> + 's
    {
        match source.expect("set by the cli parser") {
            ValueSource::DefaultValue =>
                self.key_servers.as_ref()
                .map(|s| Box::new(s.iter().map(|s| s.as_str()))
                     as Box<dyn Iterator<Item = &str>>)
                .unwrap_or_else(|| Box::new(cli.iter().map(|s| s.as_str()))
                                as Box<dyn Iterator<Item = &str>>),
            _ => Box::new(cli.iter().map(|s| s.as_str()))
                as Box<dyn Iterator<Item = &str>>,
        }
    }
}

/// Holds the document tree of the configuration file.
#[derive(Debug, Default)]
pub struct ConfigFile {
    doc: DocumentMut,
}

impl ConfigFile {
    /// A template for the configuration containing the default
    /// values.
    const TEMPLATE: &'static str = "\
# Configuration template for sq <SQ-VERSION>
<SQ-CONFIG-PATH-HINT>

[key.generate]
#cipher-suite = <DEFAULT-CIPHER-SUITE>

[network]
#keyservers = <DEFAULT-KEY-SERVERS>

[policy]
#path = <DEFAULT-POLICY-FILE>

# The policy can be inlined, either alternatively, or additionally,
# like so:

<DEFAULT-POLICY-INLINE>
";

    /// Patterns to match on in `Self::DEFAULT` to be replaced with
    /// the default values.
    const TEMPLATE_PATTERNS: &'static [&'static str] = &[
        "<SQ-VERSION>",
        "<SQ-CONFIG-PATH-HINT>",
        "<DEFAULT-CIPHER-SUITE>",
        "<DEFAULT-KEY-SERVERS>",
        "<DEFAULT-POLICY-FILE>",
        "<DEFAULT-POLICY-INLINE>",
    ];

    /// Returns a configuration template with the defaults.
    fn config_template(path: Option<PathBuf>) -> Result<String> {
        let ac = AhoCorasick::new(Self::TEMPLATE_PATTERNS)?;

        let mut p = ConfiguredStandardPolicy::new();
        p.parse_default_config()?;

        let mut default_policy_inline = Vec::new();
        p.dump(&mut default_policy_inline,
               sequoia_policy_config::DumpDefault::Template)?;
        let default_policy_inline =
            regex::Regex::new(r"(?m)^\[")?.replace_all(
                std::str::from_utf8(&default_policy_inline)?, "[policy.");

        Ok(ac.replace_all(Self::TEMPLATE, &[
            &env!("CARGO_PKG_VERSION").to_string(),
            &if let Some(path) = path {
                format!(
                    "\n\
                     # To use it, edit it to your liking and write it to\n\
                     # {}",
                    &path.display())
            } else {
                "".into()
            },
            &format!("{:?}", cli::key::CipherSuite::default().
                     to_possible_value().unwrap().get_name()),
            &format!("{:?}", cli::network::keyserver::DEFAULT_KEYSERVERS),
            &format!("{:?}", ConfiguredStandardPolicy::CONFIG_FILE),
            &default_policy_inline.to_string(),
        ]))
    }

    /// Returns the default configuration in template form.
    ///
    /// All the configuration options with their defaults are
    /// commented out.
    pub fn default_template(home: Option<&Home>) -> Result<Self> {
        let template = Self::config_template(home.map(Self::file_name))?;
        let doc: DocumentMut = template.parse()
            .context("Parsing default configuration failed")?;
        Ok(Self {
            doc,
        })
    }

    /// Returns the default configuration.
    pub fn default_config(home: Option<&Home>) -> Result<Self> {
        let template = Self::config_template(home.map(Self::file_name))?;

        // Enable all defaults by commenting-in.
        let r = regex::Regex::new(r"(?m)^#([^ ])")?;
        let defaults = r.replace_all(&template, "$1");

        let doc: DocumentMut = defaults.parse()
            .context("Parsing default configuration failed")?;
        Ok(Self {
            doc,
        })
    }

    /// Returns the path of the config file.
    pub fn file_name(home: &Home) -> PathBuf {
        home.config_dir(Component::Sq).join("config.toml")
    }

    /// Reads and validates the configuration file.
    pub fn read(&mut self, home: &Home)
                -> Result<Config>
    {
        let mut config = Config::default();
        self.read_internal(home, Some(&mut config), None)?;
        Ok(config)
    }

    /// Reads and validates the configuration file.
    pub fn read_and_augment(&mut self, home: &Home) -> Result<Augmentations>
    {
        let mut augmentations = Augmentations::default();
        self.read_internal(home, None, Some(&mut augmentations))?;
        Ok(augmentations)
    }

    /// Reads and validates the configuration file, and optionally
    /// applies them to the given configuration, and optionally
    /// supplies augmentations for the help texts in the command line
    /// parser.
    fn read_internal(&mut self, home: &Home, mut config: Option<&mut Config>,
                     mut cli: Option<&mut Augmentations>)
                     -> Result<()>
    {
        let path = Self::file_name(home);
        let raw = match fs::read_to_string(&path) {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::NotFound =>
                Self::config_template(Some(path.clone()))?,
            Err(e) => return Err(anyhow::Error::from(e).context(
                format!("Reading configuration file {} failed",
                        path.display()))),
        };

        let doc: DocumentMut = raw.parse()
            .with_context(|| format!("Parsing configuration file {} failed",
                                     path.display()))?;

        apply_schema(&mut config, &mut cli, None, doc.iter(), TOP_LEVEL_SCHEMA)
            .with_context(|| format!("Parsing configuration file {} failed",
                                     path.display()))?;
        self.doc = doc;

        Ok(())
    }

    /// Writes the configuration to the disk.
    pub fn persist(&self, home: &Home) -> Result<()> {
        let path = Self::file_name(home);
        let dir = path.parent().unwrap();

        fs::create_dir_all(dir)?;

        let mut t =
            tempfile::NamedTempFile::new_in(dir)?;
        self.dump(&mut t)?;
        t.persist(path)?;

        Ok(())
    }

    /// Writes the configuration to the given writer.
    pub fn dump(&self, sink: &mut dyn io::Write) -> Result<()> {
        write!(sink, "{}", self.doc.to_string())?;
        Ok(())
    }

    /// Verifies the configuration.
    pub fn verify(&self) -> Result<()> {
        let mut config = Default::default();
        apply_schema(&mut Some(&mut config), &mut None, None, self.doc.iter(),
                     TOP_LEVEL_SCHEMA)?;
        config.policy(SystemTime::now())?;
        Ok(())
    }

    /// Augments the configuration with the given policy.
    ///
    /// XXX: Due to the way doc.remove works, it will leave misleading
    /// comments behind.  Therefore, the resulting configuration is
    /// not suitable for dumping, but may only be used for
    /// commands::config::get.
    pub fn augment_with_policy(&self, p: &StandardPolicy) -> Result<Self> {
        use std::io::Write;
        let mut raw = Vec::new();

        // First, start with our configuration, and drop most of the
        // policy with the exception of the path.
        let p = ConfiguredStandardPolicy::from_policy(p.clone());
        let mut doc = self.doc.clone();
        doc.remove("policy");

        use crate::toml_edit_tree::Node;
        let policy_path: crate::toml_edit_tree::Path
            = "policy.path".parse().unwrap();
        if let Ok(p) = self.as_item().traverse(&policy_path) {
            let p =
                p.as_atomic_value().unwrap().as_str().unwrap().to_string();
            doc.as_table_mut().insert("policy", Item::Table(
                [("path", Value::from(p))]
                    .into_iter().collect()));
        }

        write!(&mut raw, "{}", doc.to_string())?;

        // Then, augment the configuration with the effective policy.
        let mut default_policy_inline = Vec::new();
        p.dump(&mut default_policy_inline,
               sequoia_policy_config::DumpDefault::Template)?;
        let default_policy_inline =
            regex::Regex::new(r"(?m)^\[")?.replace_all(
                std::str::from_utf8(&default_policy_inline)?, "[policy.");

        write!(&mut raw, "{}", default_policy_inline)?;

        // Now, parse the resulting configuration.
        let doc: DocumentMut = std::str::from_utf8(&raw)?.parse()?;

        // Double check that it is well-formed.
        apply_schema(&mut None, &mut None, None, doc.iter(), TOP_LEVEL_SCHEMA)?;

        Ok(Self {
            doc,
        })
    }

    /// Returns the document tree.
    pub fn as_item(&self) -> &Item {
        self.doc.as_item()
    }

    /// Returns the mutable document tree.
    pub fn as_item_mut(&mut self) -> &mut Item {
        self.doc.as_item_mut()
    }
}

/// Validates a configuration section using a schema, and optionally
/// applies changes to the configuration and CLI augmentations.
///
/// Returns an error if a key is unknown.
///
/// known_keys better be lowercase.
fn apply_schema<'toml>(config: &mut Option<&mut Config>,
                       cli: &mut Option<&mut Augmentations>,
                       path: Option<&str>,
                       section: toml_edit::Iter<'toml>,
                       schema: Schema) -> Result<()> {
    let section = section.collect::<Vec<_>>();
    let known_keys: Vec<_> =
        schema.iter().map(|(key, _)| *key).collect();

    // Schema keys better be lowercase.
    debug_assert!(known_keys.iter().all(|&s| &s.to_lowercase() == s),
                  "keys in schema must be lowercase");

    // Schema keys better be sorted.
    debug_assert!(known_keys.windows(2).all(|v| v[0] <= v[1]),
                  "keys in schema must be sorted");
    // XXX: once [].is_sorted is stabilized:
    // debug_assert!(known_keys.is_sorted(), "keys in schema must be sorted");

    let prefix = if let Some(path) = path {
        format!("{}.", path)
    } else {
        "".to_string()
    };

    let keys: HashSet<&str> = section
        .iter().map(|(key, _value)| *key)
        .collect();

    // The set of allowed keys are the known keys, plus
    // "ignore_invalid", and the value of "ignore_invalid".
    let mut allowed_keys: Vec<&str> = known_keys.to_vec();
    if let Some(ignore) = section.iter()
        .find_map(|(k, v)| (*k == "ignore_invalid").then_some(*v))
    {
        allowed_keys.push("ignore_invalid");
        match ignore {
            Item::Value(Value::String(k)) =>
                allowed_keys.push(k.value().as_str()),
            Item::Value(Value::Array(ks)) => {
                for k in ks {
                    if let Value::String(k) = k {
                        allowed_keys.push(k.value().as_str());
                    } else {
                        Err(Error::ParseError(format!(
                            "'{}ignore_invalid' takes a string \
                             or an array of strings",
                            prefix)))?
                    }
                }
            }
            _ => {
                return Err(Error::ParseError(format!(
                    "Invalid value for '{}ignore_invalid': {}, \
                     expected a string or an array of strings",
                    prefix, ignore)).into());
            }
        }
    }

    // Now check if there are any unknown sections.
    let unknown_keys = keys
        .difference(&allowed_keys.into_iter().collect())
        .map(|s| *s)
        .collect::<Vec<_>>();
    if ! unknown_keys.is_empty() {
        return Err(Error::ParseError(format!(
            "{} has unknown keys: {}, valid keys are: {}",
            if let Some(path) = path {
                path
            } else {
                "top-level section"
            },
            unknown_keys.join(", "),
            // We don't include the keys listed in ignore_invalid.
            known_keys.join(", "))).into());
    }

    // Now validate the values.
    for (key, value) in &section {
        if let Ok(i) = schema.binary_search_by_key(key, |(k, _)| k) {
            let apply = schema[i].1;
            (apply)(config, cli, &format!("{}{}", prefix, key), value)
                .with_context(|| format!("Error validating {:?}", key))?;
        }
    }

    Ok(())
}

/// Errors used in this module.
///
/// Note: This enum cannot be exhaustively matched to allow future
/// extensions.
#[non_exhaustive]
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Parse error
    #[error("Parse error: {0}")]
    ParseError(String),

    /// A Relative Path was provided where an absolute path was expected.
    #[error("Relative path not allowed: {0}")]
    RelativePathError(PathBuf),

    /// An algorithm is not known to this crate.
    #[error("Unknown algorithm: {0}")]
    UnknownAlgorithm(String),

    #[error("Configuration item {0:?} is not a {1} but a {2}")]
    BadType(String, &'static str, &'static str),
}

impl Error {
    /// Returns an `Error::BadType` given an item.
    fn bad_item_type(path: &str, i: &Item, want_type: &'static str)
                     -> anyhow::Error
    {
        Error::BadType(path.into(), want_type, i.type_name()).into()
    }

    /// Returns an `Error::BadType` given a value.
    fn bad_value_type(path: &str, v: &Value, want_type: &'static str)
                      -> anyhow::Error
    {
        Error::BadType(path.into(), want_type, v.type_name()).into()
    }
}

/// A function that validates a node in the configuration tree with
/// the given path, and optionally makes changes to the configuration
/// and CLI augmentations.
type Applicator = fn(&mut Option<&mut Config>, &mut Option<&mut Augmentations>,
                     &str, &Item)
                     -> Result<()>;

/// Ignores a node.
fn apply_nop(_: &mut Option<&mut Config>, _: &mut Option<&mut Augmentations>,
             _: &str, _: &Item)
             -> Result<()>
{
    Ok(())
}

/// A [`Schema`] maps keys to [`Applicator`]s.
type Schema = &'static [(&'static str, Applicator)];

/// Schema for the toplevel.
const TOP_LEVEL_SCHEMA: Schema = &[
    ("key", apply_key),
    ("network", apply_network),
    ("policy", apply_policy),
];

/// Schema for the `key` section.
const KEY_SCHEMA: Schema = &[
    ("generate", apply_key_generate),
];

/// Validates the `key` section.
fn apply_key(config: &mut Option<&mut Config>, cli: &mut Option<&mut Augmentations>,
                 path: &str, item: &Item)
                 -> Result<()>
{
    let section = item.as_table_like()
        .ok_or_else(|| Error::bad_item_type(path, item, "table"))?;
    apply_schema(config, cli, Some(path), section.iter(), KEY_SCHEMA)?;
    Ok(())
}

/// Schema for the `key.generate` section.
const KEY_GENERATE_SCHEMA: Schema = &[
    ("cipher-suite", apply_key_generate_cipher_suite),
];

/// Validates the `key.generate` section.
fn apply_key_generate(config: &mut Option<&mut Config>,
                      cli: &mut Option<&mut Augmentations>,
                      path: &str, item: &Item)
                      -> Result<()>
{
    let section = item.as_table_like()
        .ok_or_else(|| Error::bad_item_type(path, item, "table"))?;
    apply_schema(config, cli, Some(path), section.iter(), KEY_GENERATE_SCHEMA)?;
    Ok(())
}

/// Validates the `key.generate.cipher-suite` value.
fn apply_key_generate_cipher_suite(config: &mut Option<&mut Config>,
                                   cli: &mut Option<&mut Augmentations>,
                                   path: &str, item: &Item)
                                   -> Result<()>
{
    let s = item.as_str()
        .ok_or_else(|| Error::bad_item_type(path, item, "string"))?;
    let v = cli::key::CipherSuite::from_str(s, true)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    if let Some(config) = config {
        config.cipher_suite = Some(v.as_ciphersuite());
    }

    if let Some(cli) = cli {
        cli.insert(
            "key.generate.cipher-suite",
            v.to_possible_value().expect("just validated").get_name().into());
    }

    Ok(())
}

/// Schema for the `network` section.
const NETWORK_SCHEMA: Schema = &[
    ("keyservers", apply_network_keyservers),
];

/// Validates the `network` section.
fn apply_network(config: &mut Option<&mut Config>, cli: &mut Option<&mut Augmentations>,
                 path: &str, item: &Item)
                 -> Result<()>
{
    let section = item.as_table_like()
        .ok_or_else(|| Error::bad_item_type(path, item, "table"))?;
    apply_schema(config, cli, Some(path), section.iter(), NETWORK_SCHEMA)?;
    Ok(())
}

/// Validates the `network.keyservers` value.
fn apply_network_keyservers(config: &mut Option<&mut Config>,
                            cli: &mut Option<&mut Augmentations>,
                            path: &str, item: &Item)
                            -> Result<()>
{
    let list = item.as_array()
        .ok_or_else(|| Error::bad_item_type(path, item, "array"))?;

    let mut servers_str = Vec::new();
    let mut servers_url = Vec::new();
    for (i, server) in list.iter().enumerate() {
        let server_str = server.as_str()
            .ok_or_else(|| Error::bad_value_type(&format!("{}.{}", path, i),
                                                 server, "string"))?;

        let url = Url::parse(server_str)?;
        let s = url.scheme();
        match s {
            "hkp" => (),
            "hkps" => (),
            _ => return Err(anyhow::anyhow!(
                "must be a hkp:// or hkps:// URL: {}", url)),
        }

        servers_str.push(server_str);
        servers_url.push(url);
    }

    if let Some(cli) = cli {
        cli.insert("network.keyserver.servers", servers_str.join(" "));
    }

    if let Some(config) = config {
        config.key_servers = Some(servers_url);
    }

    Ok(())
}

/// Schema for the `policy` section.
const POLICY_SCHEMA: Schema = &[
    ("aead_algorithms", apply_nop),
    ("asymmetric_algorithms", apply_nop),
    ("hash_algorithms", apply_nop),
    ("packets", apply_nop),
    ("path", apply_policy_path),
    ("symmetric_algorithms", apply_nop),
];

/// Validates the `policy` section.
fn apply_policy(config: &mut Option<&mut Config>,
                cli: &mut Option<&mut Augmentations>,
                path: &str, item: &Item)
                -> Result<()>
{
    let section = item.as_table_like()
        .ok_or_else(|| Error::bad_item_type(path, item, "table"))?;
    apply_schema(config, cli, Some(path), section.iter(), POLICY_SCHEMA)?;

    if let Some(config) = config {
        // Extract the inline policy.

        // XXX: This doesn't work because toml_edit bug
        // https://github.com/toml-rs/toml/issues/785
        //
        //let table = section.iter().collect::<Table>();
        //
        // Instead, we have to use a workaround:
        let mut table = Table::new();
        section.iter().for_each(|(k, v)| { table.insert(k, v.clone()); });

        let mut inline = DocumentMut::from(table);
        inline.remove("path");
        config.policy_inline = Some(inline.to_string().into_bytes());
    }

    Ok(())
}

/// Validates the `policy.path` value.
fn apply_policy_path(config: &mut Option<&mut Config>,
                     _: &mut Option<&mut Augmentations>,
                     path: &str, item: &Item)
                     -> Result<()>
{
    let path = item.as_str()
        .ok_or_else(|| Error::bad_item_type(path, item, "string"))?;

    if let Some(config) = config {
        config.policy_path = Some(path.into());
    }

    Ok(())
}
