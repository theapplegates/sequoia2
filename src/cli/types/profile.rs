//! OpenPGP profiles.

/// Profiles select versions of the OpenPGP standard.
#[derive(clap::ValueEnum, Default, Debug, Clone)]
pub enum Profile {
    /// RFC4880, published in 2007, defines "v4" OpenPGP.
    #[default]
    RFC4880,
}
