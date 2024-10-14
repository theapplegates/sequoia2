//! Certificate and key import stats.

use std::sync::Arc;

use anyhow::Result;

use sequoia_cert_store::{
    LazyCert,
    store::{
        MergeCerts,
        MergePublicCollectStats,
    },
};

use crate::output::pluralize::Pluralize;

/// Certificate and key import stats.
pub struct ImportStats {
    pub certs: MergePublicCollectStats,
    pub keys: KeyStats,
}

impl Default for ImportStats {
    fn default() -> Self {
        ImportStats {
            certs: MergePublicCollectStats::new(),
            keys: Default::default(),
        }
    }
}

impl<'a> MergeCerts<'a> for ImportStats {
    fn merge_public<'b>(
        &self,
        new: Arc<LazyCert<'a>>,
        disk: Option<Arc<LazyCert<'b>>>,
    ) -> Result<Arc<LazyCert<'a>>> {
        self.certs.merge_public(new, disk)
    }
}

impl ImportStats {
    /// Print key and certificate import summary.
    pub fn print_summary(&self) -> Result<()> {
        if ! self.keys.is_empty() {
            self.keys.print_summary()?;
        }

        wprintln!("Imported {}, updated {}, {} unchanged, {}.",
                  self.certs.new_certs().of("new certificate"),
                  self.certs.updated_certs().of("certificate"),
                  self.certs.unchanged_certs().of("certificate"),
                  self.certs.errors().of("error"));
        Ok(())
    }
}

/// Key import stats.
#[derive(Debug, Default)]
pub struct KeyStats {
    /// Number of new keys.
    pub new: usize,

    /// Number of unchanged keys.
    pub unchanged: usize,

    /// Number of updated keys.
    pub updated: usize,

    /// Number of errors.
    pub errors: usize,
}

impl KeyStats {
    /// Returns whether there haven't been any key imports at all.
    pub fn is_empty(&self) -> bool {
        self.new == 0
            && self.unchanged == 0
            && self.updated == 0
            && self.errors == 0
    }

    /// Print key and certificate import summary.
    pub fn print_summary(&self) -> Result<()> {
        wprintln!("Imported {}, updated {}, {} unchanged, {}.",
                  self.new.of("new key"),
                  self.updated.of("key"),
                  self.unchanged.of("key"),
                  self.errors.of("error"));
        Ok(())
    }
}
