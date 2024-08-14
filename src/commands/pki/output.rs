use openpgp::packet::UserID;
use openpgp::Fingerprint;
use openpgp::Result;
use sequoia_openpgp as openpgp;

use sequoia_wot as wot;
use wot::Path;

mod human_readable;
pub use human_readable::print_path;
pub use human_readable::print_path_error;
pub use human_readable::print_path_header;
pub use human_readable::HumanReadableOutputNetwork;

mod concise_human_readable;
pub use concise_human_readable::ConciseHumanReadableOutputNetwork;

/// Trait to implement adding of Paths and outputting them in a specific format
///
/// This trait is implemented to consume a vector of Path, trust amount tuples,
/// a target Fingerprint, a target UserID, and aggregated trust amount (for the
/// target UserID) to allow further processing and eventual output in a desired
/// output format.
pub trait OutputType {
    /// Add Paths for a UserID associated with a Fingerprint
    ///
    /// Paths are provided in a vector of Path, trust amount tuples.
    /// The aggregated_amount represents the (total) trust amount (derived from
    /// the Paths) for the UserID associated with the Fingerprint
    fn add_paths(
        &mut self,
        paths: Vec<(Path, usize)>,
        fingerprint: &Fingerprint,
        userid: &UserID,
        aggregated_amount: usize,
    ) -> Result<()>;

    /// Output the data consumed via add_paths() in a specific output format
    fn finalize(&mut self) -> Result<()>;
}
