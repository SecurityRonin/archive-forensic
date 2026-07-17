//! Error type for archive peeling and member reading. Fail loud; never silently
//! truncate, and always name the offending format/cap in the message.

use thiserror::Error;

pub type Result<T> = core::result::Result<T, ArchiveError>;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ArchiveError {
    /// A codec decoder failed on the packed stream.
    #[error("{format} decode failed: {detail}")]
    Decode {
        format: &'static str,
        detail: String,
    },

    /// The decompressed output exceeded the in-memory cap (bomb guard) — a
    /// loud failure, never a silent truncation.
    #[error("decompressed output exceeds the {cap}-byte cap")]
    TooLarge { cap: u64 },

    /// Parsing an archive's directory / central structure failed.
    #[error("{format} archive open failed: {detail}")]
    Open {
        format: &'static str,
        detail: String,
    },

    /// Extracting a single member failed (bad offset, unsupported member codec,
    /// CRC mismatch, …). The detail carries the backend's own diagnostic.
    #[error("{format} member read failed: {detail}")]
    Read {
        format: &'static str,
        detail: String,
    },

    /// A member index was out of range for the archive.
    #[error("member index {index} out of range ({count} members)")]
    IndexOutOfRange { index: usize, count: usize },

    /// The recursion peeled past the configured nesting limit (bomb guard). The
    /// chain names the layer path that tripped it.
    #[error("nesting depth exceeded the max of {max} at layer chain: {chain}")]
    DepthExceeded { max: usize, chain: String },

    /// The cumulative number of members across the whole recursion exceeded the
    /// configured cap (bomb guard).
    #[error("member count exceeded the max of {max}")]
    TooManyEntries { max: usize },

    /// The cumulative inflated size across the whole recursion exceeded the cap
    /// (bomb guard) — tracked across layers, not per layer.
    #[error("cumulative inflated size exceeded the {cap}-byte cap")]
    TotalInflatedExceeded { cap: u64 },
}
