//! Error type for archive peeling. Fail loud; never silently truncate.

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
}
