//! `archive_core` — a pure-Rust, `forbid(unsafe)`, read-only **archive layer**
//! reader for forensics.
//!
//! An archive is treated as a transparent optional *archive layer*: `foo.E01.gz`
//! resolves identically to `foo.E01`. [`peel_bytes`] removes one archive layer
//! when present, so a consumer can recurse until it reaches the real evidence.
//!
//! Format determination follows the settled model: the **content magic** is the
//! authority for the compression codec actually applied (you cannot gzip-decode
//! bzip2 bytes), while the **file name** is a secondary hint used for aliases
//! (`.tgz`→gzip+tar) and the magic-absent formats. See [`sniff`].
//!
//! Codec coverage grows incrementally; gzip is wired first (the canonical
//! `E01.gz` archive layer). Large-member streaming / temp-spill (for multi-GB
//! inner evidence) is the next hardening step — today the peel is in-memory with
//! a hard output cap.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod archive;
mod archive_layer;
mod detect;
mod error;
mod execute;
mod peel;
mod plan;
mod reassemble;
mod resolve;

pub use archive::{Archive, ArchiveEntry};
pub use archive_layer::{peel_archive, Peel};
pub use detect::{sniff, Format};
pub use error::{ArchiveError, Result};
pub use execute::{
    peel_archive_seekable, PeelSource, PeeledSource, ReadSeek, SubRange, TempBacked,
};
pub use peel::{peel_bytes, PeelOutcome};
pub use plan::{detect, Access, AccessPlan, Codec, Segment, SegmentKind};
pub use reassemble::{reassemble, segment_sources, ConcatSource, Reassembled, SegmentSources};
pub use resolve::{resolve, Limits, Node};
