//! The unified **disk-image detour** entry point. A single function the
//! image-opening consumers (disk-forensic, 4n6mount) call so the sniff-gate +
//! peel/extract decision lives here once, instead of being duplicated in each.
//!
//! Unlike [`crate::resolve`] (content-driven, unwraps everything), the detour is
//! for a single wrapped *evidence image*: it peels one bare gzip/bzip2 wrapper —
//! guarded by the file name so a raw disk with coincidental magic is left
//! alone — OR extracts the lone member of a one-member archive. A multi-member
//! archive is a *collection*, not a wrapped image, so it is reported
//! [`Detour::NotPacked`] and left to the caller. Each consumer keeps its own
//! spill-to-tmp + recurse-into-container orchestration around this call.

use crate::archive::Archive;
use crate::detect::sniff;
use crate::error::{ArchiveError, Result};
use crate::peel::{peel_bytes, PeelOutcome};
use crate::resolve::Limits;

/// The outcome of a disk-image detour.
#[derive(Debug)]
pub enum Detour {
    /// Not a wrapped/single-member image — open `data` directly.
    NotPacked,
    /// One peeled bare-wrapper stream, or the single extracted archive member.
    Inner(Vec<u8>),
}

/// Peel a bare gz/bz2 wrapper, OR extract the single member of a one-member
/// archive, to inner bytes. Multi-member archives (a collection, not a wrapped
/// image) return [`Detour::NotPacked`], as does anything unrecognized.
///
/// A bare-wrapper peel is guarded by the file **name**: a raw disk that happens
/// to start with gzip/bzip2 magic but lacks a compression extension is left as
/// [`Detour::NotPacked`] (the coincidental-magic guard). Archive extraction is
/// keyed on magic alone, which is unambiguous for zip/7z/tar.
///
/// # Errors
/// A decode/open/read failure from the underlying layer, or
/// [`ArchiveError::TotalInflatedExceeded`] when the extracted bytes exceed
/// `limits.max_total_inflated`.
pub fn peel_detour(data: &[u8], name: Option<&str>, limits: &Limits) -> Result<Detour> {
    let format = sniff(name, data);

    if format.is_compression_wrapper() {
        // Coincidental-magic guard: only peel when the name agrees it is packed.
        if !has_compression_ext(name) {
            return Ok(Detour::NotPacked);
        }
        let inner = match peel_bytes(data, name)? {
            PeelOutcome::Peeled { inner, .. } => inner,
            // cov:unreachable: is_compression_wrapper() guarantees a Peeled outcome
            PeelOutcome::NotPacked => return Ok(Detour::NotPacked),
        };
        return cap(inner, limits);
    }

    if format.is_archive() {
        let Some(mut archive) = Archive::open(data, name)? else {
            // cov:unreachable: is_archive() guarantees open() returns Some
            return Ok(Detour::NotPacked);
        };
        // A single *file* member (directories don't count) is a wrapped image;
        // anything else is a collection left to the caller.
        let file_indices: Vec<usize> = archive
            .entries()
            .iter()
            .enumerate()
            .filter(|(_, e)| !e.is_dir)
            .map(|(i, _)| i)
            .collect();
        if let [only] = file_indices[..] {
            let inner = archive.read(only)?;
            return cap(inner, limits);
        }
        return Ok(Detour::NotPacked);
    }

    Ok(Detour::NotPacked)
}

/// Enforce the detour's cumulative inflated cap on a single extraction.
fn cap(inner: Vec<u8>, limits: &Limits) -> Result<Detour> {
    if inner.len() as u64 > limits.max_total_inflated {
        return Err(ArchiveError::TotalInflatedExceeded {
            cap: limits.max_total_inflated,
        });
    }
    Ok(Detour::Inner(inner))
}

/// Does the file name carry a compression-wrapper extension (incl. tar aliases)?
/// This is the coincidental-magic guard for the bare-wrapper branch, kept here
/// as the single fleet copy the image-opening consumers share.
fn has_compression_ext(name: Option<&str>) -> bool {
    let Some(name) = name else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    [
        ".gz", ".bz2", ".xz", ".tgz", ".taz", ".tbz", ".tbz2", ".txz", ".tzst", ".tlz", ".zst",
        ".z",
    ]
    .iter()
    .any(|e| lower.ends_with(e))
}
