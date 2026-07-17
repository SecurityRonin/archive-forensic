//! Member reading for the four archive formats — `.tgz`/`.tbz2` (+ plain
//! `ustar`), `.zip`/`.clbx`, and `.7z`.
//!
//! An [`Archive`] lists ([`entries`](Archive::entries)) and extracts
//! ([`read`](Archive::read)) members over an in-memory byte slice. Backends are
//! reused, never reimplemented: the tar family decompresses its outer layer with
//! [`crate::peel`]'s gzip/bzip2 decoders and walks members with the `tar` crate;
//! ZIP uses the fleet `zip-forensic-core` reader; 7z uses `sevenz-rust2`. Every
//! extraction is capped at [`crate::peel::MAX_INFLATED`]; a declared member size
//! is never trusted for allocation, and any backend error fails loud.

use crate::detect::{sniff, Format};
use crate::error::{ArchiveError, Result};
use crate::peel::{decode_bzip2, decode_gzip, MAX_INFLATED};

/// One member of an archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveEntry {
    /// Member path within the archive (as recorded — evidence, not sanitized).
    pub name: String,
    /// Uncompressed size in bytes, as declared by the archive metadata.
    pub size: u64,
    /// Whether the entry names a directory.
    pub is_dir: bool,
}

/// A decoded, listable archive over an in-memory byte slice.
pub struct Archive {
    format: Format,
    entries: Vec<ArchiveEntry>,
    backend: Backend,
}

/// The concrete reader behind an [`Archive`]. One variant per reused backend.
enum Backend {
    /// The decompressed tar byte stream; members are walked on demand.
    Tar { bytes: Vec<u8> },
}

impl Archive {
    /// Open `data` as one of the four archive formats, returning `Ok(None)` when
    /// it is not an archive (a bare wrapper or unrecognized input). `name` is an
    /// optional file-name hint used only to distinguish a compressed tar
    /// (`.tgz`/`.tbz2`) from a bare gzip/bzip2 stream.
    ///
    /// # Errors
    /// [`ArchiveError::Decode`] if the outer compression layer fails to inflate,
    /// [`ArchiveError::Open`] if the archive directory cannot be parsed, or
    /// [`ArchiveError::TooLarge`] if the outer inflate exceeds the cap.
    pub fn open(data: &[u8], name: Option<&str>) -> Result<Option<Archive>> {
        let format = sniff(name, data);
        match format {
            Format::Tar => Self::open_tar(format, data.to_vec()).map(Some),
            Format::TarGz => Self::open_tar(format, decode_gzip(data)?).map(Some),
            Format::TarBz2 => Self::open_tar(format, decode_bzip2(data)?).map(Some),
            _ => Ok(None),
        }
    }

    /// The archive's format.
    #[must_use]
    pub fn format(&self) -> Format {
        self.format
    }

    /// The archive's member list, in archive order.
    #[must_use]
    pub fn entries(&self) -> &[ArchiveEntry] {
        &self.entries
    }

    /// Extract the bytes of the member at `index`, capped at
    /// [`crate::peel::MAX_INFLATED`].
    ///
    /// # Errors
    /// [`ArchiveError::IndexOutOfRange`] for a bad index, [`ArchiveError::Read`]
    /// on a backend/codec failure, or [`ArchiveError::TooLarge`] past the cap.
    pub fn read(&mut self, index: usize) -> Result<Vec<u8>> {
        let count = self.entries.len();
        if index >= count {
            return Err(ArchiveError::IndexOutOfRange { index, count });
        }
        match &self.backend {
            Backend::Tar { bytes } => read_tar_member(bytes, index),
        }
    }

    /// Build a tar [`Archive`] over already-decompressed `bytes`.
    fn open_tar(format: Format, bytes: Vec<u8>) -> Result<Archive> {
        let mut ar = tar::Archive::new(std::io::Cursor::new(&bytes));
        let iter = ar.entries().map_err(|e| ArchiveError::Open {
            format: "tar",
            detail: e.to_string(),
        })?;
        let mut entries = Vec::new();
        for entry in iter {
            let entry = entry.map_err(|e| ArchiveError::Open {
                format: "tar",
                detail: e.to_string(),
            })?;
            let name = entry.path().map_or_else(
                |_| String::from_utf8_lossy(&entry.path_bytes()).into_owned(),
                |p| p.to_string_lossy().into_owned(),
            );
            let header = entry.header();
            let size = header.size().map_err(|e| ArchiveError::Open {
                format: "tar",
                detail: e.to_string(),
            })?;
            entries.push(ArchiveEntry {
                name,
                size,
                is_dir: header.entry_type().is_dir(),
            });
        }
        Ok(Archive {
            format,
            entries,
            backend: Backend::Tar { bytes },
        })
    }
}

/// Stream the `index`-th tar member's bytes, capped and CRC-agnostic (tar has no
/// per-member checksum on the data). Re-parses from the held bytes so no member
/// body is retained after listing.
fn read_tar_member(bytes: &[u8], index: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut ar = tar::Archive::new(std::io::Cursor::new(bytes));
    let mut iter = ar.entries().map_err(|e| ArchiveError::Read {
        format: "tar",
        detail: e.to_string(),
    })?;
    let entry = iter
        .nth(index)
        .ok_or(ArchiveError::IndexOutOfRange {
            index,
            count: index,
        })?
        .map_err(|e| ArchiveError::Read {
            format: "tar",
            detail: e.to_string(),
        })?;
    let mut out = Vec::new();
    let mut limited = entry.take(MAX_INFLATED + 1);
    limited
        .read_to_end(&mut out)
        .map_err(|e| ArchiveError::Read {
            format: "tar",
            detail: e.to_string(),
        })?;
    if out.len() as u64 > MAX_INFLATED {
        return Err(ArchiveError::TooLarge { cap: MAX_INFLATED });
    }
    Ok(out)
}
