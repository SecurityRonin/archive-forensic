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
// The 7z `ArchiveReader` is larger than the tar/zip variants, but exactly one
// `Backend` exists per `Archive` and they are never held in a collection, so the
// per-value size gap the lint guards against is immaterial here.
#[allow(clippy::large_enum_variant)]
enum Backend {
    /// The decompressed tar byte stream; members are walked on demand.
    Tar { bytes: Vec<u8> },
    /// The fleet ZIP reader over the archive bytes.
    Zip {
        archive: zip_core::ZipArchive<std::io::Cursor<Vec<u8>>>,
    },
    /// The `sevenz-rust2` reader over the archive bytes.
    SevenZip {
        reader: sevenz_rust2::ArchiveReader<std::io::Cursor<Vec<u8>>>,
    },
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
            Format::Zip => Self::open_zip(data).map(Some),
            Format::SevenZip => Self::open_7z(data).map(Some),
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
        // 7z extracts by name; capture it (and the declared size for the
        // pre-alloc cap) before borrowing the backend mutably.
        let (name, declared_size) = {
            let e = &self.entries[index];
            (e.name.clone(), e.size)
        };
        match &mut self.backend {
            Backend::Tar { bytes } => read_tar_member(bytes, index),
            Backend::Zip { archive } => read_zip_member(archive, index),
            Backend::SevenZip { reader } => read_7z_member(reader, &name, declared_size),
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

    /// Build a ZIP [`Archive`] via the fleet `zip-forensic-core` reader.
    fn open_zip(data: &[u8]) -> Result<Archive> {
        let mut archive =
            zip_core::ZipArchive::new(std::io::Cursor::new(data.to_vec())).map_err(|e| {
                ArchiveError::Open {
                    format: "zip",
                    detail: e.to_string(),
                }
            })?;
        let count = archive.len();
        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            let f = archive.by_index(i).map_err(|e| ArchiveError::Open {
                format: "zip",
                detail: e.to_string(),
            })?;
            entries.push(ArchiveEntry {
                name: f.name().to_string(),
                size: f.size(),
                is_dir: f.is_dir(),
            });
        }
        Ok(Archive {
            format: Format::Zip,
            entries,
            backend: Backend::Zip { archive },
        })
    }

    /// Build a 7z [`Archive`] via `sevenz-rust2`.
    fn open_7z(data: &[u8]) -> Result<Archive> {
        let reader = sevenz_rust2::ArchiveReader::new(
            std::io::Cursor::new(data.to_vec()),
            sevenz_rust2::Password::empty(),
        )
        .map_err(|e| ArchiveError::Open {
            format: "7z",
            detail: e.to_string(),
        })?;
        let entries = reader
            .archive()
            .files
            .iter()
            .map(|f| ArchiveEntry {
                name: f.name.clone(),
                size: f.size,
                is_dir: f.is_directory,
            })
            .collect();
        Ok(Archive {
            format: Format::SevenZip,
            entries,
            backend: Backend::SevenZip { reader },
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

/// Extract the `index`-th ZIP member, capped. The fleet reader verifies CRC-32
/// at EOF and fails loud on mismatch.
fn read_zip_member(
    archive: &mut zip_core::ZipArchive<std::io::Cursor<Vec<u8>>>,
    index: usize,
) -> Result<Vec<u8>> {
    use std::io::Read;
    let zf = archive.by_index(index).map_err(|e| ArchiveError::Read {
        format: "zip",
        detail: e.to_string(),
    })?;
    let mut out = Vec::new();
    let mut limited = zf.take(MAX_INFLATED + 1);
    limited
        .read_to_end(&mut out)
        .map_err(|e| ArchiveError::Read {
            format: "zip",
            detail: e.to_string(),
        })?;
    if out.len() as u64 > MAX_INFLATED {
        return Err(ArchiveError::TooLarge { cap: MAX_INFLATED });
    }
    Ok(out)
}

/// Extract a 7z member by name. `sevenz-rust2` decodes the whole member; an
/// unsupported-codec member surfaces as a loud [`ArchiveError::Read`] carrying
/// the backend's diagnostic (never a silent skip). The declared size is checked
/// against the cap before decoding, and the output length after.
fn read_7z_member(
    reader: &mut sevenz_rust2::ArchiveReader<std::io::Cursor<Vec<u8>>>,
    name: &str,
    declared_size: u64,
) -> Result<Vec<u8>> {
    if declared_size > MAX_INFLATED {
        return Err(ArchiveError::TooLarge { cap: MAX_INFLATED });
    }
    let out = reader.read_file(name).map_err(|e| ArchiveError::Read {
        format: "7z",
        detail: e.to_string(),
    })?;
    if out.len() as u64 > MAX_INFLATED {
        return Err(ArchiveError::TooLarge { cap: MAX_INFLATED });
    }
    Ok(out)
}
