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
use crate::peel::MAX_INFLATED;
use crate::plan::Access;

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
    /// The **compressed** archive bytes plus the outer tar format. Members are
    /// listed and extracted by streaming a fresh decompressor over these bytes,
    /// so the whole decompressed tar is never materialized in RAM.
    Tar { compressed: Vec<u8>, outer: Format },
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
    /// [`ArchiveError::Open`] if the archive directory cannot be parsed (a
    /// malformed outer compression layer surfaces here while streaming the tar
    /// listing). The tar family is listed by streaming, so no whole-archive
    /// inflate happens at open; the [`crate::peel::MAX_INFLATED`] cap is enforced
    /// per member in [`read`](Archive::read).
    pub fn open(data: &[u8], name: Option<&str>) -> Result<Option<Archive>> {
        Self::open_with_format(sniff(name, data), data)
    }

    /// Open `data` under an already-determined `format`, bypassing the
    /// name-based [`sniff`] — returns `Ok(None)` when `format` is not an archive.
    /// Phase-1 [`crate::detect`] uses this after classifying the format
    /// content-authoritatively (so a bare-compressed tar peeled to a known
    /// `TarGz`/`TarBz2` opens without a name hint).
    ///
    /// # Errors
    /// Same as [`open`](Archive::open): [`ArchiveError::Open`] if the archive
    /// directory cannot be parsed.
    pub(crate) fn open_with_format(format: Format, data: &[u8]) -> Result<Option<Archive>> {
        match format {
            Format::Tar | Format::TarGz | Format::TarBz2 => {
                Self::open_tar(format, data.to_vec()).map(Some)
            }
            Format::Zip => Self::open_zip(data).map(Some),
            Format::SevenZip => Self::open_7z(data).map(Some),
            _ => Ok(None),
        }
    }

    /// The most-seekable [`Access`] for member `index`, chosen from the member
    /// table without decompressing (ADR 0008, rule 4). A `Stored`/uncompressed
    /// zip member is `InPlace` (zero-copy sub-range); `Deflate`/`Deflate64` is
    /// `Zran`; every other codec — and tar/7z members, which expose no
    /// in-archive offset or use a non-seekable codec — is `SpillToTemp`.
    ///
    /// # Errors
    /// [`ArchiveError::IndexOutOfRange`] for a bad index, or [`ArchiveError::Read`]
    /// if a zip member's local header cannot be read.
    pub fn member_access(&mut self, index: usize) -> Result<Access> {
        let count = self.entries.len();
        if index >= count {
            return Err(ArchiveError::IndexOutOfRange { index, count });
        }
        match &mut self.backend {
            Backend::Zip { archive } => {
                let f = archive.by_index(index).map_err(|e| ArchiveError::Read {
                    format: "zip",
                    // cov:unreachable: open_zip already read this index's header, and
                    // the index is bounds-checked above — a re-read cannot fail.
                    detail: e.to_string(),
                })?;
                Ok(match f.compression() {
                    zip_core::CompressionMethod::Stored => Access::InPlace {
                        offset: f.data_start(),
                        len: f.compressed_size(),
                    },
                    zip_core::CompressionMethod::Deflated
                    | zip_core::CompressionMethod::Deflate64 => Access::Zran,
                    _ => Access::SpillToTemp,
                })
            }
            // The tar reader exposes no in-archive member offset, and 7z members
            // are non-seekable codecs (LZMA/LZMA2) — both spill to temp.
            Backend::Tar { .. } | Backend::SevenZip { .. } => Ok(Access::SpillToTemp),
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
            Backend::Tar { compressed, outer } => {
                extract_tar_member_streaming(compressed, *outer, index, MAX_INFLATED)
            }
            Backend::Zip { archive } => read_zip_member(archive, index),
            Backend::SevenZip { reader } => read_7z_member(reader, &name, declared_size),
        }
    }

    /// Build a tar [`Archive`] over the still-**compressed** `compressed` bytes,
    /// listing members by streaming a fresh decompressor. The `tar` crate skips
    /// each member's body *through* the decompressor, so no member data is
    /// buffered while listing.
    fn open_tar(outer: Format, compressed: Vec<u8>) -> Result<Archive> {
        let entries = {
            let mut ar = tar::Archive::new(tar_stream(&compressed, outer));
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
            entries
        };
        Ok(Archive {
            format: outer,
            entries,
            backend: Backend::Tar { compressed, outer },
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

/// A fresh streaming `Read` over the compressed archive bytes for the given
/// outer tar format. Each call re-wraps `compressed` from the start, so the
/// decompressor holds only a bounded window — never the whole decompressed tar.
fn tar_stream(compressed: &[u8], outer: Format) -> Box<dyn std::io::Read + '_> {
    let cursor = std::io::Cursor::new(compressed);
    match outer {
        Format::TarGz => Box::new(flate2::read::GzDecoder::new(cursor)),
        Format::TarBz2 => Box::new(bzip2_rs::DecoderReader::new(cursor)),
        // Plain `Format::Tar` (and, defensively, any non-tar caller) reads the
        // bytes straight through with no decompression layer.
        _ => Box::new(cursor),
    }
}

/// Stream the `index`-th tar member's bytes over a fresh decompressor, capped at
/// `cap`. The `tar` crate skips prior members' bodies *through* the stream, so
/// only this one member is ever read into memory — the whole decompressed tar is
/// never materialized. Fails loud with [`ArchiveError::TooLarge`] past `cap`.
/// CRC-agnostic (tar has no per-member data checksum).
fn extract_tar_member_streaming(
    compressed: &[u8],
    outer: Format,
    index: usize,
    cap: u64,
) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut ar = tar::Archive::new(tar_stream(compressed, outer));
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
    let mut limited = entry.take(cap + 1);
    limited
        .read_to_end(&mut out)
        .map_err(|e| ArchiveError::Read {
            format: "tar",
            detail: e.to_string(),
        })?;
    if out.len() as u64 > cap {
        return Err(ArchiveError::TooLarge { cap });
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Build an uncompressed `ustar` archive from `(name, bytes)` members.
    fn build_tar(members: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (name, data) in members {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, name, data.as_slice()).unwrap();
        }
        b.into_inner().unwrap()
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    // The load-bearing streaming property: `cap = 1200` is LESS than the combined
    // decompressed tar (two members × 512-byte header + 1024-byte padded data,
    // plus 1024 bytes of end blocks ≈ 3584 bytes) but MORE than either single
    // member (1000 bytes). A whole-tar materialization under this cap would
    // exceed it and fail `TooLarge`; the streaming per-member extract must
    // succeed because the whole decompressed tar is never held at once.
    #[test]
    fn streaming_targz_extracts_each_member_under_whole_tar_cap() {
        let a = vec![0xAA_u8; 1000];
        let b = vec![0xBB_u8; 1000];
        let tar = build_tar(&[("a.bin", a.clone()), ("b.bin", b.clone())]);
        assert!(
            tar.len() as u64 > 1200,
            "combined tar ({}) must exceed the per-member cap",
            tar.len()
        );
        let targz = gzip(&tar);
        assert_eq!(
            extract_tar_member_streaming(&targz, Format::TarGz, 0, 1200).unwrap(),
            a
        );
        assert_eq!(
            extract_tar_member_streaming(&targz, Format::TarGz, 1, 1200).unwrap(),
            b
        );
    }

    #[test]
    fn streaming_plain_tar_extracts_member() {
        let a = vec![0x11_u8; 800];
        let b = vec![0x22_u8; 800];
        let tar = build_tar(&[("a.bin", a.clone()), ("b.bin", b.clone())]);
        assert_eq!(
            extract_tar_member_streaming(&tar, Format::Tar, 0, MAX_INFLATED).unwrap(),
            a
        );
        assert_eq!(
            extract_tar_member_streaming(&tar, Format::Tar, 1, MAX_INFLATED).unwrap(),
            b
        );
    }

    #[test]
    fn streaming_member_over_cap_fails_loud() {
        let targz = gzip(&build_tar(&[("a.bin", vec![0xAA_u8; 1000])]));
        match extract_tar_member_streaming(&targz, Format::TarGz, 0, 500) {
            Err(ArchiveError::TooLarge { cap }) => assert_eq!(cap, 500),
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn streaming_bad_index_fails_loud() {
        let tar = build_tar(&[("only.bin", vec![0x33_u8; 10])]);
        assert!(matches!(
            extract_tar_member_streaming(&tar, Format::Tar, 99, MAX_INFLATED),
            Err(ArchiveError::IndexOutOfRange { .. })
        ));
    }

    // bzip2 uses the identical streaming code path; drive it through the public
    // `Archive` so the `TarBz2` arm is exercised in both `open_tar` (listing) and
    // `read` (extraction).
    const PAYLOAD_TBZ2: &[u8] = include_bytes!("../../tests/data/fixtures/payload.tbz2");

    #[test]
    fn member_access_out_of_range_fails_loud() {
        let mut a = Archive::open(PAYLOAD_TBZ2, Some("payload.tbz2"))
            .unwrap()
            .unwrap();
        assert!(matches!(
            a.member_access(9999),
            Err(ArchiveError::IndexOutOfRange { .. })
        ));
    }

    #[test]
    fn streaming_tbz2_reads_member_via_same_path() {
        let mut a = Archive::open(PAYLOAD_TBZ2, Some("payload.tbz2"))
            .unwrap()
            .unwrap();
        assert_eq!(a.format(), Format::TarBz2);
        let ia = a
            .entries()
            .iter()
            .position(|e| e.name == "a.txt" && !e.is_dir)
            .unwrap();
        assert_eq!(a.read(ia).unwrap(), b"alpha member contents\n");
    }
}
