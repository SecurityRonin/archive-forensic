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

    /// Stream the bytes of member `index` into `out`, capped at `cap`. The member
    /// is copied through a bounded buffer — never fully materialized in a `Vec` —
    /// so a multi-GB inner image spills to the caller's writer (a temp file)
    /// without holding it in RAM. Fails loud with [`ArchiveError::TooLarge`] past
    /// `cap`. Returns the number of bytes written.
    ///
    /// The one exception is a 7z member: `sevenz-rust2` exposes no streaming
    /// extract, so its bytes pass through a transient `Vec` before the write.
    ///
    /// # Errors
    /// [`ArchiveError::IndexOutOfRange`] for a bad index, [`ArchiveError::Read`]
    /// on a backend/codec failure, or [`ArchiveError::TooLarge`] past `cap`.
    pub fn stream_member(
        &mut self,
        index: usize,
        out: &mut dyn std::io::Write,
        cap: u64,
    ) -> Result<u64> {
        let count = self.entries.len();
        if index >= count {
            return Err(ArchiveError::IndexOutOfRange { index, count });
        }
        let (name, declared_size) = {
            let e = &self.entries[index];
            (e.name.clone(), e.size)
        };
        match &mut self.backend {
            Backend::Tar { compressed, outer } => {
                stream_tar_member(compressed, *outer, index, out, cap)
            }
            Backend::Zip { archive } => stream_zip_member(archive, index, out, cap),
            Backend::SevenZip { reader } => {
                let bytes = read_7z_member(reader, &name, declared_size)?;
                if bytes.len() as u64 > cap {
                    return Err(ArchiveError::TooLarge { cap });
                }
                out.write_all(&bytes).map_err(|e| ArchiveError::Read {
                    format: "7z",
                    detail: e.to_string(),
                })?;
                Ok(bytes.len() as u64)
            }
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

/// Copy `reader` into `out` through a bounded buffer, capped at `cap`. Reads one
/// byte past the cap so an over-cap stream is *detected*, not silently truncated;
/// fails loud with [`ArchiveError::TooLarge`]. Returns the bytes written.
fn copy_capped(
    reader: impl std::io::Read,
    out: &mut dyn std::io::Write,
    cap: u64,
    format: &'static str,
) -> Result<u64> {
    let mut limited = reader.take(cap + 1);
    let n = std::io::copy(&mut limited, out).map_err(|e| ArchiveError::Read {
        format,
        detail: e.to_string(),
    })?;
    if n > cap {
        return Err(ArchiveError::TooLarge { cap });
    }
    Ok(n)
}

/// Stream the `index`-th tar member into `out`, capped. Mirrors
/// [`extract_tar_member_streaming`], writing to a sink instead of a `Vec` so the
/// member never lands in RAM whole.
fn stream_tar_member(
    compressed: &[u8],
    outer: Format,
    index: usize,
    out: &mut dyn std::io::Write,
    cap: u64,
) -> Result<u64> {
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
    copy_capped(entry, out, cap, "tar")
}

/// Stream the `index`-th ZIP member into `out`, capped. The fleet reader verifies
/// CRC-32 at EOF and fails loud on mismatch.
fn stream_zip_member(
    archive: &mut zip_core::ZipArchive<std::io::Cursor<Vec<u8>>>,
    index: usize,
    out: &mut dyn std::io::Write,
    cap: u64,
) -> Result<u64> {
    let zf = archive.by_index(index).map_err(|e| ArchiveError::Read {
        format: "zip",
        detail: e.to_string(),
    })?;
    copy_capped(zf, out, cap, "zip")
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

    const FX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/fixtures/");

    fn load(name: &str) -> Vec<u8> {
        std::fs::read(format!("{FX}{name}")).unwrap()
    }

    fn member_index(a: &Archive, name: &str) -> usize {
        a.entries()
            .iter()
            .position(|e| e.name == name && !e.is_dir)
            .unwrap_or_else(|| panic!("member {name} not found"))
    }

    // `stream_member` writes a tar member's bytes to a sink and returns the count,
    // without ever materializing the whole decompressed tar.
    #[test]
    fn stream_member_tar_writes_bytes_and_count() {
        let payload = vec![0xCD_u8; 700];
        let tar = build_tar(&[("only.bin", payload.clone())]);
        let mut a = Archive::open(&tar, Some("x.tar")).unwrap().unwrap();
        let mut sink = Vec::new();
        let n = a.stream_member(0, &mut sink, MAX_INFLATED).unwrap();
        assert_eq!(n, payload.len() as u64);
        assert_eq!(sink, payload);
    }

    // A tar member streamed under a cap smaller than its size fails loud via
    // `copy_capped`'s over-cap guard (never a silent truncation).
    #[test]
    fn stream_member_tar_over_cap_fails_loud() {
        let tar = build_tar(&[("big.bin", vec![0x7E_u8; 1000])]);
        let mut a = Archive::open(&tar, Some("x.tar")).unwrap().unwrap();
        let mut sink = Vec::new();
        match a.stream_member(0, &mut sink, 100) {
            Err(ArchiveError::TooLarge { cap }) => assert_eq!(cap, 100),
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    // A bad index into `stream_member` fails loud before any backend dispatch.
    #[test]
    fn stream_member_out_of_range_fails_loud() {
        let tar = build_tar(&[("only.bin", vec![0x33_u8; 10])]);
        let mut a = Archive::open(&tar, Some("x.tar")).unwrap().unwrap();
        let mut sink = Vec::new();
        assert!(matches!(
            a.stream_member(99, &mut sink, MAX_INFLATED),
            Err(ArchiveError::IndexOutOfRange { .. })
        ));
    }

    // The 7z streaming arm decodes a member and writes it through the transient
    // `Vec` seam (sevenz-rust2 has no streaming extract), returning the count.
    #[test]
    fn stream_member_7z_writes_bytes() {
        let data = load("payload.7z");
        let mut a = Archive::open(&data, Some("payload.7z")).unwrap().unwrap();
        let ia = member_index(&a, "a.txt");
        let mut sink = Vec::new();
        let n = a.stream_member(ia, &mut sink, MAX_INFLATED).unwrap();
        assert_eq!(sink, b"alpha member contents\n");
        assert_eq!(n, sink.len() as u64);
    }

    // A 7z member streamed under a cap smaller than the decoded size fails loud
    // (the decoded-length check on the 7z arm).
    #[test]
    fn stream_member_7z_over_cap_fails_loud() {
        let data = load("payload.7z");
        let mut a = Archive::open(&data, Some("payload.7z")).unwrap().unwrap();
        let ia = member_index(&a, "a.txt");
        let mut sink = Vec::new();
        match a.stream_member(ia, &mut sink, 3) {
            Err(ArchiveError::TooLarge { cap }) => assert_eq!(cap, 3),
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    // A ZIP member streams to the sink byte-for-byte via the fleet reader.
    #[test]
    fn stream_member_zip_writes_bytes() {
        let data = load("payload.zip");
        let mut a = Archive::open(&data, Some("payload.zip")).unwrap().unwrap();
        let ia = member_index(&a, "a.txt");
        let mut sink = Vec::new();
        let n = a.stream_member(ia, &mut sink, MAX_INFLATED).unwrap();
        assert_eq!(sink, b"alpha member contents\n");
        assert_eq!(n, sink.len() as u64);
    }

    // A zip payload behind the `PK\x03\x04` magic that is not a valid archive
    // fails loud with a byte-carrying Open error — never a silent empty listing.
    #[test]
    fn corrupt_zip_open_fails_loud() {
        let mut bytes = b"PK\x03\x04".to_vec();
        bytes.extend_from_slice(&[0u8; 64]);
        match Archive::open(&bytes, Some("x.zip")) {
            Err(ArchiveError::Open { format, .. }) => assert_eq!(format, "zip"),
            Err(e) => panic!("expected a zip Open error, got a different error: {e:?}"),
            Ok(_) => panic!("expected a loud zip Open error, got Ok"),
        }
    }

    // 7z magic followed by garbage fails loud at open (the sevenz-rust2 header
    // parse errors out), not a silent None.
    #[test]
    fn corrupt_7z_open_fails_loud() {
        let mut bytes = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
        bytes.extend_from_slice(&[0u8; 64]);
        match Archive::open(&bytes, Some("x.7z")) {
            Err(ArchiveError::Open { format, .. }) => assert_eq!(format, "7z"),
            Err(e) => panic!("expected a 7z Open error, got a different error: {e:?}"),
            Ok(_) => panic!("expected a loud 7z Open error, got Ok"),
        }
    }

    // `member_access` classifies a Stored zip member as a zero-copy InPlace window
    // and a Deflated member as a Zran seek index (ADR 0008 access ladder).
    #[test]
    fn member_access_classifies_zip_stored_and_deflated() {
        let mut stored = Archive::open(&load("stored_one.zip"), Some("stored_one.zip"))
            .unwrap()
            .unwrap();
        assert!(matches!(
            stored.member_access(0).unwrap(),
            Access::InPlace { .. }
        ));
        let mut deflated = Archive::open(&load("deflate_one.zip"), Some("deflate_one.zip"))
            .unwrap()
            .unwrap();
        assert!(matches!(deflated.member_access(0).unwrap(), Access::Zran));
    }

    /// A single-member STORED zip whose recorded CRC-32 is deliberately wrong, so
    /// the fleet reader's EOF CRC check must reject it on extract.
    fn stored_zip_bad_crc(name: &str, payload: &[u8]) -> Vec<u8> {
        let nb = name.as_bytes();
        let mut crc = flate2::Crc::new();
        crc.update(payload);
        let bad_crc = crc.sum() ^ 0xFFFF_FFFF; // guaranteed != the real CRC
        let (sz, nlen) = (payload.len() as u32, nb.len() as u16);
        let mut z = Vec::new();
        // Local file header (method 0 = stored).
        z.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        z.extend_from_slice(&20u16.to_le_bytes()); // version needed
        z.extend_from_slice(&0u16.to_le_bytes()); // flags
        z.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        z.extend_from_slice(&0u16.to_le_bytes()); // mod time
        z.extend_from_slice(&0u16.to_le_bytes()); // mod date
        z.extend_from_slice(&bad_crc.to_le_bytes());
        z.extend_from_slice(&sz.to_le_bytes()); // compressed size
        z.extend_from_slice(&sz.to_le_bytes()); // uncompressed size
        z.extend_from_slice(&nlen.to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes()); // extra len
        z.extend_from_slice(nb);
        z.extend_from_slice(payload);
        let cd_offset = z.len() as u32;
        // Central directory header.
        let mut central = Vec::new();
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes()); // version made by
        central.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central.extend_from_slice(&0u16.to_le_bytes()); // flags
        central.extend_from_slice(&0u16.to_le_bytes()); // method
        central.extend_from_slice(&0u16.to_le_bytes()); // mod time
        central.extend_from_slice(&0u16.to_le_bytes()); // mod date
        central.extend_from_slice(&bad_crc.to_le_bytes());
        central.extend_from_slice(&sz.to_le_bytes());
        central.extend_from_slice(&sz.to_le_bytes());
        central.extend_from_slice(&nlen.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra len
        central.extend_from_slice(&0u16.to_le_bytes()); // comment len
        central.extend_from_slice(&0u16.to_le_bytes()); // disk number start
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        central.extend_from_slice(&0u32.to_le_bytes()); // local header offset
        central.extend_from_slice(nb);
        let cd_size = central.len() as u32;
        z.extend_from_slice(&central);
        // End of central directory.
        z.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes()); // disk num
        z.extend_from_slice(&0u16.to_le_bytes()); // disk with cd
        z.extend_from_slice(&1u16.to_le_bytes()); // entries this disk
        z.extend_from_slice(&1u16.to_le_bytes()); // total entries
        z.extend_from_slice(&cd_size.to_le_bytes());
        z.extend_from_slice(&cd_offset.to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes()); // comment len
        z
    }

    // A zip member with a wrong CRC-32 opens fine (the directory is intact) but
    // must fail LOUD on extraction — both `read` and `stream_member` reject it via
    // the fleet reader's EOF CRC check, never returning corrupt bytes silently.
    #[test]
    fn zip_member_bad_crc_fails_loud_on_read_and_stream() {
        let data = stored_zip_bad_crc("blob.bin", b"corruption-detected-by-crc");
        let mut a = Archive::open(&data, Some("x.zip")).unwrap().unwrap();
        assert_eq!(a.entries().len(), 1);
        match a.read(0) {
            Err(ArchiveError::Read { format, .. }) => assert_eq!(format, "zip"),
            other => panic!("expected a loud zip Read error on read, got {other:?}"),
        }
        let mut sink = Vec::new();
        match a.stream_member(0, &mut sink, MAX_INFLATED) {
            Err(ArchiveError::Read { format, .. }) => assert_eq!(format, "zip"),
            other => panic!("expected a loud zip Read error on stream, got {other:?}"),
        }
    }
}
