//! `forensic-vfs` integration: the archive layer as an [`ArchiveOpen`] opener.
//!
//! [`ArchiveOpener`] plugs archive-core into the forensic-vfs resolver contract
//! (`forensic-vfs` ADR 0008 — archives resolve as a first-class layer). It owns
//! no new archive logic: [`probe`](ArchiveOpener::probe) delegates format
//! detection to [`crate::sniff`], and [`open`](ArchiveOpener::open) delegates the
//! peel to [`crate::peel_bytes`] (a bare gzip/bzip2 wrapper → one decoded
//! [`ArchiveContents::Stream`], 1→1) and [`crate::Archive`] (a multi-member
//! tar/zip/7z archive → the [`ArchiveContents::Members`] table, 1→N).
//!
//! Detection here is content-authoritative (magic only): the opener never sees a
//! file name, so a bare `.gz`/`.bz2` wrapper is recognized by its `1f 8b`/`BZh`
//! magic and a `.tar.gz` presented nameless resolves as a gzip *stream* whose
//! decoded tar re-enters resolution and matches the `ustar` magic — the layered
//! model, not a special case.
//!
//! Member bytes are extracted into memory (matching archive-core's in-memory
//! [`Archive::read`] / [`crate::peel_bytes`] model, each capped against a
//! decompression bomb). A seekable, temp/zran-backed [`ImageSource`] per member
//! is a future hardening step — see the module TODO on [`ArchiveOpener::open`].

use std::sync::Arc;

use forensic_vfs::registry::{ArchiveOpen, Confidence, SniffWindow};
use forensic_vfs::{
    ArchiveContents, DynSource, ImageSource, Member, SmallHex, VfsError, VfsResult,
};

use crate::archive::Archive;
use crate::detect::{sniff, Format};
use crate::peel::{peel_bytes, PeelOutcome};

/// The archive/compression layer as a forensic-vfs [`ArchiveOpen`] opener. A
/// zero-state delegator over archive-core's own detect + peel — register one in
/// the engine's `Openers` to make archives a transparent resolution layer.
#[derive(Debug, Default, Clone, Copy)]
pub struct ArchiveOpener;

impl ArchiveOpener {
    /// A new opener.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl ArchiveOpen for ArchiveOpener {
    fn probe(&self, w: &SniffWindow) -> Confidence {
        // Name-blind, magic-authoritative: the window carries only bytes.
        let how = match sniff(None, w.bytes()) {
            Format::Unknown => return Confidence::No,
            Format::Gzip => "archive: gzip magic (1f 8b)",
            Format::Bzip2 => "archive: bzip2 magic (BZh)",
            Format::Zip => "archive: zip magic (PK\\x03\\x04)",
            Format::SevenZip => "archive: 7z magic (37 7a bc af 27 1c)",
            Format::Tar => "archive: ustar magic (offset 257)",
            Format::TarGz | Format::TarBz2 => "archive: compressed-tar magic",
        };
        Confidence::Yes { how }
    }

    fn open(&self, src: DynSource) -> VfsResult<ArchiveContents> {
        // archive-core's peel operates over an in-memory byte slice, so read the
        // archive whole — the same model as `Archive::open(&[u8])` / `peel_bytes`.
        // TODO(seam): a seekable Members mapping (per-member SubRange/Zran over
        // the shared archive) would avoid materializing member bytes; archive-core
        // exposes `execute_member_access` only as `pub(crate)` today, so a public
        // "list members as seekable sources" API is the enabling change.
        let data = read_all(&src)?;
        let format = sniff(None, &data);

        if format.is_compression_wrapper() {
            let inner = match peel_bytes(&data, None).map_err(|e| decode_err(&data, &e))? {
                PeelOutcome::Peeled { inner, .. } => inner,
                // cov:unreachable: is_compression_wrapper() guarantees a Peeled outcome
                PeelOutcome::NotPacked => return Err(not_archive(&data)),
            };
            return Ok(ArchiveContents::Stream(bytes_source(inner)));
        }

        if format.is_archive() {
            let mut archive = Archive::open(&data, None)
                .map_err(|e| decode_err(&data, &e))?
                // cov:unreachable: is_archive() guarantees open() returns Some
                .ok_or_else(|| not_archive(&data))?;
            let entries = archive.entries().to_vec();
            let mut members = Vec::with_capacity(entries.len());
            for (i, entry) in entries.iter().enumerate() {
                // A directory has no byte source; only file members re-enter
                // resolution (mirrors `peel_archive`'s !is_dir filter).
                if entry.is_dir {
                    continue;
                }
                let bytes = archive.read(i).map_err(|e| decode_err(&data, &e))?;
                members.push(Member {
                    name: entry.name.as_bytes().to_vec(),
                    source: bytes_source(bytes),
                });
            }
            return Ok(ArchiveContents::Members(members));
        }

        // probe() gates this out; a direct caller that opens a non-archive gets a
        // loud, byte-carrying decode error rather than a silent empty result.
        Err(not_archive(&data))
    }
}

/// Wrap owned bytes as a shared [`DynSource`].
fn bytes_source(bytes: Vec<u8>) -> DynSource {
    Arc::new(BytesSource { bytes })
}

/// Map an [`crate::ArchiveError`] to a byte-carrying [`VfsError::Decode`] (fail
/// loud with the offending head bytes attached — "show the unrecognized value").
fn decode_err(data: &[u8], err: &crate::ArchiveError) -> VfsError {
    VfsError::Decode {
        layer: "archive",
        offset: 0,
        detail: err.to_string(),
        bytes: SmallHex::new(data),
    }
}

/// The loud error for input that reached `open` without being a recognized
/// archive layer (a direct caller that skipped `probe`, or a defensive arm).
fn not_archive(data: &[u8]) -> VfsError {
    VfsError::Decode {
        layer: "archive",
        offset: 0,
        detail: "not a recognized archive layer".to_string(),
        bytes: SmallHex::new(data),
    }
}

/// Read the whole source into a buffer via positioned reads (short-read safe).
fn read_all(src: &DynSource) -> VfsResult<Vec<u8>> {
    let len = src.len();
    let mut buf = vec![0u8; len as usize];
    let mut off = 0u64;
    while off < len {
        let Some(dst) = buf.get_mut(off as usize..) else {
            break; // cov:unreachable: off < len == buf.len(), so the slice is in range
        };
        let n = src.read_at(off, dst)?;
        if n == 0 {
            break;
        }
        off = off.saturating_add(n as u64);
    }
    buf.truncate(off as usize);
    Ok(buf)
}

/// An in-memory [`ImageSource`] over owned bytes: a decoded wrapper stream or a
/// single extracted archive member. Positioned reads only; shared by `Arc`.
struct BytesSource {
    bytes: Vec<u8>,
}

impl ImageSource for BytesSource {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let total = self.bytes.len() as u64;
        if offset >= total {
            return Ok(0);
        }
        let start = offset as usize;
        // start < total == bytes.len(), so the tail slice is always in range.
        let Some(src) = self.bytes.get(start..) else {
            return Ok(0); // cov:unreachable: start < bytes.len() proven above
        };
        let n = src.len().min(buf.len());
        let Some(dst) = buf.get_mut(..n) else {
            return Ok(0); // cov:unreachable: n <= buf.len() by the min above
        };
        // Both slices are exactly `n` bytes.
        dst.copy_from_slice(&src[..n]);
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    const FX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/fixtures/");

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// A two-member uncompressed `ustar` tar (recognized by magic, name-blind).
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

    fn source(bytes: Vec<u8>) -> DynSource {
        bytes_source(bytes)
    }

    /// Drain a `DynSource` to a `Vec` through the adapter's own positioned reads.
    fn drain(src: &DynSource) -> Vec<u8> {
        read_all(src).unwrap()
    }

    #[test]
    fn probe_recognizes_archive_magics_and_rejects_raw() {
        let op = ArchiveOpener::new();
        let gz = gzip(b"payload");
        assert!(op.probe(&SniffWindow::new(0, &gz)).is_yes());
        assert!(op.probe(&SniffWindow::new(0, b"PK\x03\x04rest")).is_yes());
        assert!(op
            .probe(&SniffWindow::new(
                0,
                &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0, 0]
            ))
            .is_yes());
        // Raw bytes are not an archive layer.
        assert_eq!(
            op.probe(&SniffWindow::new(0, b"\x00\x01\x02 not packed")),
            Confidence::No
        );
    }

    // A bare gzip wrapper peels 1→1 to a decoded Stream whose bytes equal the
    // original inner payload.
    #[test]
    fn bare_gzip_opens_as_stream() {
        let inner = b"raw disk sector bytes \x00\x01\x02 the quick brown fox".repeat(40);
        let gz = gzip(&inner);
        match ArchiveOpener::new().open(source(gz)).unwrap() {
            ArchiveContents::Stream(s) => assert_eq!(drain(&s), inner),
            _ => panic!("a bare gzip wrapper is a Stream, not Members"),
        }
    }

    // A multi-member tar (recognized by ustar magic, name-blind) opens to a
    // Members table with one Member per file entry — right count, names, bytes.
    #[test]
    fn multi_member_tar_opens_as_members() {
        let a = b"AAAA member one\n".repeat(5);
        let b = b"BBBB member two contents\n".repeat(7);
        let tar = build_tar(&[("alpha.bin", a.clone()), ("beta.bin", b.clone())]);
        match ArchiveOpener::new().open(source(tar)).unwrap() {
            ArchiveContents::Members(members) => {
                assert_eq!(members.len(), 2, "one Member per file entry");
                assert_eq!(members[0].name, b"alpha.bin");
                assert_eq!(members[1].name, b"beta.bin");
                assert_eq!(drain(&members[0].source), a);
                assert_eq!(drain(&members[1].source), b);
            }
            _ => panic!("a tar is a Members table, not a Stream"),
        }
    }

    // Real-fixture Members: the committed multi-member payload.zip maps to the
    // same member names + bytes the archive-core reader reports (oracle),
    // proving the adapter delegates to Archive faithfully.
    #[test]
    fn committed_zip_members_match_archive_oracle() {
        let data = std::fs::read(format!("{FX}payload.zip")).unwrap();
        let mut oracle = Archive::open(&data, Some("payload.zip")).unwrap().unwrap();
        let expected: Vec<(Vec<u8>, Vec<u8>)> = oracle
            .entries()
            .to_vec()
            .iter()
            .enumerate()
            .filter(|(_, e)| !e.is_dir)
            .map(|(i, e)| (e.name.as_bytes().to_vec(), oracle.read(i).unwrap()))
            .collect();
        assert!(expected.len() > 1, "payload.zip is multi-member");

        match ArchiveOpener::new().open(source(data)).unwrap() {
            ArchiveContents::Members(members) => {
                assert_eq!(members.len(), expected.len());
                for (m, (name, bytes)) in members.iter().zip(expected.iter()) {
                    assert_eq!(&m.name, name);
                    assert_eq!(&drain(&m.source), bytes);
                }
            }
            _ => panic!("payload.zip is multi-member → Members"),
        }
    }

    // A member source honors the positioned-read contract: past-EOF reads yield
    // 0, and a mid-stream offset returns the exact tail bytes.
    #[test]
    fn bytes_source_positioned_read_contract() {
        let s = source((0u8..50).collect());
        assert_eq!(s.len(), 50);
        let mut buf = [0u8; 8];
        let n = s.read_at(45, &mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], &[45, 46, 47, 48, 49]);
        assert_eq!(s.read_at(50, &mut buf).unwrap(), 0);
        assert_eq!(s.read_at(999, &mut buf).unwrap(), 0);
    }

    // open() on non-archive input fails loud with the offending bytes attached,
    // never a silent empty Members table.
    #[test]
    fn open_non_archive_fails_loud() {
        match ArchiveOpener::new().open(source(b"\x00\x01\x02 not an archive".to_vec())) {
            Err(VfsError::Decode { layer, bytes, .. }) => {
                assert_eq!(layer, "archive");
                assert!(!bytes.is_empty(), "offending bytes are attached");
            }
            Err(e) => panic!("expected a Decode error, got a different VfsError: {e}"),
            Ok(_) => panic!("expected a loud Decode error, got Ok"),
        }
    }
}
