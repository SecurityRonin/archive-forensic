//! Phase 2 of two-phase archive access (ADR 0008): the **peel executors** behind
//! an [`AccessPlan`]. Where [`crate::plan::detect`] classifies the most-direct
//! route without touching a payload, [`peel_archive_seekable`] *executes* that
//! route and hands back the inner evidence as a **seekable handle** — never a
//! whole-image `Vec<u8>`:
//!
//! - [`Access::InPlace`] (a Stored zip member / verbatim window) → a zero-copy
//!   [`SubRange`] over the original bytes: no decompression, no member copy.
//! - [`Access::SpillToTemp`] (a compressed member or a bare gzip/bzip2 wrapper) →
//!   a single streamed decode to a temp file under [`std::env::temp_dir`],
//!   returned as a [`TempBacked`] handle that RAII-deletes on drop.
//! - [`Access::Zran`] → treated as [`Access::SpillToTemp`] for now (full decode
//!   to temp). The checkpoint seek-index is Phase 3.
//!
//! Every extraction is capped at `limits.max_total_inflated` and fails loud with
//! [`ArchiveError::TooLarge`] past it — a decompression bomb never silently
//! fills RAM or the temp volume.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::archive::Archive;
use crate::error::{ArchiveError, Result};
use crate::plan::{detect, Access, AccessPlan, Codec};
use crate::resolve::Limits;

/// A seekable byte source: the common capability every peeled handle exposes so
/// a consumer can take a `Box<dyn ReadSeek>` without knowing the backing store.
pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}

/// A zero-copy, seekable window `[offset, offset + len)` over an owned byte
/// buffer. Reading never decompresses and never copies the member into a second
/// buffer — the bytes come straight from the original archive image.
#[derive(Debug)]
pub struct SubRange {
    data: Vec<u8>,
    start: u64,
    len: u64,
    pos: u64,
}

impl SubRange {
    /// Window `data` to `[offset, offset + len)`.
    ///
    /// # Errors
    /// [`ArchiveError::TooLarge`] when `len` exceeds `cap`, or
    /// [`ArchiveError::Read`] when the window falls outside `data` (a lying
    /// member offset/size — never trusted).
    fn new(data: Vec<u8>, offset: u64, len: u64, cap: u64) -> Result<Self> {
        if len > cap {
            return Err(ArchiveError::TooLarge { cap });
        }
        let end = offset
            .checked_add(len)
            .filter(|&e| e <= data.len() as u64)
            .ok_or(ArchiveError::Read {
                format: "in-place",
                detail: format!(
                    "member window [{offset}, {offset}+{len}) exceeds the {}-byte source",
                    data.len()
                ),
            })?;
        let _ = end;
        Ok(SubRange {
            data,
            start: offset,
            len,
            pos: 0,
        })
    }

    /// The window's absolute start offset in the original bytes.
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.start
    }

    /// The window length in bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the window is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Read for SubRange {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.len - self.pos;
        if remaining == 0 || buf.is_empty() {
            return Ok(0);
        }
        let n = remaining.min(buf.len() as u64) as usize;
        let start = self.start.saturating_add(self.pos) as usize;
        let src = match self.data.get(start..start + n) {
            Some(s) => s,
            // cov:unreachable: new() proves start+len <= data.len(), and pos <= len,
            // so start+n never exceeds the buffer.
            None => return Ok(0),
        };
        buf[..n].copy_from_slice(src);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for SubRange {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let target = match from {
            SeekFrom::Start(o) => o,
            SeekFrom::End(o) => offset_from(self.len, o)?,
            SeekFrom::Current(o) => offset_from(self.pos, o)?,
        };
        // A window is bounded: clamp to `len` so reads stop at the window edge.
        self.pos = target.min(self.len);
        Ok(self.pos)
    }
}

/// A seekable handle over a temp file holding a once-decoded stream. The temp
/// file lives under [`std::env::temp_dir`] and is deleted when this value drops.
#[derive(Debug)]
pub struct TempBacked {
    inner: tempfile::NamedTempFile,
    len: u64,
}

impl TempBacked {
    /// The decoded length spilled to the temp file, in bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the spilled stream is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The temp file's path (valid until this handle drops, which deletes it).
    #[must_use]
    pub fn path(&self) -> &Path {
        self.inner.path()
    }
}

impl Read for TempBacked {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.as_file_mut().read(buf)
    }
}

impl Seek for TempBacked {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.inner.as_file_mut().seek(from)
    }
}

/// The peeled inner evidence as a seekable handle: either a zero-copy in-place
/// window or a temp-backed decode. Both implement [`Read`] + [`Seek`].
#[derive(Debug)]
#[non_exhaustive]
pub enum PeeledSource {
    /// A zero-copy window over the original bytes (no decompression).
    InPlace(SubRange),
    /// A once-decoded stream spilled to a temp file (RAII-deleted on drop).
    Temp(TempBacked),
}

impl Read for PeeledSource {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            PeeledSource::InPlace(s) => s.read(buf),
            PeeledSource::Temp(t) => t.read(buf),
        }
    }
}

impl Seek for PeeledSource {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        match self {
            PeeledSource::InPlace(s) => s.seek(from),
            PeeledSource::Temp(t) => t.seek(from),
        }
    }
}

/// The outcome of the seekable peel executor — the streaming twin of
/// [`crate::Peel`].
#[derive(Debug)]
#[non_exhaustive]
pub enum PeelSource {
    /// Not a wrapped/single-member image (a collection, split set, or raw
    /// stream) — open the source directly.
    NotPacked,
    /// One peeled bare-wrapper stream, or the single extracted archive member,
    /// as a seekable handle.
    Inner(PeeledSource),
}

/// Peel a bare gz/bz2 wrapper, OR extract the single member of a one-member
/// archive, to a **seekable handle** — streaming to a temp file when a decode is
/// needed, or a zero-copy window when the member is stored verbatim. Multi-member
/// archives (a collection) and split sets return [`PeelSource::NotPacked`], as
/// does anything unrecognized.
///
/// Classification is content-authoritative via [`crate::plan::detect`]; the
/// coincidental-magic guard (valid magic that does not decode) is handled there.
///
/// # Errors
/// A decode/open/read failure from the underlying layer, or
/// [`ArchiveError::TooLarge`] when the extracted output exceeds
/// `limits.max_total_inflated`.
pub fn peel_archive_seekable(
    data: Vec<u8>,
    _name: Option<&str>,
    _limits: &Limits,
) -> Result<PeelSource> {
    // RED stub — the executor is not wired yet; see the GREEN implementation.
    let _ = detect(&data)?;
    Ok(PeelSource::NotPacked)
}

/// Add a signed offset to a base position, failing on under/overflow.
fn offset_from(base: u64, off: i64) -> io::Result<u64> {
    let r = if off >= 0 {
        base.checked_add(off as u64)
    } else {
        base.checked_sub(off.unsigned_abs())
    };
    r.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek position out of range"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::AccessPlan;
    use flate2::write::GzEncoder;
    use flate2::Compression;

    const FX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/fixtures/");

    fn load(name: &str) -> Vec<u8> {
        std::fs::read(format!("{FX}{name}")).unwrap()
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// The oracle bytes of the single file member of `archive`.
    fn member_oracle(data: &[u8], name: &str, member: &str) -> Vec<u8> {
        let mut a = Archive::open(data, Some(name)).unwrap().unwrap();
        let idx = a
            .entries()
            .iter()
            .position(|e| e.name == member && !e.is_dir)
            .unwrap();
        a.read(idx).unwrap()
    }

    // (a) A Stored zip member → a zero-copy InPlace sub-range: the handle reads
    // the exact member bytes straight from the original image (no decompression,
    // no copy), and its window matches the plan's [offset, len).
    #[test]
    fn stored_member_is_inplace_zero_copy() {
        let data = load("stored_one.zip");
        let AccessPlan::Member {
            access: Access::InPlace { offset, len },
            ..
        } = detect(&data).unwrap()
        else {
            panic!("expected an InPlace Member plan");
        };
        let expected = member_oracle(&data, "stored_one.zip", "disk.dd");

        match peel_archive_seekable(data.clone(), Some("stored_one.zip"), &Limits::default())
            .unwrap()
        {
            PeelSource::Inner(PeeledSource::InPlace(mut sub)) => {
                assert_eq!(sub.offset(), offset, "window offset matches the plan");
                assert_eq!(sub.len(), len, "window len matches the plan");
                let mut got = Vec::new();
                sub.read_to_end(&mut got).unwrap();
                assert_eq!(got, expected, "reads the exact member bytes");
                // Zero-copy proof: the window is literally the original bytes at
                // [offset, offset+len) — no decompression happened.
                let s = offset as usize;
                let e = (offset + len) as usize;
                assert_eq!(got.as_slice(), &data[s..e]);
                // Seekable within the window.
                sub.seek(SeekFrom::Start(10)).unwrap();
                let mut three = [0u8; 3];
                sub.read_exact(&mut three).unwrap();
                assert_eq!(&three[..], &data[s + 10..s + 13]);
            }
            other => panic!("expected InPlace, got {other:?}"),
        }
    }

    // (b1) A Deflate zip member → SpillToTemp: a temp-backed handle whose full
    // read equals the decompressed member, and whose temp file is removed on drop.
    #[test]
    fn deflate_member_spills_to_temp_and_cleans_up() {
        let data = load("deflate_one.zip");
        let expected = member_oracle(&data, "deflate_one.zip", "big.dd");

        let leftover;
        match peel_archive_seekable(data, Some("deflate_one.zip"), &Limits::default()).unwrap() {
            PeelSource::Inner(PeeledSource::Temp(mut t)) => {
                let mut got = Vec::new();
                t.read_to_end(&mut got).unwrap();
                assert_eq!(got, expected, "temp holds the decompressed member");
                let p = t.path().to_path_buf();
                assert!(p.exists(), "temp file exists while the handle is live");
                leftover = p;
                drop(t);
            }
            other => panic!("expected Temp, got {other:?}"),
        }
        assert!(!leftover.exists(), "temp file removed on drop");
    }

    // (b2) A bare gzip wrapper → SpillToTemp of the whole decompressed stream,
    // and the handle is seekable.
    #[test]
    fn bare_gzip_wrapper_spills_full_stream_to_temp() {
        let inner = b"raw disk sector bytes, not an archive at all ".repeat(50);
        let gz = gzip(&inner);
        match peel_archive_seekable(gz, Some("disk.dd.gz"), &Limits::default()).unwrap() {
            PeelSource::Inner(PeeledSource::Temp(mut t)) => {
                assert_eq!(t.len(), inner.len() as u64);
                assert!(!t.is_empty());
                let mut got = Vec::new();
                t.read_to_end(&mut got).unwrap();
                assert_eq!(got, inner);
                // Seekable: jump back into the middle and read.
                t.seek(SeekFrom::Start(5)).unwrap();
                let mut chunk = [0u8; 4];
                t.read_exact(&mut chunk).unwrap();
                assert_eq!(&chunk[..], &inner[5..9]);
            }
            other => panic!("expected Temp, got {other:?}"),
        }
    }

    // (c1) An over-cap decompression fails loud (bomb guard) on the spill path.
    #[test]
    fn over_cap_spill_fails_loud() {
        let gz = gzip(&vec![0xAB_u8; 10_000]);
        let limits = Limits {
            max_total_inflated: 500,
            ..Limits::default()
        };
        match peel_archive_seekable(gz, Some("x.gz"), &limits) {
            Err(ArchiveError::TooLarge { cap }) => assert_eq!(cap, 500),
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    // (c2) An over-cap in-place window fails loud before yielding a handle.
    #[test]
    fn over_cap_inplace_fails_loud() {
        let data = load("stored_one.zip"); // 4096-byte stored member
        let limits = Limits {
            max_total_inflated: 100,
            ..Limits::default()
        };
        match peel_archive_seekable(data, Some("stored_one.zip"), &limits) {
            Err(ArchiveError::TooLarge { cap }) => assert_eq!(cap, 100),
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    // Raw bytes are not packed → open directly.
    #[test]
    fn raw_bytes_are_not_packed() {
        match peel_archive_seekable(
            b"\x00\x01\x02 not packed".to_vec(),
            Some("x.raw"),
            &Limits::default(),
        )
        .unwrap()
        {
            PeelSource::NotPacked => {}
            other => panic!("expected NotPacked, got {other:?}"),
        }
    }

    // A multi-member archive is a collection, not a wrapped image → NotPacked.
    #[test]
    fn multi_member_zip_is_not_packed() {
        let data = load("payload.zip");
        assert!(matches!(
            peel_archive_seekable(data, Some("payload.zip"), &Limits::default()).unwrap(),
            PeelSource::NotPacked
        ));
    }

    // A split segment set is one logical image the caller reassembles → NotPacked.
    #[test]
    fn segment_set_is_not_packed() {
        let data = load("seg_ewf.zip");
        assert!(matches!(
            peel_archive_seekable(data, Some("seg_ewf.zip"), &Limits::default()).unwrap(),
            PeelSource::NotPacked
        ));
    }

    // A compressed-tar single member → SpillToTemp (tar exposes no in-archive
    // offset), reading the decompressed member.
    #[test]
    fn targz_single_member_spills_to_temp() {
        let mut b = tar::Builder::new(Vec::new());
        let payload = b"RAW-IMAGE-BYTES-in-a-tar".repeat(10);
        let mut h = tar::Header::new_gnu();
        h.set_size(payload.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, "disk.img", payload.as_slice())
            .unwrap();
        let tar = b.into_inner().unwrap();
        let gz = gzip(&tar);
        match peel_archive_seekable(gz, Some("disk.tgz"), &Limits::default()).unwrap() {
            PeelSource::Inner(PeeledSource::Temp(mut t)) => {
                let mut got = Vec::new();
                t.read_to_end(&mut got).unwrap();
                assert_eq!(got, payload);
            }
            other => panic!("expected Temp, got {other:?}"),
        }
    }
}
