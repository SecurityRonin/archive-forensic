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
        offset
            .checked_add(len)
            .filter(|&e| e <= data.len() as u64)
            .ok_or(ArchiveError::Read {
                format: "in-place",
                detail: format!(
                    "member window [{offset}, {offset}+{len}) exceeds the {}-byte source",
                    data.len()
                ),
            })?;
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
        // new() proves start+len <= data.len(), and pos <= len, so start+n never
        // exceeds the buffer; the guard degrades gracefully if that ever breaks.
        let Some(src) = self.data.get(start..start + n) else {
            return Ok(0); // cov:unreachable: window bounds proven in new()
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
    limits: &Limits,
) -> Result<PeelSource> {
    let cap = limits.max_total_inflated;
    match detect(&data)? {
        // A collection, split set, or raw stream is not a single wrapped image.
        AccessPlan::Direct | AccessPlan::Collection { .. } | AccessPlan::SegmentSet { .. } => {
            Ok(PeelSource::NotPacked)
        }

        // A bare gzip/bzip2 wrapper: stream the whole decode once to temp.
        AccessPlan::Wrapper { codec, .. } => {
            let temp = spill_wrapper_to_temp(&data, codec, cap)?;
            Ok(PeelSource::Inner(PeeledSource::Temp(temp)))
        }

        // A single archive member, routed by its most-seekable access.
        AccessPlan::Member {
            format,
            index,
            access,
            ..
        } => match access {
            // Stored/verbatim → a zero-copy window over the original bytes.
            Access::InPlace { offset, len } => {
                let sub = SubRange::new(data, offset, len, cap)?;
                Ok(PeelSource::Inner(PeeledSource::InPlace(sub)))
            }
            // Phase 3: zran → a checkpoint seek-index. Until then a Deflate member
            // is decoded in full to temp, exactly like any other compressed codec.
            Access::Zran | Access::SpillToTemp => {
                let temp = spill_member_to_temp(format, &data, index, cap)?;
                Ok(PeelSource::Inner(PeeledSource::Temp(temp)))
            }
        },
    }
}

/// Stream a bare gzip/bzip2 wrapper's whole decoded stream to a temp file.
fn spill_wrapper_to_temp(data: &[u8], codec: Codec, cap: u64) -> Result<TempBacked> {
    let reader: Box<dyn Read> = match codec {
        Codec::Gzip => Box::new(flate2::read::GzDecoder::new(data)),
        Codec::Bzip2 => Box::new(bzip2_rs::DecoderReader::new(data)),
    };
    spill(|out| copy_capped(reader, out, cap, codec_name(codec)))
}

/// Stream one archive member's decoded bytes to a temp file.
fn spill_member_to_temp(
    format: crate::Format,
    data: &[u8],
    index: usize,
    cap: u64,
) -> Result<TempBacked> {
    // detect() already opened this archive format to build the Member plan, so
    // open_with_format returns Some here; the guard fails loud if that breaks.
    let Some(mut archive) = Archive::open_with_format(format, data)? else {
        // cov:unreachable: Member plan implies an archive format
        return Err(ArchiveError::Open {
            format: "archive",
            detail: "member plan produced for a non-archive format".to_string(),
        });
    };
    spill(|out| archive.stream_member(index, out, cap))
}

/// Create a fresh temp file under [`std::env::temp_dir`], run `write_into` to fill
/// it (capped), then rewind it to the start and return a [`TempBacked`] handle.
/// The temp file is deleted if `write_into` fails (RAII on the local).
fn spill(write_into: impl FnOnce(&mut dyn Write) -> Result<u64>) -> Result<TempBacked> {
    let mut tmp = tempfile::NamedTempFile::new().map_err(|e| ArchiveError::Read {
        format: "temp-spill",
        detail: e.to_string(),
    })?;
    let written = write_into(tmp.as_file_mut())?;
    let file = tmp.as_file_mut();
    file.flush().map_err(|e| ArchiveError::Read {
        format: "temp-spill",
        detail: e.to_string(),
    })?;
    file.seek(SeekFrom::Start(0))
        .map_err(|e| ArchiveError::Read {
            format: "temp-spill",
            detail: e.to_string(),
        })?;
    Ok(TempBacked {
        inner: tmp,
        len: written,
    })
}

/// Copy `reader` into `out` through a bounded buffer, capped at `cap`; fails loud
/// with [`ArchiveError::TooLarge`] past it. Returns the bytes written.
fn copy_capped(
    reader: impl Read,
    out: &mut dyn Write,
    cap: u64,
    format: &'static str,
) -> Result<u64> {
    let mut limited = reader.take(cap + 1);
    let n = io::copy(&mut limited, out).map_err(|e| ArchiveError::Decode {
        format,
        detail: e.to_string(),
    })?;
    if n > cap {
        return Err(ArchiveError::TooLarge { cap });
    }
    Ok(n)
}

/// A short, stable label for a codec (for diagnostics).
fn codec_name(codec: Codec) -> &'static str {
    match codec {
        Codec::Gzip => "gzip",
        Codec::Bzip2 => "bzip2",
    }
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

    /// A deterministic, non-repeating byte pattern of length `n` (so a wrong
    /// offset yields visibly wrong bytes, unlike an all-equal fill).
    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    /// Hand-assemble a single-member ZIP whose one file member `name` holds
    /// `payload` compressed with method 8 (Deflate) at `level`. `Compression::none()`
    /// emits stored (`BTYPE=00`) deflate blocks — the byte-addressable fast path a
    /// forensic `E01`-in-zip uses; a real compression level emits Huffman blocks.
    fn deflate_zip(name: &str, payload: &[u8], level: Compression) -> Vec<u8> {
        use flate2::write::DeflateEncoder;
        let mut enc = DeflateEncoder::new(Vec::new(), level);
        enc.write_all(payload).unwrap();
        let comp = enc.finish().unwrap();
        let mut crc = flate2::Crc::new();
        crc.update(payload);
        let crc = crc.sum();
        let nb = name.as_bytes();
        let (csz, usz, nlen) = (comp.len() as u32, payload.len() as u32, nb.len() as u16);

        let mut z = Vec::new();
        // Local file header.
        z.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        z.extend_from_slice(&20u16.to_le_bytes()); // version needed
        z.extend_from_slice(&0u16.to_le_bytes()); // flags
        z.extend_from_slice(&8u16.to_le_bytes()); // method: deflate
        z.extend_from_slice(&0u16.to_le_bytes()); // mod time
        z.extend_from_slice(&0u16.to_le_bytes()); // mod date
        z.extend_from_slice(&crc.to_le_bytes());
        z.extend_from_slice(&csz.to_le_bytes());
        z.extend_from_slice(&usz.to_le_bytes());
        z.extend_from_slice(&nlen.to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes()); // extra len
        z.extend_from_slice(nb);
        z.extend_from_slice(&comp);
        let cd_offset = z.len() as u32;
        // Central directory file header.
        z.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        z.extend_from_slice(&20u16.to_le_bytes()); // version made by
        z.extend_from_slice(&20u16.to_le_bytes()); // version needed
        z.extend_from_slice(&0u16.to_le_bytes()); // flags
        z.extend_from_slice(&8u16.to_le_bytes()); // method
        z.extend_from_slice(&0u16.to_le_bytes()); // mod time
        z.extend_from_slice(&0u16.to_le_bytes()); // mod date
        z.extend_from_slice(&crc.to_le_bytes());
        z.extend_from_slice(&csz.to_le_bytes());
        z.extend_from_slice(&usz.to_le_bytes());
        z.extend_from_slice(&nlen.to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes()); // extra len
        z.extend_from_slice(&0u16.to_le_bytes()); // comment len
        z.extend_from_slice(&0u16.to_le_bytes()); // disk number start
        z.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        z.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        z.extend_from_slice(&0u32.to_le_bytes()); // local header offset
        z.extend_from_slice(nb);
        let cd_size = z.len() as u32 - cd_offset;
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

    // (Phase 3, a) A Deflate zip member → a Zran-backed seekable handle (NOT a
    // temp spill): random reads at start / a stored-block boundary / the end / a
    // backward re-seek all return the exact decompressed bytes, and a full read
    // reproduces the member. Uses `Compression::none()` so the deflate stream is a
    // run of stored blocks spanning several 64 KiB boundaries — the byte-addressable
    // fast path with no full inflate.
    #[test]
    fn deflate_member_zran_random_access() {
        let payload = pattern(200_000);
        let data = deflate_zip("big.dd", &payload, Compression::none());
        assert!(
            matches!(
                detect(&data).unwrap(),
                AccessPlan::Member {
                    access: Access::Zran,
                    ..
                }
            ),
            "a Deflate member routes to Zran"
        );
        let PeelSource::Inner(PeeledSource::Zran(mut z)) =
            peel_archive_seekable(data, Some("big.dd.zip"), &Limits::default()).unwrap()
        else {
            panic!("expected a Zran-backed peel");
        };
        assert_eq!(z.len(), payload.len() as u64);
        assert!(!z.is_empty());

        // Start.
        z.seek(SeekFrom::Start(0)).unwrap();
        let mut head = vec![0u8; 4096];
        z.read_exact(&mut head).unwrap();
        assert_eq!(head, payload[..4096]);

        // A read straddling a 65 535-byte stored-block boundary.
        let mid = 65_535 - 10;
        z.seek(SeekFrom::Start(mid as u64)).unwrap();
        let mut span = vec![0u8; 5000];
        z.read_exact(&mut span).unwrap();
        assert_eq!(span, payload[mid..mid + 5000]);

        // End-relative.
        z.seek(SeekFrom::End(-100)).unwrap();
        let mut tail = vec![0u8; 100];
        z.read_exact(&mut tail).unwrap();
        assert_eq!(tail, payload[payload.len() - 100..]);

        // Backward re-seek.
        z.seek(SeekFrom::Start(1234)).unwrap();
        let mut back = vec![0u8; 2000];
        z.read_exact(&mut back).unwrap();
        assert_eq!(back, payload[1234..1234 + 2000]);

        // Full read from the start reproduces the member.
        z.seek(SeekFrom::Start(0)).unwrap();
        let mut all = Vec::new();
        z.read_to_end(&mut all).unwrap();
        assert_eq!(all, payload);
    }

    // (Phase 3, a2) A genuinely-compressed Deflate member (Huffman blocks, not
    // stored) is still served by the Zran executor with correct random reads.
    #[test]
    fn genuinely_compressed_deflate_member_zran_reads_correctly() {
        let payload = b"the quick brown fox jumps over the lazy dog\n".repeat(4000);
        let data = deflate_zip("log.txt", &payload, Compression::best());
        let PeelSource::Inner(PeeledSource::Zran(mut z)) =
            peel_archive_seekable(data, Some("log.txt.zip"), &Limits::default()).unwrap()
        else {
            panic!("expected a Zran-backed peel");
        };
        assert_eq!(z.len(), payload.len() as u64);
        let off = payload.len() / 2;
        z.seek(SeekFrom::Start(off as u64)).unwrap();
        let mut got = vec![0u8; 3000];
        z.read_exact(&mut got).unwrap();
        assert_eq!(got, payload[off..off + 3000]);
    }

    // (Phase 3, b/c) The Zran path yields the Zran variant, never a Temp spill of
    // the decompressed member — the member is randomly accessed, never inflated to
    // a temp file.
    #[test]
    fn zran_path_does_not_spill_decompressed_member() {
        let payload = pattern(120_000);
        let data = deflate_zip("img.dd", &payload, Compression::none());
        match peel_archive_seekable(data, Some("img.dd.zip"), &Limits::default()).unwrap() {
            PeelSource::Inner(PeeledSource::Zran(_)) => {}
            other => panic!("expected Zran (no decompressed-member spill), got {other:?}"),
        }
    }

    // (Phase 3, d) The index-size coverage gate: when a zran checkpoint index would
    // exceed `max_index_bytes`, the executor falls back to a temp spill (which still
    // yields the exact member bytes) rather than building an unbounded index.
    #[test]
    fn zran_index_cap_falls_back_to_spill() {
        let payload = pattern(120_000);
        let expected = payload.clone();
        let data = deflate_zip("img.dd", &payload, Compression::none());
        let limits = Limits {
            max_index_bytes: 1,
            ..Limits::default()
        };
        match peel_archive_seekable(data, Some("img.dd.zip"), &limits).unwrap() {
            PeelSource::Inner(PeeledSource::Temp(mut t)) => {
                let mut got = Vec::new();
                t.read_to_end(&mut got).unwrap();
                assert_eq!(
                    got, expected,
                    "spill fallback still yields the member bytes"
                );
            }
            other => panic!("expected a Temp spill fallback, got {other:?}"),
        }
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

    // A bare bzip2 wrapper → SpillToTemp of the whole decompressed stream. Uses
    // the committed payload.bz2 fixture (no in-tree bzip2 encoder) to exercise the
    // bzip2 decoder arm of the wrapper spill.
    #[test]
    fn bare_bzip2_wrapper_spills_to_temp() {
        let expected = "archive-detour bzip2 test payload — the quick brown fox\n"
            .repeat(30)
            .into_bytes();
        match peel_archive_seekable(load("payload.bz2"), Some("payload.bz2"), &Limits::default())
            .unwrap()
        {
            PeelSource::Inner(PeeledSource::Temp(mut t)) => {
                let mut got = Vec::new();
                t.read_to_end(&mut got).unwrap();
                assert_eq!(got, expected);
            }
            other => panic!("expected Temp, got {other:?}"),
        }
    }

    // Full Seek semantics on a SubRange window: End- and Current-relative seeks
    // (both directions), clamping past the window edge, and a loud error on an
    // out-of-range negative seek.
    #[test]
    fn subrange_seek_end_and_current() {
        let data: Vec<u8> = (0u8..50).collect();
        // Window bytes [10, 30) → values 10..30.
        let mut sub = SubRange::new(data, 10, 20, u64::MAX).unwrap();
        assert_eq!(sub.offset(), 10);
        assert!(!sub.is_empty());

        // End-relative.
        assert_eq!(sub.seek(SeekFrom::End(-4)).unwrap(), 16);
        let mut four = [0u8; 4];
        sub.read_exact(&mut four).unwrap();
        assert_eq!(four, [26, 27, 28, 29]);

        // Current-relative, both directions.
        assert_eq!(sub.seek(SeekFrom::Current(-4)).unwrap(), 16);
        sub.seek(SeekFrom::Start(0)).unwrap();
        assert_eq!(sub.seek(SeekFrom::Current(5)).unwrap(), 5);

        // Seeking past the window edge clamps to len.
        assert_eq!(sub.seek(SeekFrom::Start(999)).unwrap(), 20);

        // An out-of-range negative seek fails loud.
        assert!(sub.seek(SeekFrom::Current(-999)).is_err());
    }

    // A window that overruns the source is rejected (a lying member offset/size
    // is never trusted), and a zero-length window reports empty.
    #[test]
    fn subrange_rejects_overrun_and_reports_empty() {
        let overrun = SubRange::new(vec![0u8; 10], 5, 20, u64::MAX);
        assert!(matches!(overrun, Err(ArchiveError::Read { .. })));

        let empty = SubRange::new(vec![0u8; 10], 4, 0, u64::MAX).unwrap();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
    }

    // The public trait-object surface: read and seek through `PeeledSource`
    // itself (and a `Box<dyn ReadSeek>`), not the inner handle — this is how a
    // consumer that erases the backing store uses the peel.
    #[test]
    fn peeled_source_reads_and_seeks_as_trait_object() {
        let data = load("stored_one.zip");
        let expected = member_oracle(&data, "stored_one.zip", "disk.dd");
        let PeelSource::Inner(source) =
            peel_archive_seekable(data, Some("stored_one.zip"), &Limits::default()).unwrap()
        else {
            panic!("expected an Inner source");
        };
        // Drive Read+Seek through the erased handle.
        let mut handle: Box<dyn ReadSeek> = Box::new(source);
        handle.seek(SeekFrom::Start(0)).unwrap();
        let mut got = Vec::new();
        handle.read_to_end(&mut got).unwrap();
        assert_eq!(got, expected);
    }
}
