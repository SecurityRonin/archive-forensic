//! Phase 4 of two-phase archive access (ADR 0008): **`SegmentSet` reassembly**.
//! A multi-segment image split across archive members (`.E01/.E02/.E03`, split
//! raw `.001/.002`, split VMDK `-s001/-s002`) is presented as ONE logical
//! seekable source, built from the per-segment [`PeeledSource`] handles the
//! phase-2/3 executor produces for each member's own [`crate::Access`].
//!
//! Two reassembly regimes, chosen by [`crate::SegmentKind`]:
//!
//! - [`SegmentKind::SplitRaw`] (`.001/.002/.003`, a raw dd split) — the segments
//!   ARE a byte-for-byte concatenation, so [`ConcatSource`] stitches the ordered
//!   per-segment handles into one `Read + Seek`: logical offset `O` maps to
//!   `(segment k, local offset)`, and `seek`/`read` dispatch to the owning
//!   segment. Fully reassembled in archive-core.
//! - [`SegmentKind::Ewf`] / [`SegmentKind::SplitVmdk`] — the segments are NOT a
//!   raw concatenation: each `.E0N` carries its own EWF header/section structure,
//!   and split-VMDK extents are described by the descriptor. Stitching needs the
//!   container reader's multi-segment logic, so archive-core's job here is to hand
//!   back the **ordered per-segment byte sources** via [`segment_sources`]; the
//!   container reader consumes them through its own segment backing.
//!
//! ## The EWF `SegmentBacking` seam
//!
//! The `ewf` crate accepts explicit segment backings through
//! `EwfReader::open_from_sources(Vec<ewf::SegmentSource>)`. `ewf::SegmentSource`
//! has four variants: `File` (a loose segment file), `Sub` (a `[base, base+len)`
//! sub-range of a shared **on-disk** `File`), `Mem` (an in-RAM `Arc<[u8]>`), and
//! `Backing(Arc<dyn SegmentBacking>)` — an arbitrary boxed positioned reader
//! (`read_at` + `len`). archive-core's [`PeeledSource`]s are in-RAM
//! `Read + Seek` handles (a zero-copy [`SubRange`](crate::SubRange) window, a
//! zran checkpoint index, or a temp spill) — not `File`s — but they need not be
//! flattened to an `Arc<[u8]>`: a `PeeledSource` wrapped in a `SegmentBacking`
//! impl feeds `ewf::SegmentSource::Backing` directly, preserving the zero-spill
//! zran path for a Deflate-compressed E01-in-zip set (no full inflate, no `Mem`
//! materialization).
//!
//! No `ewf`-side change is required — the `Backing` variant already ships. Per
//! the phase plan archive-core STOPS at exposing the ordered [`PeeledSource`]s
//! here; the adapter that wraps one in `ewf::SegmentSource::Backing` lives in the
//! consumer (disk-forensic / forensic-vfs-engine), never inside this leaf (which
//! would invert the layer direction — the archive layer must not depend on a
//! CONTAINER crate).

use std::io::{self, Read, Seek, SeekFrom};
use std::sync::Arc;

use crate::detect::Format;
use crate::error::Result;
use crate::execute::{execute_member_access, offset_from, PeeledSource};
use crate::plan::{detect, AccessPlan, SegmentKind};
use crate::resolve::Limits;

/// The ordered per-segment byte sources of a segmented image, each materialized
/// via its own [`crate::Access`] (phase-2/3 executor) and ordered by segment
/// number. For [`SegmentKind::SplitRaw`] these concatenate ([`ConcatSource`]);
/// for [`SegmentKind::Ewf`] / [`SegmentKind::SplitVmdk`] they feed a container
/// reader's multi-segment backing (the `SegmentBacking` seam above).
#[derive(Debug)]
#[non_exhaustive]
pub struct SegmentSources {
    /// The archive format the segments live in.
    pub format: Format,
    /// How the segments reassemble.
    pub kind: SegmentKind,
    /// The per-segment seekable handles, ordered by segment number.
    pub sources: Vec<PeeledSource>,
}

/// One logical, seekable image reassembled by **concatenating** the ordered
/// per-segment handles of a raw split set (`.001/.002/.003`). A logical offset
/// maps to `(segment, local offset)`; a single `read` never crosses a segment
/// boundary (the caller's `read_exact` loops across it), and `seek` is
/// bounded — a position past the end clamps to the total length.
#[derive(Debug)]
pub struct ConcatSource {
    segs: Vec<ConcatSeg>,
    total: u64,
    pos: u64,
}

/// One segment inside a [`ConcatSource`]: its handle plus its logical window.
#[derive(Debug)]
struct ConcatSeg {
    source: PeeledSource,
    /// Logical start offset of this segment in the reassembled image.
    start: u64,
    /// Length of this segment in bytes.
    len: u64,
}

impl ConcatSource {
    /// Stitch `sources` (ordered by segment number) into one logical image, each
    /// segment placed at its running logical offset.
    pub(crate) fn new(sources: Vec<PeeledSource>) -> Self {
        let mut segs = Vec::with_capacity(sources.len());
        let mut start = 0u64;
        for source in sources {
            let len = source.len();
            segs.push(ConcatSeg { source, start, len });
            start = start.saturating_add(len);
        }
        ConcatSource {
            segs,
            total: start,
            pos: 0,
        }
    }

    /// The reassembled image's total length, in bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.total
    }

    /// Whether the reassembled image is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// Index of the segment containing logical `pos`, or `None` at/after the end.
    /// Contiguous, ordered segments make this the first segment whose end exceeds
    /// `pos` — a zero-length segment (`start == end`) is never selected.
    fn seg_at(&self, pos: u64) -> Option<usize> {
        let idx = self.segs.partition_point(|s| s.start + s.len <= pos);
        (idx < self.segs.len()).then_some(idx)
    }
}

impl Read for ConcatSource {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.pos >= self.total {
            return Ok(0);
        }
        let pos = self.pos;
        let Some(i) = self.seg_at(pos) else {
            return Ok(0); // cov:unreachable: pos < total ⇒ a segment contains it
        };
        let seg = &mut self.segs[i];
        let local = pos - seg.start;
        seg.source.seek(SeekFrom::Start(local))?;
        // Cap the read at this segment's boundary so one `read` never crosses
        // into the next segment; a caller's `read_exact` loops across it.
        let avail = seg.len - local;
        let want = (buf.len() as u64).min(avail) as usize;
        let n = seg.source.read(&mut buf[..want])?;
        self.pos = self.pos.saturating_add(n as u64);
        Ok(n)
    }
}

impl Seek for ConcatSource {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let target = match from {
            SeekFrom::Start(o) => o,
            SeekFrom::End(o) => offset_from(self.total, o)?,
            SeekFrom::Current(o) => offset_from(self.pos, o)?,
        };
        // A reassembled image is bounded: clamp so reads stop at its end.
        self.pos = target.min(self.total);
        Ok(self.pos)
    }
}

/// The outcome of reassembling a segmented image (or the finding that the input
/// is not a segment set).
#[derive(Debug)]
#[non_exhaustive]
pub enum Reassembled {
    /// A raw split set (`.001/.002/.003`) stitched into one logical `Read + Seek`.
    Concat(ConcatSource),
    /// An EWF / split-VMDK set: the ordered per-segment sources for a container
    /// reader's multi-segment backing (archive-core does not stitch these).
    Segments(SegmentSources),
    /// The input is not a segment set (a single member, wrapper, collection, or
    /// raw stream) — nothing to reassemble.
    NotSegmented,
}

/// Produce the ordered per-segment [`PeeledSource`] handles for a segmented
/// image, or `Ok(None)` when `data` is not a segment set. Each segment is
/// materialized via its own [`crate::Access`] (in-place window / zran index /
/// temp spill), in segment-number order — the primitive both [`reassemble`] and
/// a container reader's `SegmentBacking` build on.
///
/// # Errors
/// Propagates a detect/executor failure ([`crate::ArchiveError`]).
pub fn segment_sources(data: Vec<u8>, limits: &Limits) -> Result<Option<SegmentSources>> {
    let AccessPlan::SegmentSet {
        format,
        members,
        kind,
    } = detect(&data)?
    else {
        return Ok(None);
    };
    // Share the archive bytes across every segment window (no per-segment clone).
    let data = Arc::new(data);
    let mut sources = Vec::with_capacity(members.len());
    for seg in &members {
        sources.push(execute_member_access(
            format,
            &data,
            seg.index,
            &seg.name,
            &seg.access,
            limits,
        )?);
    }
    Ok(Some(SegmentSources {
        format,
        kind,
        sources,
    }))
}

/// Reassemble a segmented image: a [`SegmentKind::SplitRaw`] set becomes a
/// stitched [`ConcatSource`]; an [`SegmentKind::Ewf`] / [`SegmentKind::SplitVmdk`]
/// set yields its ordered [`SegmentSources`] for a container reader's backing;
/// anything else is [`Reassembled::NotSegmented`].
///
/// # Errors
/// Propagates a detect/executor failure ([`crate::ArchiveError`]).
pub fn reassemble(data: Vec<u8>, limits: &Limits) -> Result<Reassembled> {
    let Some(ss) = segment_sources(data, limits)? else {
        return Ok(Reassembled::NotSegmented);
    };
    Ok(match ss.kind {
        // A raw split IS a byte-for-byte concatenation — stitch it here.
        SegmentKind::SplitRaw => Reassembled::Concat(ConcatSource::new(ss.sources)),
        // EWF / split-VMDK need the container reader's multi-segment logic;
        // hand back the ordered sources for its backing (the seam above).
        SegmentKind::Ewf | SegmentKind::SplitVmdk => Reassembled::Segments(ss),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic, non-repeating byte pattern of length `n` seeded by
    /// `seed`, so a wrong segment/offset yields visibly wrong bytes.
    fn pattern(n: usize, seed: usize) -> Vec<u8> {
        (0..n).map(|i| ((i + seed) % 251) as u8).collect()
    }

    /// Hand-assemble a multi-member ZIP whose members are each STORED (method 0),
    /// so every member's [`crate::Access`] is `InPlace` (a zero-copy window). The
    /// members appear in the given order — pass them out of segment order to
    /// prove reassembly reorders by segment number.
    fn stored_zip(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut z = Vec::new();
        let mut central = Vec::new();
        let mut count = 0u16;
        for (name, payload) in members {
            let nb = name.as_bytes();
            let mut crc = flate2::Crc::new();
            crc.update(payload);
            let crc = crc.sum();
            let lho = z.len() as u32;
            let (sz, nlen) = (payload.len() as u32, nb.len() as u16);
            // Local file header (method 0 = stored).
            z.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
            z.extend_from_slice(&20u16.to_le_bytes()); // version needed
            z.extend_from_slice(&0u16.to_le_bytes()); // flags
            z.extend_from_slice(&0u16.to_le_bytes()); // method: stored
            z.extend_from_slice(&0u16.to_le_bytes()); // mod time
            z.extend_from_slice(&0u16.to_le_bytes()); // mod date
            z.extend_from_slice(&crc.to_le_bytes());
            z.extend_from_slice(&sz.to_le_bytes()); // compressed size
            z.extend_from_slice(&sz.to_le_bytes()); // uncompressed size
            z.extend_from_slice(&nlen.to_le_bytes());
            z.extend_from_slice(&0u16.to_le_bytes()); // extra len
            z.extend_from_slice(nb);
            z.extend_from_slice(payload);
            // Central directory header.
            central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes()); // version made by
            central.extend_from_slice(&20u16.to_le_bytes()); // version needed
            central.extend_from_slice(&0u16.to_le_bytes()); // flags
            central.extend_from_slice(&0u16.to_le_bytes()); // method
            central.extend_from_slice(&0u16.to_le_bytes()); // mod time
            central.extend_from_slice(&0u16.to_le_bytes()); // mod date
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&sz.to_le_bytes());
            central.extend_from_slice(&sz.to_le_bytes());
            central.extend_from_slice(&nlen.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes()); // extra len
            central.extend_from_slice(&0u16.to_le_bytes()); // comment len
            central.extend_from_slice(&0u16.to_le_bytes()); // disk number start
            central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
            central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
            central.extend_from_slice(&lho.to_le_bytes()); // local header offset
            central.extend_from_slice(nb);
            count += 1;
        }
        let cd_offset = z.len() as u32;
        let cd_size = central.len() as u32;
        z.extend_from_slice(&central);
        // End of central directory.
        z.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes()); // disk num
        z.extend_from_slice(&0u16.to_le_bytes()); // disk with cd
        z.extend_from_slice(&count.to_le_bytes()); // entries this disk
        z.extend_from_slice(&count.to_le_bytes()); // total entries
        z.extend_from_slice(&cd_size.to_le_bytes());
        z.extend_from_slice(&cd_offset.to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes()); // comment len
        z
    }

    const FX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/fixtures/");

    fn load(name: &str) -> Vec<u8> {
        std::fs::read(format!("{FX}{name}")).unwrap()
    }

    // (a) A raw split set (`.001/.002/.003`), stored OUT OF ORDER in the zip, is
    // reassembled by concatenation in segment-number order; random reads across
    // the segment boundaries return the correct logical bytes, and a full read
    // reproduces `p1 ++ p2 ++ p3`.
    #[test]
    fn split_raw_concatenates_in_order_with_random_access() {
        let p1 = pattern(1000, 0);
        let p2 = pattern(1500, 100);
        let p3 = pattern(777, 200);
        // Out of order in the archive: 002, 003, 001.
        let data = stored_zip(&[("img.002", &p2), ("img.003", &p3), ("img.001", &p1)]);
        let Reassembled::Concat(mut c) = reassemble(data, &Limits::default()).unwrap() else {
            panic!("expected a SplitRaw ConcatSource");
        };
        let total = (p1.len() + p2.len() + p3.len()) as u64;
        assert_eq!(c.len(), total);
        assert!(!c.is_empty());

        // Full read reproduces the ordered concatenation.
        let mut whole = Vec::new();
        c.seek(SeekFrom::Start(0)).unwrap();
        c.read_to_end(&mut whole).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(&p1);
        expected.extend_from_slice(&p2);
        expected.extend_from_slice(&p3);
        assert_eq!(whole, expected);

        // A read straddling the p1|p2 boundary (offset 1000).
        c.seek(SeekFrom::Start(995)).unwrap();
        let mut span = [0u8; 12];
        c.read_exact(&mut span).unwrap();
        assert_eq!(&span[..5], &p1[995..1000]);
        assert_eq!(&span[5..], &p2[..7]);

        // A read straddling the p2|p3 boundary (offset 2500).
        c.seek(SeekFrom::Start(2495)).unwrap();
        let mut span2 = [0u8; 10];
        c.read_exact(&mut span2).unwrap();
        assert_eq!(&span2[..5], &p2[p2.len() - 5..]);
        assert_eq!(&span2[5..], &p3[..5]);

        // End-relative seek reads the tail of the last segment.
        c.seek(SeekFrom::End(-4)).unwrap();
        let mut tail = [0u8; 4];
        c.read_exact(&mut tail).unwrap();
        assert_eq!(tail, p3[p3.len() - 4..]);

        // A seek past the end clamps to the total length.
        assert_eq!(c.seek(SeekFrom::Start(u64::MAX)).unwrap(), total);
        assert_eq!(c.read(&mut [0u8; 8]).unwrap(), 0);
    }

    // (b) Each segment of a raw split uses its OWN access — a stored member is a
    // zero-copy `InPlace` window, never a copy — and `segment_sources` orders
    // them by segment number, each reading the exact segment bytes.
    #[test]
    fn split_raw_segment_sources_are_inplace_and_ordered() {
        let p1 = pattern(300, 1);
        let p2 = pattern(400, 2);
        let data = stored_zip(&[("d.002", &p2), ("d.001", &p1)]);
        let ss = segment_sources(data, &Limits::default())
            .unwrap()
            .expect("a segment set");
        assert_eq!(ss.kind, SegmentKind::SplitRaw);
        assert_eq!(ss.sources.len(), 2);
        let expected = [p1, p2];
        for (src, want) in ss.sources.into_iter().zip(expected) {
            assert!(
                matches!(src, PeeledSource::InPlace(_)),
                "a stored segment is a zero-copy InPlace window"
            );
            let mut got = Vec::new();
            let mut src = src;
            src.read_to_end(&mut got).unwrap();
            assert_eq!(got, want, "segment bytes read in order");
        }
    }

    // (c) An EWF `.E0N` set: archive-core hands back the ORDERED per-segment
    // sources (the `SegmentBacking` seam) — E01, E02, E03 — each reading the exact
    // segment bytes. Uses the committed `seg_ewf.zip` (members stored out of order).
    #[test]
    fn ewf_segment_sources_are_ordered_per_segment_handles() {
        let data = load("seg_ewf.zip");
        // Oracle: the ordered member bytes, straight from the archive reader.
        let mut a = crate::Archive::open(&data, Some("seg_ewf.zip"))
            .unwrap()
            .unwrap();
        let order = ["img.E01", "img.E02", "img.E03"];
        let oracle: Vec<Vec<u8>> = order
            .iter()
            .map(|n| {
                let idx = a.entries().iter().position(|e| e.name == *n).unwrap();
                a.read(idx).unwrap()
            })
            .collect();

        let ss = segment_sources(data, &Limits::default())
            .unwrap()
            .expect("a segment set");
        assert_eq!(ss.kind, SegmentKind::Ewf);
        assert_eq!(ss.sources.len(), 3);
        for (src, want) in ss.sources.into_iter().zip(oracle) {
            let mut got = Vec::new();
            let mut src = src;
            src.read_to_end(&mut got).unwrap();
            assert_eq!(got, want, "ordered E0N segment bytes");
        }

        // `reassemble` routes an EWF set to the Segments seam, not a ConcatSource.
        let data = load("seg_ewf.zip");
        match reassemble(data, &Limits::default()).unwrap() {
            Reassembled::Segments(s) => {
                assert_eq!(s.kind, SegmentKind::Ewf);
                assert_eq!(s.sources.len(), 3);
            }
            other => panic!("expected Segments seam, got {other:?}"),
        }
    }

    // A non-segmented input (a single stored member) is `NotSegmented`, and
    // `segment_sources` returns `None`.
    #[test]
    fn single_member_is_not_segmented() {
        let data = load("stored_one.zip");
        assert!(matches!(
            reassemble(data.clone(), &Limits::default()).unwrap(),
            Reassembled::NotSegmented
        ));
        assert!(segment_sources(data, &Limits::default()).unwrap().is_none());
    }

    // `SeekFrom::Current` moves the position relative to the cursor (forward and
    // backward), and a subsequent read returns the bytes at the resulting offset.
    #[test]
    fn seek_from_current_is_relative_both_ways() {
        let p1 = pattern(500, 0);
        let p2 = pattern(500, 50);
        let data = stored_zip(&[("s.001", &p1), ("s.002", &p2)]);
        let Reassembled::Concat(mut c) = reassemble(data, &Limits::default()).unwrap() else {
            panic!("expected a SplitRaw ConcatSource");
        };
        c.seek(SeekFrom::Start(100)).unwrap();
        assert_eq!(c.seek(SeekFrom::Current(50)).unwrap(), 150);
        let mut got = [0u8; 4];
        c.read_exact(&mut got).unwrap();
        assert_eq!(got, p1[150..154]);
        // pos is now 154; a negative relative seek walks back into segment 1.
        assert_eq!(c.seek(SeekFrom::Current(-54)).unwrap(), 100);
        c.read_exact(&mut got).unwrap();
        assert_eq!(got, p1[100..104]);
    }
}
