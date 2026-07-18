//! Phase 1 of two-phase archive access (ADR 0008): **content-authoritative,
//! name-free classification**. [`detect`] reads only bounded decompressed heads
//! and the archive's own member *table* — never a payload — and returns the
//! most-direct [`AccessPlan`] route to the evidence. Phase 2 (peel/execute) is a
//! later step; `detect.rs::peel_detour` is the current executor and coexists.

use crate::detect::Format;
use crate::error::Result;

/// The access strategy for one member or segment, chosen from the archive's
/// member table without decompressing (ADR 0008, rule 4 — most-seekable first).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Access {
    /// Stored/uncompressed member — seek a zero-copy sub-range in place.
    InPlace {
        /// Absolute offset of the member's first data byte in the archive.
        offset: u64,
        /// Length of the in-archive window (bytes).
        len: u64,
    },
    /// Deflate/Deflate64/gzip — a checkpoint seek-index gives random access
    /// with no full inflate.
    Zran,
    /// A non-seekable codec (LZMA/LZMA2/7z, bzip2 until a block-index lands) or
    /// a format exposing no in-archive offset — decompress once to temp.
    SpillToTemp,
}

/// The bare compression codec of an [`AccessPlan::Wrapper`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Codec {
    /// gzip (`1F 8B`).
    Gzip,
    /// bzip2 (`BZh`).
    Bzip2,
}

/// How a segmented set's members reassemble into one logical image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SegmentKind {
    /// EWF `.E01/.E02…` (also `.Ex01`, `.s01`) — ordered by segment number.
    Ewf,
    /// Raw split `.001/.002…` — ordered by the numeric suffix.
    SplitRaw,
    /// Split VMDK `<base>-s001.vmdk`… — ordered by the `-sNNN` index.
    SplitVmdk,
}

/// One member of an [`AccessPlan::SegmentSet`], carrying its own access strategy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// Member name within the archive (the ordering signal for a split set).
    pub name: String,
    /// The member's index in the archive's table.
    pub index: usize,
    /// This segment's most-seekable access strategy.
    pub access: Access,
}

/// The classified, most-direct route from packed bytes to the evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AccessPlan {
    /// Uncompressed, non-archive stream — open as-is.
    Direct,
    /// A bare gzip/bzip2 wrapper over a single stream.
    Wrapper {
        /// The outer compression codec.
        codec: Codec,
        /// Access strategy for the single wrapped stream.
        access: Access,
    },
    /// Exactly one forensic file member inside an archive.
    Member {
        /// The archive format the member lives in.
        format: Format,
        /// The member's index in the archive table.
        index: usize,
        /// The member's recorded name.
        name: String,
        /// The member's most-seekable access strategy.
        access: Access,
    },
    /// A segmented image (`E01/E02…`, split raw, split VMDK) — one logical stream.
    SegmentSet {
        /// The archive format the segments live in.
        format: Format,
        /// The segments, ordered by segment number.
        members: Vec<Segment>,
        /// How the segments reassemble.
        kind: SegmentKind,
    },
    /// Several independent members — a tree, each re-resolved on its own.
    Collection {
        /// The archive format.
        format: Format,
    },
}

/// Classify the most-direct access route to the evidence inside `data`,
/// **content-authoritatively and name-free** (ADR 0008, five rules): every
/// decision is made from bytes plus the archive's own internal member table; no
/// payload is ever inflated to classify.
///
/// # Errors
/// Propagates an archive open/read failure ([`crate::ArchiveError`]) from reading
/// the member table (never from inflating a payload — that is phase 2).
pub fn detect(data: &[u8]) -> Result<AccessPlan> {
    let _ = data;
    todo!()
}

/// A bare gz/bz2 wrapper. Peeks a bounded decompressed head and classifies from
/// it (rules 2/3).
fn detect_wrapper(codec: Codec, data: &[u8]) -> Result<AccessPlan> {
    let _ = (codec, data);
    todo!()
}

/// Read the archive's member TABLE (never a payload) and classify the set.
fn detect_archive(format: Format, data: &[u8]) -> Result<AccessPlan> {
    let _ = (format, data);
    todo!()
}

/// Decompress at most a bounded head of `data`'s single compressed stream.
fn peek_head(codec: Codec, data: &[u8]) -> Result<Vec<u8>> {
    let _ = (codec, data);
    todo!()
}

/// The best access a bare wrapper's codec allows: gzip → zran, bzip2 → spill.
fn wrapper_access(codec: Codec) -> Access {
    let _ = codec;
    todo!()
}

/// A short, stable label for a codec (for diagnostics).
fn codec_name(codec: Codec) -> &'static str {
    let _ = codec;
    todo!()
}

/// The segment number for `name` under `kind`, or `None` if it does not match.
fn segment_number(name: &str, kind: SegmentKind) -> Option<u64> {
    let _ = (name, kind);
    todo!()
}

/// The uniform [`SegmentKind`] all `files` match, if any (VMDK, then EWF, then
/// raw — the three are name-disjoint).
fn classify_segment_kind(files: &[(usize, String)]) -> Option<SegmentKind> {
    let _ = files;
    todo!()
}

/// The `files` that match `kind`, ordered by segment number.
fn order_segments(files: &[(usize, String)], kind: SegmentKind) -> Vec<(usize, String, u64)> {
    let _ = (files, kind);
    todo!()
}

/// EWF segment number from an `.E0N`/`.Ex0N`/`.s0N` name (two-digit suffix).
fn ewf_segment(name: &str) -> Option<u64> {
    let _ = name;
    todo!()
}

/// Raw-split segment number from an all-digit extension (`.001`, ≥ 2 digits).
fn raw_split(name: &str) -> Option<u64> {
    let _ = name;
    todo!()
}

/// Split-VMDK segment number from a `<base>-sNNN.vmdk` name.
fn vmdk_segment(name: &str) -> Option<u64> {
    let _ = name;
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const FX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/fixtures/");

    fn load(name: &str) -> Vec<u8> {
        std::fs::read(format!("{FX}{name}")).unwrap()
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

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

    // ---- wrappers ------------------------------------------------------------

    #[test]
    fn bare_gzip_of_raw_bytes_is_wrapper_zran() {
        let gz = gzip(&b"raw disk sector bytes, not an archive at all ".repeat(40));
        assert_eq!(
            detect(&gz).unwrap(),
            AccessPlan::Wrapper {
                codec: Codec::Gzip,
                access: Access::Zran
            }
        );
    }

    #[test]
    fn gzip_of_single_member_tar_is_targz_member() {
        let tar = build_tar(&[("disk.img", b"RAW-IMAGE-BYTES".to_vec())]);
        let gz = gzip(&tar);
        match detect(&gz).unwrap() {
            AccessPlan::Member {
                format,
                name,
                access,
                ..
            } => {
                assert_eq!(format, Format::TarGz);
                assert_eq!(name, "disk.img");
                assert_eq!(access, Access::SpillToTemp);
            }
            other => panic!("expected TarGz Member, got {other:?}"),
        }
    }

    #[test]
    fn coincidental_gzip_magic_is_direct() {
        // Valid `1F 8B` magic but an invalid gzip member (CM != deflate): the
        // bounded head fails to decode → not packed (rule 2 content guard).
        assert_eq!(
            detect(b"\x1f\x8b\x00\x00garbage-not-really-gzip").unwrap(),
            AccessPlan::Direct
        );
    }

    #[test]
    fn raw_bytes_are_direct() {
        assert_eq!(
            detect(b"\x00\x01\x02 not a wrapper or archive").unwrap(),
            AccessPlan::Direct
        );
    }

    // ---- zip access ladder ---------------------------------------------------

    #[test]
    fn zip_single_stored_member_is_inplace() {
        match detect(&load("stored_one.zip")).unwrap() {
            AccessPlan::Member {
                format,
                name,
                access,
                ..
            } => {
                assert_eq!(format, Format::Zip);
                assert_eq!(name, "disk.dd");
                match access {
                    Access::InPlace { offset, len } => {
                        assert_eq!(len, 4096);
                        assert!(offset > 0, "stored data starts after a local header");
                    }
                    other => panic!("expected InPlace, got {other:?}"),
                }
            }
            other => panic!("expected Member, got {other:?}"),
        }
    }

    #[test]
    fn zip_single_deflate_member_is_zran() {
        match detect(&load("deflate_one.zip")).unwrap() {
            AccessPlan::Member {
                format,
                name,
                access,
                ..
            } => {
                assert_eq!(format, Format::Zip);
                assert_eq!(name, "big.dd");
                assert_eq!(access, Access::Zran);
            }
            other => panic!("expected Member, got {other:?}"),
        }
    }

    // ---- segment sets --------------------------------------------------------

    #[test]
    fn zip_ewf_segments_order_by_number_each_inplace() {
        // seg_ewf.zip stores members out of order (E03, E01, E02); detect must
        // reorder by segment number and mark each Stored member InPlace.
        match detect(&load("seg_ewf.zip")).unwrap() {
            AccessPlan::SegmentSet {
                format,
                members,
                kind,
            } => {
                assert_eq!(format, Format::Zip);
                assert_eq!(kind, SegmentKind::Ewf);
                let names: Vec<&str> = members.iter().map(|s| s.name.as_str()).collect();
                assert_eq!(names, ["img.E01", "img.E02", "img.E03"]);
                for s in &members {
                    assert!(
                        matches!(s.access, Access::InPlace { .. }),
                        "stored segment → InPlace, got {:?}",
                        s.access
                    );
                }
            }
            other => panic!("expected SegmentSet Ewf, got {other:?}"),
        }
    }

    #[test]
    fn zip_raw_split_is_segmentset_splitraw() {
        match detect(&load("seg_split.zip")).unwrap() {
            AccessPlan::SegmentSet {
                format,
                members,
                kind,
            } => {
                assert_eq!(format, Format::Zip);
                assert_eq!(kind, SegmentKind::SplitRaw);
                let names: Vec<&str> = members.iter().map(|s| s.name.as_str()).collect();
                assert_eq!(names, ["disk.001", "disk.002"]);
            }
            other => panic!("expected SegmentSet SplitRaw, got {other:?}"),
        }
    }

    #[test]
    fn tar_split_vmdk_is_segmentset_splitvmdk() {
        // Segment classification is format-agnostic; a plain tar carrying split
        // VMDK names classifies identically (access falls to SpillToTemp for tar).
        let tar = build_tar(&[
            ("disk-s002.vmdk", b"seg-two".to_vec()),
            ("disk-s001.vmdk", b"seg-one".to_vec()),
        ]);
        match detect(&tar).unwrap() {
            AccessPlan::SegmentSet {
                format,
                members,
                kind,
            } => {
                assert_eq!(format, Format::Tar);
                assert_eq!(kind, SegmentKind::SplitVmdk);
                let names: Vec<&str> = members.iter().map(|s| s.name.as_str()).collect();
                assert_eq!(names, ["disk-s001.vmdk", "disk-s002.vmdk"]);
                assert!(members.iter().all(|s| s.access == Access::SpillToTemp));
            }
            other => panic!("expected SegmentSet SplitVmdk, got {other:?}"),
        }
    }

    // ---- collections ---------------------------------------------------------

    #[test]
    fn zip_unrelated_members_is_collection() {
        assert_eq!(
            detect(&load("payload.zip")).unwrap(),
            AccessPlan::Collection {
                format: Format::Zip
            }
        );
    }

    #[test]
    fn sevenzip_unrelated_members_is_collection() {
        assert_eq!(
            detect(&load("payload.7z")).unwrap(),
            AccessPlan::Collection {
                format: Format::SevenZip
            }
        );
    }

    // ---- content authority ---------------------------------------------------

    #[test]
    fn bzip2_tar_classified_by_decompressed_content_not_name() {
        // payload.tbz2 is a bzip2-compressed tar. `detect` takes no name, so the
        // classification is decided from the decompressed head (tar magic) — the
        // outer bzip2 magic alone cannot reveal the inner tar.
        match detect(&load("payload.tbz2")).unwrap() {
            AccessPlan::Collection { format } => assert_eq!(format, Format::TarBz2),
            other => panic!("expected TarBz2 Collection from content, got {other:?}"),
        }
    }

    // ---- segment name matchers (unit) ---------------------------------------

    #[test]
    fn ewf_segment_matches_e_ex_s_only() {
        assert_eq!(ewf_segment("img.E01"), Some(1));
        assert_eq!(ewf_segment("img.e12"), Some(12));
        assert_eq!(ewf_segment("img.Ex03"), Some(3));
        assert_eq!(ewf_segment("img.s07"), Some(7));
        assert_eq!(ewf_segment("notes.txt"), None);
        assert_eq!(ewf_segment("tool.exe"), None);
        assert_eq!(ewf_segment("img.E1"), None); // single digit
        assert_eq!(ewf_segment("noext"), None);
    }

    #[test]
    fn raw_split_matches_all_digit_ext() {
        assert_eq!(raw_split("disk.001"), Some(1));
        assert_eq!(raw_split("disk.017"), Some(17));
        assert_eq!(raw_split("disk.E01"), None);
        assert_eq!(raw_split("disk.1"), None); // needs >= 2 digits
        assert_eq!(raw_split("noext"), None);
    }

    #[test]
    fn vmdk_segment_matches_dash_s_only() {
        assert_eq!(vmdk_segment("disk-s001.vmdk"), Some(1));
        assert_eq!(vmdk_segment("disk-s012.vmdk"), Some(12));
        assert_eq!(vmdk_segment("disk.vmdk"), None); // monolithic
        assert_eq!(vmdk_segment("disk-flat.vmdk"), None);
        assert_eq!(vmdk_segment("disk-s001.bin"), None); // not vmdk
    }
}
