//! Peel one outer BARE compression layer (gzip / bzip2), if present.
//!
//! This handles a single compressed file — e.g. a `disk.dd.gz` evidence image.
//! Multi-member archives (`.tgz`/`.tbz2`/`.zip`/`.7z`) are handled by
//! [`crate::archive`], which reuses [`decode_gzip`]/[`decode_bzip2`] for their
//! outer layer.

use crate::detect::{sniff, Format};
use crate::error::{ArchiveError, Result};

/// In-memory cap on a single decompression's output (bomb guard). Streaming /
/// temp-spill for genuinely large inner evidence is the next hardening step.
pub(crate) const MAX_INFLATED: u64 = 4 << 30; // 4 GiB

/// The result of attempting to peel one bare-compression layer.
#[derive(Debug)]
#[non_exhaustive]
pub enum PeelOutcome {
    /// Not a bare compression wrapper — pass it through unchanged.
    NotPacked,
    /// A bare gzip/bzip2 wrapper peeled to its inner byte stream. A consumer
    /// re-runs detection on `inner` to continue down the stack.
    Peeled { format: Format, inner: Vec<u8> },
}

/// Peel one outer BARE gzip/bzip2 compression layer from `data`. Archives
/// (`.tgz`/`.tbz2`/`.zip`/`.7z`) are NOT peeled here — they are member lists;
/// use [`crate::archive::open`]. `name` is an optional file-name hint.
pub fn peel_bytes(data: &[u8], name: Option<&str>) -> Result<PeelOutcome> {
    match sniff(name, data) {
        Format::Gzip => Ok(PeelOutcome::Peeled {
            format: Format::Gzip,
            inner: decode_gzip(data)?,
        }),
        Format::Bzip2 => Ok(PeelOutcome::Peeled {
            format: Format::Bzip2,
            inner: decode_bzip2(data)?,
        }),
        _ => Ok(PeelOutcome::NotPacked),
    }
}

/// Inflate a gzip stream to bytes, failing loud past [`MAX_INFLATED`].
pub(crate) fn decode_gzip(data: &[u8]) -> Result<Vec<u8>> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut out = Vec::new();
    // Read one byte past the cap so an over-cap stream is *detected*, not
    // silently truncated.
    let mut limited = GzDecoder::new(data).take(MAX_INFLATED + 1);
    limited
        .read_to_end(&mut out)
        .map_err(|e| ArchiveError::Decode {
            format: "gzip",
            detail: e.to_string(),
        })?;
    if out.len() as u64 > MAX_INFLATED {
        return Err(ArchiveError::TooLarge { cap: MAX_INFLATED });
    }
    Ok(out)
}

/// Inflate a bzip2 stream to bytes, failing loud past [`MAX_INFLATED`].
pub(crate) fn decode_bzip2(data: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut out = Vec::new();
    let mut limited = bzip2_rs::DecoderReader::new(data).take(MAX_INFLATED + 1);
    limited
        .read_to_end(&mut out)
        .map_err(|e| ArchiveError::Decode {
            format: "bzip2",
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
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn peels_bare_gzip_to_inner_bytes() {
        let inner = b"E01-ish evidence \x00\x01\x02 the quick brown fox".repeat(20);
        let gz = gzip(&inner);
        assert_eq!(sniff(Some("evidence.bin"), &gz), Format::Gzip);
        match peel_bytes(&gz, Some("evidence.dd.gz")).unwrap() {
            PeelOutcome::Peeled { format, inner: got } => {
                assert_eq!(format, Format::Gzip);
                assert_eq!(got, inner);
            }
            other => panic!("expected Peeled, got {other:?}"),
        }
    }

    const PAYLOAD_BZ2: &[u8] = include_bytes!("../../tests/data/fixtures/payload.bz2");

    #[test]
    fn peels_bare_bzip2() {
        let expected = "archive-detour bzip2 test payload — the quick brown fox\n"
            .repeat(30)
            .into_bytes();
        match peel_bytes(PAYLOAD_BZ2, Some("payload.bz2")).unwrap() {
            PeelOutcome::Peeled { format, inner } => {
                assert_eq!(format, Format::Bzip2);
                assert_eq!(inner, expected);
            }
            other => panic!("expected Peeled, got {other:?}"),
        }
    }

    #[test]
    fn archive_is_not_bare_peeled() {
        // A zip is a member list, not a bare wrapper — peel_bytes leaves it.
        let zip = b"PK\x03\x04 rest of a zip";
        assert!(matches!(
            peel_bytes(zip, Some("eo.zip")).unwrap(),
            PeelOutcome::NotPacked
        ));
    }

    #[test]
    fn non_packed_passthrough() {
        let raw = b"\x00\x01\x02 not a known wrapper";
        assert!(matches!(
            peel_bytes(raw, Some("disk.raw")).unwrap(),
            PeelOutcome::NotPacked
        ));
    }

    #[test]
    fn magic_beats_extension() {
        let seven = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0, 0];
        assert_eq!(sniff(Some("foo.gz"), &seven), Format::SevenZip);
    }

    // A gzip stream whose tail is truncated still sniffs as gzip (magic head
    // intact) but must fail LOUD on inflate — never silently return a short body.
    #[test]
    fn truncated_gzip_fails_loud() {
        let inner = b"disk sector bytes \x00\x01\x02 the quick brown fox".repeat(50);
        let mut gz = gzip(&inner);
        gz.truncate(gz.len() / 2); // lop off the compressed tail + CRC/ISIZE
        assert_eq!(sniff(Some("disk.dd.gz"), &gz), Format::Gzip);
        match peel_bytes(&gz, Some("disk.dd.gz")) {
            Err(ArchiveError::Decode { format, .. }) => assert_eq!(format, "gzip"),
            other => panic!("expected a loud gzip Decode error, got {other:?}"),
        }
    }

    // The committed bzip2 fixture, truncated mid-stream, still carries the `BZh`
    // magic (sniffs Bzip2) but must fail loud on decode.
    #[test]
    fn truncated_bzip2_fails_loud() {
        let mut bz = PAYLOAD_BZ2.to_vec();
        bz.truncate(bz.len() / 2);
        assert_eq!(sniff(Some("payload.bz2"), &bz), Format::Bzip2);
        match peel_bytes(&bz, Some("payload.bz2")) {
            Err(ArchiveError::Decode { format, .. }) => assert_eq!(format, "bzip2"),
            other => panic!("expected a loud bzip2 Decode error, got {other:?}"),
        }
    }
}
