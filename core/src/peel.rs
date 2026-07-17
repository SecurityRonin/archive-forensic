//! Peel one outer packing layer, if present.

use crate::detect::{sniff, Format};
use crate::error::{ArchiveError, Result};

/// In-memory cap on a single peel's decompressed output (bomb guard). Streaming
/// / temp-spill for genuinely large inner evidence is the next hardening step.
const MAX_INFLATED: u64 = 4 << 30; // 4 GiB

/// The result of attempting to peel one packing layer.
#[derive(Debug)]
#[non_exhaustive]
pub enum PeelOutcome {
    /// The input is not a recognized packing layer — pass it through unchanged.
    NotPacked,
    /// A compression wrapper was peeled to its inner byte stream. A consumer
    /// re-runs detection on `inner` to continue down the stack.
    Peeled { format: Format, inner: Vec<u8> },
}

/// Peel one outer compression layer from `data` if it is a recognized wrapper.
/// `name` is an optional file name used as a secondary detection hint.
pub fn peel_bytes(data: &[u8], name: Option<&str>) -> Result<PeelOutcome> {
    match sniff(name, data) {
        Format::Gzip => Ok(PeelOutcome::Peeled {
            format: Format::Gzip,
            inner: decode_gzip(data)?,
        }),
        _ => Ok(PeelOutcome::NotPacked),
    }
}

/// Inflate a gzip member to bytes, failing loud past [`MAX_INFLATED`].
fn decode_gzip(data: &[u8]) -> Result<Vec<u8>> {
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
    fn peels_gzip_to_inner_bytes() {
        let inner = b"E01-ish evidence \x00\x01\x02 the quick brown fox".repeat(20);
        let gz = gzip(&inner);
        // Magic wins even with a misleading name.
        assert_eq!(sniff(Some("evidence.bin"), &gz), Format::Gzip);
        match peel_bytes(&gz, Some("evidence.E01.gz")).unwrap() {
            PeelOutcome::Peeled { format, inner: got } => {
                assert_eq!(format, Format::Gzip);
                assert_eq!(got, inner);
            }
            other => panic!("expected Peeled, got {other:?}"),
        }
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
        // A `.gz`-named file that is actually 7z magic sniffs as 7z (content
        // is authority for the codec).
        let seven = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0, 0];
        assert_eq!(sniff(Some("foo.gz"), &seven), Format::SevenZip);
    }
}
