#![no_main]
//! `peel_bytes` removes one archive/compression layer from attacker-controllable
//! bytes (gzip/bzip2/xz/zip/7z/tar). Peeling arbitrary bytes must NEVER panic.

use archive_core::peel_bytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // With and without a name hint — the name steers alias/magic-absent detection.
    let _ = peel_bytes(data, None);
    let _ = peel_bytes(data, Some("evidence.tar.gz"));
});
