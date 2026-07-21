#![no_main]
//! `peel_bytes` peels one BARE compression layer — **gzip/bzip2 only** — from
//! attacker-controllable bytes. Everything else returns `NotPacked`: xz is not
//! supported, and the zip/7z/tar member-list archives are handled by
//! `crate::archive`, not here. Peeling arbitrary bytes must NEVER panic.

use archive_core::peel_bytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // With and without a name hint — the name steers alias/magic-absent detection.
    let _ = peel_bytes(data, None);
    let _ = peel_bytes(data, Some("evidence.tar.gz"));
});
