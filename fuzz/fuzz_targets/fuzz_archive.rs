#![no_main]
//! `Archive::open` parses an archive's member table (zip central directory, 7z
//! header, tar block stream) from attacker-controllable bytes, and `read` inflates
//! a member. Opening and reading arbitrary bytes must NEVER panic.

use archive_core::Archive;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(Some(mut archive)) = Archive::open(data, Some("evidence.zip")) {
        let count = archive.entries().len().min(64);
        for i in 0..count {
            let _ = archive.member_access(i);
            let _ = archive.read(i);
        }
    }
});
