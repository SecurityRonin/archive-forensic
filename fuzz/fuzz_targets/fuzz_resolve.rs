#![no_main]
//! `resolve` recursively peels every archive layer of attacker-controllable bytes
//! down to leaf files, guarded by `Limits` (depth / inflated-size / entry-count
//! bomb caps). The full recursion over arbitrary bytes must NEVER panic.

use archive_core::{resolve, Limits};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Tight limits keep each fuzz iteration fast while still exercising the
    // recursion, the bomb guards, and their fail-loud paths.
    let limits = Limits {
        max_depth: 4,
        max_total_inflated: 8 << 20, // 8 MiB
        max_entries: 4096,
        max_index_bytes: 1 << 20, // 1 MiB
    };
    let _ = resolve(data, Some("evidence.zip"), &limits);
});
