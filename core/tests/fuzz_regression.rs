//! An input that once panicked `resolve`, kept as an ordinary test.
//!
//! Unlike the other fuzz-found defects in this fleet, the panic was not ours:
//! it fired inside `sevenz-rust2` 0.21.3 (`reader.rs:1047`, "attempt to add
//! with overflow") while parsing a 7z header. That does not make it any less
//! our problem — a `*-core` crate must not panic on attacker-controlled input,
//! whichever crate's frame the panic happens to be in.
//!
//! Upstream fixed it in 0.21.4, and the requirement here (`"0.21"`) already
//! allowed that; only the lockfile was behind. So the fix is a lock refresh
//! rather than a workaround, and this test is what stops the lock drifting back
//! without anyone noticing.
//!
//! The assertion is deliberately weak on *what* comes back. A malformed archive
//! may legitimately resolve to nothing or fail; the contract under test is only
//! that it returns rather than panicking.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use archive_core::{resolve, Limits};

/// libFuzzer `fuzz_resolve` reproducer: overflowed an addition in the 7z header
/// reader.
const SEVENZ_CRASH: &[u8] =
    include_bytes!("../../tests/data/fixtures/fuzz-crash-resolve-sevenz-overflow.7z");

#[test]
fn sevenz_header_overflow_reproducer_does_not_panic() {
    // The same limits the fuzz target uses, so this exercises the path that
    // broke rather than a more permissive one.
    let limits = Limits {
        max_depth: 4,
        max_total_inflated: 8 << 20,
        max_entries: 4096,
        max_index_bytes: 1 << 20,
    };
    let _ = resolve(SEVENZ_CRASH, Some("evidence.zip"), &limits);
}
