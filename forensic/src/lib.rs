//! `archive-forensic` — an anomaly auditor over [`archive_core`] that emits
//! findings for extension-vs-content masquerade, CRC/declared-size lies,
//! path-traversal member names, and decompression-bomb signatures.
//!
//! Scaffold: audits land as `archive-core`'s peel/tree surface grows.
