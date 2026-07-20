<p align="center">
  <h1 align="center">archive-forensic</h1>
  <p align="center">Peel every archive layer to reach the evidence — and catch the ones that lie about what they hold.</p>
</p>

[![Crates.io (archive-core)](https://img.shields.io/crates/v/archive-core.svg?label=archive-core)](https://crates.io/crates/archive-core)
[![Crates.io (archive-forensic)](https://img.shields.io/crates/v/archive-forensic.svg?label=archive-forensic)](https://crates.io/crates/archive-forensic)
[![docs.rs](https://img.shields.io/docsrs/archive-core?label=docs.rs)](https://docs.rs/archive-core)
[![Rust 1.93+](https://img.shields.io/badge/rust-1.93%2B-orange.svg)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

[![CI](https://github.com/SecurityRonin/archive-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/archive-forensic/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-89%25%20lines-yellowgreen.svg)](https://github.com/SecurityRonin/archive-forensic/actions/workflows/ci.yml)
[![unsafe: forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](Cargo.toml)
[![Security audit](https://img.shields.io/badge/security-audit-brightgreen.svg)](https://github.com/SecurityRonin/archive-forensic/actions/workflows/ci.yml)

**An archive is a transparent layer over your evidence — `evidence.E01.gz` should read exactly like `evidence.E01`.**

`archive-core` is a pure-Rust, `forbid(unsafe)`, read-only reader that peels
gzip / bzip2 / xz / zip / 7z / tar layers to reach the inner artifact, choosing
the codec by **content magic** (the authority for what was actually applied) and
using the file name only as a secondary hint for aliases (`.tgz` / `.tbz2`) and
the magic-absent formats. `archive-forensic` is the anomaly auditor layered on
top of it.

Recursively unpack any nested archive to its leaf files, with archive-bomb guards:

```rust
use archive_core::{resolve, Limits, Node};

let bytes = std::fs::read("evidence.tar.gz.zip")?;
for node in resolve(&bytes, Some("evidence.tar.gz.zip"), &Limits::default())? {
    if let Node::File { name, bytes } = node {
        println!("{name}: {} bytes", bytes.len());
    }
}
# Ok::<(), archive_core::ArchiveError>(())
```

`resolve` peels layer after layer (zip → tar.gz → tar → …) until it reaches real
files, capping cumulative depth, inflated size, and member count so a
decompression bomb fails loud instead of exhausting memory. For a single peel use
`peel_bytes`; to read members of one archive without recursing use `Archive`.

## The two crates

| crate | role |
|---|---|
| **`archive-core`** | the peel / archive-layer reader + format detection: single-layer `peel_bytes`, recursive `resolve` with bomb guards, member reading via `Archive`, segment reassembly (split / EWF `.E0n` / raw `.00n`), and the phase-1 `detect` access-plan. Reuses the fleet readers `zip-forensic-core` (zip) and `sevenz-rust2` (7z), plus pure-Rust flate2 / bzip2. |
| **`archive-forensic`** | the anomaly auditor over archive-core: extension-vs-content masquerade, CRC / declared-size lies, path-traversal member names, decompression-bomb signatures. |

**Status:** under active TDD construction. The reader (zip/7z/tar/gzip/bzip2 peel,
recursive `resolve`, segment reassembly, and the optional `vfs` `ArchiveOpener`
adapter) is wired and validated; the `archive-forensic` audit surface lands as
archive-core's tree API grows.

## Trust, but verify

- **Pure-Rust, no C-FFI codecs.** `forbid(unsafe)` across the whole workspace; the
  compression stack (flate2/miniz_oxide, bzip2-rs/libbz2-rs-sys, lzma-rust2,
  ruzstd) is pure-Rust — no bundled C is compiled or linked.
- **Panic-free by lint.** `unwrap_used` / `expect_used` denied in production code;
  the bomb guards (depth / cumulative-inflated-size / entry-count caps) fail loud.
- **Input-fuzzed.** `cargo-fuzz` targets drive `peel_bytes`, `resolve`, and
  `Archive::open`/`read` on arbitrary bytes — invariant *never panic*.
- **Validated against reference-tool archives.** Fixtures are minted by GNU tar,
  Info-ZIP, 7-Zip, and CPython and read back byte-for-byte — see
  [docs/validation.md](docs/validation.md).

## Documentation

Full docs, including the validation write-up, are published at
[securityronin.github.io/archive-forensic](https://securityronin.github.io/archive-forensic/).

---

[Privacy Policy](https://securityronin.github.io/archive-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/archive-forensic/terms/) · © 2026 Security Ronin Ltd
