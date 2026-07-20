# archive-forensic

Pure-Rust, `forbid(unsafe)`, read-only **archive-layer** reader and anomaly auditor
for digital forensics.

An archive is treated as a transparent optional *archive layer*: `evidence.E01.gz`
resolves identically to `evidence.E01`. archive-core peels gzip / bzip2 / xz / zip /
7z / tar layers to reach the inner evidence, determining the format by **content
magic** (the authority for the codec) with the file name as a secondary hint for
aliases (`.tgz` / `.tbz2`) and the magic-absent formats.

## The two crates

| crate | role |
|---|---|
| **`archive-core`** | the peel / archive-layer reader + format detection: single-layer [`peel_bytes`], recursive [`resolve`] with bomb guards, member reading via [`Archive`], segment reassembly, and the phase-1 [`detect`] access-plan. Reuses the fleet readers `zip-forensic-core` (zip) and `sevenz-rust2` (7z), plus pure-Rust flate2 / bzip2. |
| **`archive-forensic`** | the analyzer over archive-core: extension-vs-content masquerade, CRC / declared-size lies, path-traversal member names, and decompression-bomb signatures. |

Status: under active TDD construction — the reader (zip/7z/tar/gzip/bzip2 peel,
recursive resolve, segment reassembly, VFS adapter) is wired; the analyzer surface
lands as archive-core's tree API grows.

## Trust but verify

- **Pure-Rust, no C-FFI codecs.** `forbid(unsafe)` at the workspace root; the
  compression stack (flate2/miniz_oxide, bzip2-rs/libbz2-rs-sys, lzma-rust2,
  ruzstd) is pure-Rust — no bundled C is compiled or linked.
- **Panic-free by lint.** `unwrap_used` / `expect_used` are denied in production
  code; bomb guards (depth / cumulative-inflated-size / entry-count caps) fail
  loud rather than exhausting memory.
- **Input-fuzzed.** `cargo-fuzz` targets drive `peel_bytes`, `resolve`, and
  `Archive::open`/`read` on arbitrary bytes — the invariant is *never panic*.
- **Validated against reference-tool archives.** See [Validation](validation.md).

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · © 2026 Security Ronin Ltd.
