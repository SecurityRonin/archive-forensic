# 4. Reuse fleet readers; batteries-included default features

Date: 2026-07-24
Status: Accepted

> Reverse-documented from `core/src/archive.rs`, `core/Cargo.toml`, and the fleet
> constitution's "Dependency Preference" + "Batteries-Included" standards.

## Context

Archive-core needs to walk zip and 7z member tables and decompress tar's outer
layer. Two fleet standards constrain how:

- **Prefer our own crates** (`~/src/ronin-issen/CLAUDE.md`, "Dependency
  Preference"): when SecurityRonin already publishes an equivalent reader, use it
  over a third-party crate.
- **Batteries-included** (same file): a forensic tool must do the whole job from
  one artifact; `default-features = false` as a way to *slim a capability* is
  banned, because a codec that isn't compiled in isn't there when an examiner
  needs it in the field.

## Decision

1. **ZIP → the fleet's own `zip-forensic-core`** (imports as `zip_core`), not a
   third-party zip crate (`core/Cargo.toml`; `Backend::Zip` in
   `core/src/archive.rs`). This is the prefer-our-own rule applied directly.
2. **7z → `sevenz-rust2` with its default features on** (aes256 + bzip2 + ppmd +
   the built-in LZMA/LZMA2/copy/delta codecs). No third-party fleet 7z reader
   exists, so the mature pure-Rust crate is reused; its full codec set is kept
   compiled in per batteries-included. Only the C-linking `zstd` feature is left
   off (ADR 0003).
3. **tar outer layer → reuse `archive-core`'s own `peel` gzip/bzip2 decoders**
   plus the `tar` crate for member walking — the decode path is not reimplemented
   (`core/src/archive.rs` module doc: "Backends are reused, never
   reimplemented").
4. **When full features trip a gate, fix the gate.** The pure-Rust codec licences
   (bzip2-1.0.6, MIT-0) are added to the `deny.toml` allow-list with rationale,
   rather than disabling a codec to satisfy the licence check.

## Consequences

- Adding a format capability benefits from a maintained, fuzzed upstream rather
  than a partial in-repo reimplementation — consistent with the `unsafe`-law's
  build-vs-reuse corollary.
- One `archive-core` build decodes zip/7z/tar/gzip/bzip2 with no feature flags to
  remember; a downstream binary linking it is capable by default.
- The `vfs` feature (ADR 0007) is the deliberate *narrow* exception the standard
  permits — an optional, rarely-wanted integration dependency kept off the default
  path so a bare reader stays dependency-light.
