# 3. `forbid(unsafe)`, panic-free by lint, and a pure-Rust (no C-FFI) codec stack

Date: 2026-07-24
Status: Accepted

> Reverse-documented from `Cargo.toml` (`[workspace.lints]`), `core/Cargo.toml`
> dependency comments, `deny.toml`, and the README "Trust, but verify" section.

## Context

`archive-core` parses **untrusted, attacker-controllable** compressed streams and
archive directories: a crafted gzip tail, a lying zip central directory, a 7z
header with an absurd declared size. The fleet's Paranoid Gatekeeper standard
(`~/src/ronin-issen/CLAUDE.md`) requires such crates to never panic, never read
out of bounds, and never trust a length field — and the global `unsafe`-exception
law prefers `forbid(unsafe)` as a *provable, badge-able* "zero places a crafted
input can corrupt memory," accepting a bounded `deny`+allow only when a real
benefit (e.g. an mmap) justifies it.

A second axis: the compression codecs. A C-FFI `-sys` crate (libz, libbz2, liblzma)
gives the compiler zero visibility into the parsing of untrusted bytes — exactly
the C/C++ memory-corruption/RCE class safe Rust deletes. The `unsafe`-law weights
a C-FFI liability far more heavily than any pure-Rust bounded block.

## Decision

1. **`unsafe_code = "forbid"` across the whole workspace** (`Cargo.toml`
   `[workspace.lints.rust]`). No mmap or other perf-motivated `unsafe` is used, so
   the crate keeps the strongest posture and earns the `unsafe: forbidden` README
   badge honestly (unlike ewf/memory-forensic which are `deny`+bounded-allow).
2. **Panic-free by lint** — `unwrap_used = "deny"` and `expect_used = "deny"` in
   production (`[workspace.lints.clippy]`), plus the base clippy tier
   (`correctness`/`suspicious` denied, `all`/`pedantic` warned). Tests may unwrap
   (`clippy.toml` `allow-unwrap-in-tests`/`allow-expect-in-tests`, and each lib's
   `#![cfg_attr(test, allow(...))]`). Failures fail loud via typed
   `ArchiveError` (`core/src/error.rs`), never a silent truncation — see the
   `truncated_gzip_fails_loud` / `truncated_bzip2_fails_loud` tests.
3. **Pure-Rust, no bundled C.** Every codec resolves to a Rust implementation:
   flate2 with `default-features = false, features = ["rust_backend"]`
   (miniz_oxide, not zlib-sys); `bzip2-rs`; 7z's bzip2 via `libbz2-rs-sys` (a Rust
   port) with the C-linking `zstd` codec left as a non-default feature that is
   **not** enabled; `tar` with `default-features = false` to drop the `xattr`
   restore path. `core/Cargo.toml` documents each of these choices inline.

## Consequences

- Empirically backstopped by fuzzing: `fuzz/fuzz_targets/{fuzz_peel,fuzz_resolve,
  fuzz_archive}.rs` drive the untrusted-input surface with the invariant *never
  panic* — the README leads with "input-fuzzed" (measured) and qualifies the
  static half as "panic-free by lint," per the fleet's evidence-based robustness
  wording.
- No C toolchain is compiled or linked, so the crate cross-compiles cleanly and
  carries no C-supply-chain surface.
- The pure-Rust codecs pull a few non-Apache permissive licences (bzip2-1.0.6 for
  `libbz2-rs-sys`, MIT-0 for `ppmd-rust`); `deny.toml` allows exactly those with
  an inline rationale rather than dropping the codec — the batteries-included
  posture of ADR 0004.
