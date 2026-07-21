# Plan — add `.xz` / `.tar.xz` peel support to archive-core

**Status:** Proposed · **Size:** small (mirror `decode_gzip`; `lzma-rs` is already in the tree)

## Why
archive-core peels bare **gzip** and **bzip2** (`peel.rs`) and reads **zip/7z/tar**
member lists (`archive.rs`), but has **no `.xz`/`.tar.xz`** path — `Format` has no
`Xz`/`TarXz` variant, so xz bytes return `NotPacked` (a safe passthrough, but the
evidence isn't decoded). `.tar.xz` is one of the most common shapes for **Linux
evidence and malware samples**, so this is a real coverage gap (not a security one).

The decoder is **`lzma-rs` 0.3 (pure-Rust)** — already pulled transitively via
`sevenz-rust2`. Keep the pure-Rust posture: **do NOT** add `xz2`/`liblzma-sys` (a C
binding would reintroduce exactly the C memory-corruption class — cf. CVE-2026-14266,
a heap overflow in 7-Zip's C++ XZ handling; safe Rust deletes that class).

## Scope
1. **`detect.rs`** — add `Format::Xz` (bare) + `Format::TarXz`. Magic: `FD 37 7A 58 5A 00`
   (6 bytes) at offset 0. Name hints: `.xz`, `.tar.xz`, `.txz`. Keep the
   **coincidental-magic guard** (only peel when the name agrees, like gzip/bzip2).
2. **`peel.rs`** — `decode_xz(data) -> Result<Vec<u8>>`, wired as
   `Format::Xz => Peeled { format: Xz, inner: decode_xz(data)? }` in `peel_bytes`.
   `TarXz` peels xz → inner tar (the archive layer re-runs detection on the inner
   stream, same as `.tgz`/`.tbz2`).
3. **Fuzz** — once `decode_xz` is wired, `fuzz_peel` exercises it automatically
   (it already feeds arbitrary bytes); seed the corpus with a real `.xz` + a
   truncated one. Update the `fuzz_peel.rs` doc line to include xz.

## The one non-obvious detail — bomb guard differs from gzip/bzip2
`decode_gzip`/`decode_bzip2` wrap a **`Read`** decoder in `.take(MAX_INFLATED + 1)`.
`lzma-rs` is the opposite shape — **`lzma_rs::xz_decompress(&mut reader, &mut writer)`
decodes into a `Write` sink.** So the guard **cannot** use `.take()`, and must **not**
decode-then-check-`len()` (that allocates the full bomb output first → OOM, defeating
the guard). Instead pass a **capped `Write` wrapper** that counts bytes and returns an
error the moment output exceeds `MAX_INFLATED`, then map that to
`ArchiveError::TooLarge { cap: MAX_INFLATED }`. Sketch:

```rust
struct Capped<'a> { out: &'a mut Vec<u8>, cap: u64 }
impl Write for Capped<'_> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if self.out.len() as u64 + b.len() as u64 > self.cap {
            return Err(io::Error::new(io::ErrorKind::Other, "xz output exceeds cap"));
        }
        self.out.extend_from_slice(b); Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
```
Any `lzma-rs` decode error (truncated/malformed xz — the CVE-2026-14266 threat shape)
maps to `ArchiveError::Decode { format: "xz", detail }` — fail loud, never panic.

## Tests (Tier-2)
- Round-trip: `tar cJf` / `xz` a known payload → `peel_bytes` → bytes match.
- Truncated xz → `Err(Decode)` (not a panic).
- Over-cap: an xz stream that inflates past `MAX_INFLATED` → `Err(TooLarge)` **without**
  first allocating the full output (proves the capped-writer guard, not decode-then-check).

## Non-goals
Streaming / temp-spill for genuinely huge inner evidence — same as the existing
gzip/bzip2 4 GiB in-memory cap; that's the shared "next hardening step" noted in
`peel.rs`, tracked separately.
