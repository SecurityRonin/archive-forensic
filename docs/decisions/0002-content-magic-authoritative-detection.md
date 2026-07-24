# 2. Content magic is authoritative for format; the file name is a secondary hint

Date: 2026-07-24
Status: Accepted

> Reverse-documented from `core/src/detect.rs` and its tests.

## Context

An evidence file's name lies. An analyst receives `evidence.gz` that is really a
7z container, `disk.dd.bz2` that is a bare single stream, or a renamed
`.tbz`/`.tb2`/`.tgz` short alias for a compressed tar. The reader must decide
what codec/container was *actually* applied, not what the extension claims — you
cannot gzip-decode bzip2 bytes, and mis-detection either crashes or produces
silent garbage.

But magic alone is insufficient in one direction: the outer gzip/bzip2 magic
(`1f 8b` / `BZh`) cannot distinguish a gzipped *tar* (a member list) from a
gzipped *single file* (a bare wrapper) — the tar structure only appears after
decompression. So the name is needed to route `.tgz`/`.tar.gz` and
`.tbz2`/`.tbz`/`.tb2` to the tar path.

## Decision

`sniff(name, head)` in `core/src/detect.rs` follows a fixed precedence:

1. **Container identity is decided by magic, both ways.** 7z (`37 7a bc af 27
   1c`), zip (`PK\x03\x04`), and uncompressed tar (`ustar` at offset 257) are
   recognized by content bytes regardless of name. `magic_beats_extension`
   asserts a `.gz`-named file with 7z magic sniffs as `SevenZip`.
2. **For the gzip/bzip2 codecs, the name distinguishes tar-inside from a bare
   single file.** `1f 8b` + a `.tgz`/`.tar.gz` name → `TarGz`; otherwise bare
   `Gzip`. `BZh` + a `.tar.bz2`/`.tbz2`/`.tbz`/`.tb2` name → `TarBz2`; otherwise
   bare `Bzip2`. The alias set lives in one place (`is_tar_bz2_name`) so the
   magic branch and the magic-silent fallback stay in sync.
3. **When magic is silent (renamed / stripped header), fall to the name** for
   `.7z`/`.zip`/`.clbx`/`.tar`/`.gz`/`.bz2` — so a peeled inner stream whose head
   is unrecognized is still routed by whatever name it carries.
4. `.clbx` (Cellebrite extraction container) reads as a ZIP here, per the
   published cellebrite-labs/clbx spec (files + msgpack metadata inside a ZIP);
   its CLBX-specific semantics are a higher layer.

The uncompressed-tar `ustar`-at-257 check is what lets a bare-compressed tar,
once peeled to its inner stream, be re-detected as a tar *even after its
`.tgz`/`.tbz` name was stripped* — the layered-recursion property (ADR 0006)
depends on it.

## Consequences

- A renamed or extension-stripped archive is still handled correctly; the file
  name is never trusted where the bytes can answer.
- The name is load-bearing for exactly one ambiguity (compressed-tar vs bare
  wrapper) that the outer magic genuinely cannot resolve — a documented, minimal
  reliance, not a general fallback to trusting names.
- Adding a codec whose magic is unambiguous (e.g. xz `FD 37 7A`) is a pure
  addition to the magic branch; see ADR 0006 consequences and
  `docs/plans/tar-xz-support.md` for the deferred `.tar.xz` scope.
