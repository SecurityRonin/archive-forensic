# archive-forensic — Design: Purpose & Scope

> This is a **library** design note, not a product PRD. `archive-forensic` ships
> no binary an examiner runs; it is a pair of crates other fleet code links.
> For the decision records behind the choices below, see
> [`docs/decisions/`](decisions/).

## Purpose

Peel every archive/compression layer that wraps forensic evidence so a consumer
reaches the inner artifact, and audit the layers for the ways they lie about what
they hold. The organizing idea: **an archive is a transparent optional layer** —
`evidence.E01.gz` must read exactly like `evidence.E01` (ADR 0006).

Two crates:

- **`archive-core`** — a pure-Rust, `forbid(unsafe)`, read-only reader that peels
  gzip / bzip2 / zip / 7z / tar layers (and their combinations) to reach the
  inner stream, choosing the codec by **content magic** with the file name as a
  secondary hint (ADR 0002). It exposes single-layer `peel_bytes`, recursive
  `resolve` with cumulative decompression-bomb guards, per-archive member reading
  via `Archive`, the phase-1 `detect` access-plan and phase-2 seekable executors,
  and split/segment reassembly.
- **`archive-forensic`** — the anomaly auditor layered over `archive-core`:
  extension-vs-content masquerade, CRC / declared-size lies, path-traversal member
  names, and decompression-bomb signatures. It currently ships as a documented
  scaffold; audits land as `archive-core`'s tree API grows (ADR 0001).

## Who links it

- **`forensic-vfs-engine` / `disk-forensic`** — register `archive-core`'s
  `ArchiveOpener` (behind the `vfs` feature, ADR 0007) so archives resolve as a
  first-class layer in the universal container abstraction; a stacked
  `E01 → filesystem` inside a `.zip` reads as one source.
- **Orchestration (Issen) and any consumer** peeling nested evidence — via
  `resolve` for a flat leaf list, or the phase-1/2 `detect` + `peel_archive_seekable`
  path for large images read without full materialization.

## What it does

- **Detects** the applied codec/container from magic, using the name only for the
  compressed-tar-vs-bare-wrapper ambiguity magic cannot resolve, and for
  magic-silent renamed inputs (ADR 0002).
- **Peels** one layer (`peel_bytes`) or recurses through every nested layer
  (`resolve`), unwrapping arbitrary nestings (`.tbz.zip`, `.gz.gz`,
  `.tar.gz`-in-`.zip`) by construction rather than by special case (ADR 0006).
- **Reads members** of tar / zip / 7z archives by reusing the fleet
  `zip-forensic-core` reader and `sevenz-rust2`, never reimplementing a codec
  (ADR 0004).
- **Classifies then executes** the most-direct access route (stored → zero-copy
  window, Deflate → zran seek index, else → temp spill) so a multi-GiB inner
  image is read seekably without a whole-image `Vec` (ADR 0008).
- **Reassembles** a segmented image (`.001/.002`, EWF `.E01/.E02`, split VMDK)
  into one logical seekable source (ADR 0008).
- **Fails loud** on every malformed input, bomb-guard trip, or lying
  offset/size — typed `ArchiveError`, never a silent truncation (ADR 0003, 0006).

## Scope

In scope: gzip, bzip2, uncompressed tar, `.tar.gz`/`.tgz`, `.tar.bz2`/`.tbz2`/
`.tbz`/`.tb2`, zip (`.zip`/`.clbx`), and 7z — as read-only archive layers over
evidence; recursive resolution with bomb guards; content-authoritative detection;
seekable/streaming access; split/segment reassembly; and the anomaly-audit surface
over all of the above.

## Non-goals

- **No writing / repacking.** Read-only by construction; the reader never mutates
  or emits an archive.
- **`.tar.xz` / bare xz is deferred**, not supported. Early work added an xz peel
  (`c8202f2`) then commit `d843a25` scoped `archive-core` to
  `{.7z,.tgz,.tbz2,.zip,.clbx}` and dropped xz plus speculative aliases (YAGNI);
  the re-introduction plan is [`docs/plans/tar-xz-support.md`](plans/tar-xz-support.md).
- **No filesystem or container parsing.** Archive-core hands back the inner byte
  stream; decoding an inner disk container (EWF/VMDK) or filesystem is a higher
  layer's job — reaching into `ewf` from here would invert the fleet layer
  direction (ADR 0008).
- **No CLI / GUI / MCP front-end.** The examiner-facing surface is `disk4n6` /
  Issen; this repo is linked, not run.
- **CLBX-specific semantics are out of scope** — `.clbx` is read as the ZIP it is;
  its Cellebrite msgpack metadata is a higher layer (ADR 0002).

## Validation approach

Fixtures are minted by reference tools (GNU tar, Info-ZIP, 7-Zip, CPython) and
read back byte-for-byte, so correctness is checked against independent encoders
rather than self-encoded round-trips — see [`docs/validation.md`](validation.md)
and `tests/data/README.md`. The untrusted-input parse surface (`peel_bytes`,
`resolve`, `Archive::open`/`read`) is driven by `cargo-fuzz` targets under
`fuzz/fuzz_targets/` with the invariant *never panic* (ADR 0003).
