# 8. Two-phase, seekable/streaming access: detect → execute → reassemble

Date: 2026-07-24
Status: Accepted

> Reverse-documented from `core/src/plan.rs`, `core/src/execute.rs`,
> `core/src/reassemble.rs`, and `core/src/archive.rs`. This is the ADR the module
> headers already cite as "ADR 0008"; the record was reverse-written to match
> those in-code cross-references.

## Context

The initial peel path (`peel_bytes`, `Archive::read`) materializes the inner
stream as a whole `Vec<u8>`. That is fine for a small member but wrong for the
target workload: the inner evidence is often a multi-GiB disk image
(`evidence.E01.gz`, an `E01` split across zip members). Materializing a 40 GiB
image into RAM — or even one temp copy when the member is stored uncompressed and
could be read in place — defeats the point of a forensic reader.

Two properties are wanted before touching any payload:

- **Classify the most-direct route without decompressing.** A stored zip member
  can be windowed zero-copy; a Deflate member can be randomly accessed via a
  checkpoint index; only a genuinely non-seekable codec must spill to temp. That
  decision comes from the archive's own member *table*, not from inflating.
- **Present a segmented image as one logical seekable stream** (`.001/.002`, EWF
  `.E01/.E02`, split VMDK `-s001/-s002`).

## Decision

A two-phase architecture, each phase a module:

1. **Phase 1 — `detect` (`core/src/plan.rs`): content-authoritative, name-free
   classification.** `detect(data)` reads only bounded decompressed heads
   (`HEAD_PEEK = 512`, reaching the tar `ustar` magic at 257) and the archive's
   member table — never a payload — and returns an `AccessPlan`
   (`Direct`/`Wrapper`/`Member`/`SegmentSet`/`Collection`). Per-member/-segment
   access is chosen most-seekable-first (`member_access` in `core/src/archive.rs`):
   `Access::InPlace` (stored → zero-copy sub-range), `Access::Zran`
   (Deflate/Deflate64 → checkpoint seek index), `Access::SpillToTemp` (non-seekable
   codec or no in-archive offset).
2. **Phase 2 — `peel_archive_seekable` (`core/src/execute.rs`): execute the plan
   as a seekable handle, never a whole-image `Vec`.** `InPlace` → a zero-copy
   `SubRange` over the shared `Arc<Vec<u8>>`; `Zran` → a checkpoint-indexed handle
   that decodes only the block(s) around the target offset (falling back to
   `SpillToTemp` when the index would exceed `max_index_bytes`); `SpillToTemp` → a
   single streamed decode to an RAII-deleted temp file (`TempBacked`). Every
   extraction is capped at `limits.max_total_inflated` and fails loud with
   `TooLarge` (the ADR 0006 budget).
3. **Phase 4 — `reassemble` (`core/src/reassemble.rs`): `SegmentSet` → one
   logical seekable source.** `SplitRaw` (`.001/.002`) is a byte-for-byte
   concatenation, stitched fully in-repo by `ConcatSource` (logical offset →
   `(segment, local offset)`). `Ewf`/`SplitVmdk` are **not** a raw concatenation
   (each `.E0N` carries its own header/section structure), so archive-core stops
   at exposing the ordered per-segment `PeeledSource` handles (`segment_sources`);
   the container reader consumes them through its own multi-segment backing.

## Consequences

- A stored inner image is read with **zero decompression and zero copy**; a
  Deflate image with **no full inflate and no RAM/temp materialization**; only a
  truly non-seekable codec pays a one-time temp spill. This is the streaming
  hardening the early in-memory peel deferred (`core/src/lib.rs`,
  `core/src/peel.rs` TODOs).
- Phase 1 and the legacy `peel_archive` executor coexist deliberately
  (`core/src/plan.rs` header) — the phased path is additive, not a rewrite.
- **A clean zero-copy EWF wiring is already possible on the `ewf` side**:
  `ewf::SegmentSource` carries a `Backing(Arc<dyn SegmentBacking>)` variant
  (shipped 2026-06-29, `ewf` commit `bc0bc46`) — an arbitrary boxed positioned
  reader (`read_at` + `len`) — so a zran-backed or windowed in-RAM `PeeledSource`
  can flow into `EwfReader::open_from_sources` without materializing each segment
  as `Mem` (an `Arc<[u8]>`) and without a full inflate, preserving the zero-spill
  zran path. `core/src/reassemble.rs` describes this `SegmentBacking` seam.
  archive-core still deliberately stops at the ordered handles rather than depend
  on a CONTAINER crate — depending on `ewf` here would invert the layer direction
  (the archive layer sits below CONTAINER readers, per the fleet layer hierarchy).
  The adapter that wraps a `PeeledSource` in `ewf::SegmentSource::Backing` lives
  in the consumer (disk-forensic / forensic-vfs-engine).
