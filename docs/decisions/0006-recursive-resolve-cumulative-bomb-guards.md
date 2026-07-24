# 6. Archive as a transparent layer: recursive `resolve` with cumulative bomb guards

Date: 2026-07-24
Status: Accepted

> Reverse-documented from `core/src/resolve.rs`, `core/src/lib.rs`,
> `core/src/peel.rs`, and commit `3e8c5cc` (the `detour` → `archive layer`
> rename).

## Context

Evidence arrives wrapped: `evidence.E01.gz`, `foo.tbz.zip`, `.gz.gz`,
`.tar.gz`-in-`.zip`. The design goal (README, `core/src/lib.rs`) is that an
archive is a **transparent optional layer** — `foo.E01.gz` must resolve
identically to `foo.E01`. Early commits framed this as a "detour" on the path to
the inner disk image (`peel_detour`, "determination model"); commit `3e8c5cc`
renamed the concept to "archive layer" (`peel_detour` → `peel_archive`, `Detour`
→ `Peel`) once it was clear the wrapper is a first-class layer to peel, not a
side-trip.

Two hazards shape the recursion:

- **Combinatorial nesting must not be special-cased.** Handling `foo.tbz.zip`
  with an `if this-exact-combo` branch would leave every sibling combination
  broken (the "No Special Cases" discipline).
- **Decompression bombs.** Nested or highly-compressible archives can exhaust RAM
  or disk. A bomb must fail loud, not silently fill memory.

## Decision

1. **Peel by construction, not by special case** (`core/src/resolve.rs`).
   `resolve` drives `peel_bytes` (one bare gzip/bzip2 layer → one re-detected
   inner stream) and `Archive` (each member re-detected) in one loop, so
   `zip → member foo.tbz → tar → leaf files` and every other nesting fall out of
   the same recursion. `sniff` re-runs on every inner stream (ADR 0002), and a
   peeled stream's name is stripped of one compression extension
   (`strip_compression_ext`) so it re-detects under its remaining name.
2. **Mandatory, cumulative bomb guards** (`Limits` in `core/src/resolve.rs`):
   `max_depth` (default 8), `max_total_inflated` (4 GiB, tracked **across the
   whole recursion**, not per layer), `max_entries` (1,000,000), and
   `max_index_bytes` (512 MiB, the per-member seek-index ceiling). A trip returns
   a typed loud error (`DepthExceeded`/`TooManyEntries`/`TotalInflatedExceeded`,
   `core/src/error.rs`) that names the offending cap and layer chain — verified by
   `nested_bomb_in_archive_member_propagates_error`. A single peel is also capped
   at `MAX_INFLATED` and reads one byte past the cap so an over-cap stream is
   *detected*, never silently truncated (`core/src/peel.rs`).

## Consequences

- Any new archive/codec added to `sniff` + `Archive` participates in nesting for
  free — no per-combination wiring.
- The default `Limits` are conservative for interactive use; a caller reassembling
  a genuinely large split image raises them explicitly, keeping the safe path the
  default.
- The bomb-guard budget is threaded through `resolve` and re-used by the phase-2
  executors (ADR 0008), so streaming access enforces the same caps as the
  materializing `resolve`.
