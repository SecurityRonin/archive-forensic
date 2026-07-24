# 7. Optional `forensic-vfs` `ArchiveOpen` adapter behind a `vfs` feature

Date: 2026-07-24
Status: Accepted

> Reverse-documented from `core/src/vfs.rs`, `core/Cargo.toml` (`[features]`),
> and commit `2865353` ("add forensic-vfs ArchiveOpen adapter behind `vfs`
> feature").

## Context

The fleet's universal container abstraction (`~/src/ronin-issen/CLAUDE.md`, "VFS &
Universal Container Abstraction") requires that a consumer reading an evidence
image not know one container/filesystem format from another — it asks the
`forensic-vfs` resolver to open a path and gets back a uniform byte source. For
archives to be a *first-class resolution layer* in that engine (so
`E01 → GPT → NTFS` inside a `.zip` reads as one stack), archive-core must
implement the `forensic-vfs` `ArchiveOpen` contract.

But not every consumer of `archive-core` wants the `forensic-vfs` dependency. A
tool that only needs to peel a `.gz` should get a dependency-light reader — the
batteries-included standard's one sanctioned exception is a genuinely optional,
rarely-wanted integration kept off the default path.

## Decision

1. **Implement `ArchiveOpen` as `ArchiveOpener`** (`core/src/vfs.rs`), a
   zero-state delegator that owns no new archive logic: `probe` delegates to
   `sniff` (name-blind, magic-only — the window carries only bytes) and `open`
   delegates to `peel_bytes` (bare wrapper → one `ArchiveContents::Stream`, 1→1)
   and `Archive` (multi-member → `ArchiveContents::Members`, 1→N).
2. **Gate it behind an off-by-default `vfs` feature** (`core/Cargo.toml`
   `vfs = ["dep:forensic-vfs"]`; `forensic-vfs` is `optional = true`), so a bare
   reader stays dependency-light and only a consumer wiring the VFS engine pulls
   `forensic-vfs`.
3. **Keep detection content-authoritative in the adapter** (the opener never sees
   a file name), so a `.tar.gz` presented nameless resolves as a gzip stream whose
   decoded tar re-enters resolution and matches the `ustar` magic — the layered
   model of ADR 0006, not a special case.

## Consequences

- Archives plug into the fleet's format-agnostic VFS resolver without any
  consumer special-casing an `if archive { … }` branch.
- Member bytes are extracted into memory today (matching `Archive::read`); a
  seekable, temp/zran-backed `ImageSource` per member is a documented future
  seam. The enabling change is noted inline in `open` (`execute_member_access`
  is `pub(crate)`; a public "list members as seekable sources" API would remove
  the materialization) — this is the phase-2/3 executor of ADR 0008 reaching the
  VFS boundary.
- A `forensic-vfs` major-version bump only affects consumers building `--features
  vfs`; the default reader is insulated from that churn.
