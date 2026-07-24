# 1. Two-crate reader/analyzer split (`archive-core` + `archive-forensic`)

Date: 2026-07-24
Status: Accepted

> Reverse-documented from the shipped repository (workspace layout, `Cargo.toml`
> manifests, and the fleet constitution). The record captures the rationale
> visible in the code and the fleet standard it follows.

## Context

The repository reads and audits packing/archive layers (gzip, bzip2, zip, 7z,
tar and their combinations) that wrap forensic evidence. The SecurityRonin fleet
constitution (`~/src/ronin-issen/CLAUDE.md`, "Crate-structure standard —
reader/analyzer split") mandates that every single-format artifact repo split
into two crates: a raw reader (`<x>-core`) that exposes structure without
judgement, and an anomaly auditor (`<x>-forensic`) that emits graded findings.
The reasoning in the standard: a reader is built to read *valid* data robustly,
so it abstracts away exactly the detail a forensic auditor must see (slack,
malformed fields, checksums it verifies-and-discards), and the auditor must be
free to see the raw, possibly-broken structure.

Archive-forensic is a single-format-family repo (Pattern A in the constitution's
"Crate naming grammar"), so it takes the two-crate shape rather than a
multi-crate suite.

## Decision

1. One workspace, two members (`Cargo.toml` `members = ["core", "forensic"]`):
   - **`core/` → crate `archive-core`** — the peel/archive-layer reader:
     `peel_bytes`, recursive `resolve`, `Archive` member reading, segment
     reassembly, and the phase-1 `detect` access-plan. No findings.
   - **`forensic/` → crate `archive-forensic`** — the anomaly auditor
     (extension-vs-content masquerade, CRC/declared-size lies, path-traversal
     member names, bomb signatures), depending on `archive-core`
     (`forensic/Cargo.toml` `archive-core.workspace = true`).
2. Keep the import path `archive_core` (`core/Cargo.toml` `[lib] name =
   "archive_core"`), so the crate publishes as `archive-core` while consumers
   write `use archive_core::…`.
3. `archive-forensic` is the headline repo name even though the workspace also
   holds the reader — per the standard, the analyzer names the repo.

## Consequences

- The reader is independently useful and publishable (`archive-core` on
  crates.io) for any consumer that only needs to peel layers, without pulling in
  audit logic.
- The audit surface can drop below `archive-core`'s happy-path API when it needs
  the raw structure (the constitution's "`-forensic` is NOT required to depend on
  `-core`" principle); today it depends on `archive-core`, matching the default.
- `archive-forensic` currently ships as a documented scaffold (`forensic/src/lib.rs`
  states "audits land as `archive-core`'s peel/tree surface grows") — the split is
  in place ahead of the full audit implementation, which is deliberate: the reader
  is the load-bearing dependency and lands first.
