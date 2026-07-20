# Validation

How archive-core's correctness is established, and the honest limits of that
evidence.

## Approach — read back what a reference packer wrote

archive-core is a *reader*: the ground truth for "did we peel/decompress this
correctly" is the exact member bytes a canonical, widely-used packing tool wrote.
Every fixture under `tests/data/fixtures/` is minted on the host by the reference
implementation for its format, and each test asserts that archive-core reproduces
the packed input **byte-for-byte**:

| format | reference packer (oracle) | test |
|---|---|---|
| tar (`ustar`) | GNU `tar --format=ustar` | `core/tests/archive_tar.rs` |
| tar.gz (`.tgz`) | GNU `tar` + `gzip -n` | `core/tests/archive_tar.rs`, `resolve.rs` |
| tar.bz2 (`.tbz2`) | GNU `tar` + `bzip2` | `core/tests/archive_tar.rs` |
| zip (Deflate / Stored) | Info-ZIP `zip -X` / `zip -0` / `zip -9` | `core/tests/archive_zip.rs`, `plan.rs` unit tests |
| zip (bzip2 member, method 12) | Python `zipfile.ZIP_BZIP2` | `plan.rs` unit tests |
| 7z (LZMA2) | 7-Zip `7zz a` | `core/tests/archive_7z.rs` |
| gzip / bzip2 bare wrapper | `gzip -n`, `bzip2` | `peel.rs` unit tests, `core/tests/archive_layer.rs` |
| nested (zip → `.tbz` → tar) | the tools above, composed | `core/tests/resolve.rs` |

The known member contents (three files, including a member whose name is a U+2014
em-dash and whose bytes are UTF-8) and the **verbatim mint commands** are recorded
in [`tests/data/README.md`](https://github.com/SecurityRonin/archive-forensic/blob/main/tests/data/README.md),
so a clean clone can regenerate the corpus and reproduce the assertions.

### Evidence tier

This is a **tier-2** validation in the fleet's rigor scale: the artifacts are
produced by real, third-party reference packers (GNU tar, Info-ZIP, 7-Zip,
CPython) — not fixtures hand-encoded to the reader's own assumptions — and the
ground truth is derivable from the documented construction. It is short of tier-1
(a downloaded third-party corpus with an externally-authored answer key), which is
the next hardening step for the recursive-`resolve` and segment-reassembly paths.

## Robustness — fuzzing the untrusted-input surface

archive-core parses attacker-controllable archives, so the parse entry points are
fuzzed with `cargo-fuzz` (`fuzz/`), invariant *never panic*:

| target | entry point exercised |
|---|---|
| `fuzz_peel` | `peel_bytes` — single-layer peel of arbitrary bytes |
| `fuzz_resolve` | `resolve` — the full recursive peel under bomb-guard `Limits` |
| `fuzz_archive` | `Archive::open` + `member_access` + `read` |

`.github/workflows/fuzz.yml` smoke-runs each target on every push/PR touching the
parser or harness, and for ten minutes on a weekly schedule. Local smoke runs
complete ~0.8–1.4 M executions per target with no crash. Fuzzing demonstrates
present-robustness over the executed inputs; it does not prove the absence of all
panics — the paired static guarantee is the `unwrap_used` / `expect_used = deny`
lint posture plus `forbid(unsafe)`.

## Bomb guards

`resolve` enforces cumulative caps across the whole recursion — max nesting depth,
max total inflated bytes, max member count, and a per-member index-size ceiling
that falls back to a one-time temp spill. Each cap fails loud (a typed error), and
the failure paths are covered by the `*_limit_trips_loud` tests in
`core/tests/resolve.rs`.

## Coverage

CI enforces a workspace line-coverage **floor** (`cargo llvm-cov`), set at the
honestly-achieved level while the codec/analyzer surface is built out
incrementally, as a regression backstop rather than a 100%-for-its-own-sake target.
