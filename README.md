# archive-forensic

Pure-Rust, `forbid(unsafe)`, read-only **archive-layer** reader and auditor. An
archive is a transparent optional *archive layer*: `evidence.E01.gz` resolves
identically to `evidence.E01`. `archive-core` peels gzip/bzip2/xz/zip/7z/tar
layers (reusing `zip-forensic-core` and `sevenzip-core`), determining the format
by **content magic** (authority for the codec) with the file name as a secondary
hint for aliases (`.tgz`/`.tbz2`) and the magic-absent formats.

- **`archive-core`** — the peel/archive-layer reader + format detection.
- **`archive-forensic`** — the analyzer: extension-vs-content masquerade,
  declared-size lies, path-traversal names, decompression-bomb findings.

Status: under active TDD construction (gzip peel wired; more codecs follow).

[Privacy Policy](https://securityronin.github.io/archive-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/archive-forensic/terms/) · © 2026 Security Ronin Ltd
