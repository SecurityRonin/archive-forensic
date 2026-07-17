# archive-forensic test fixtures

Small, committed archive fixtures with **known** member contents, used by the
`core/tests/*` byte-for-byte member-reading and recursive-`resolve` tests. All
are minted on the host (see the exact commands below); nothing here is a
downloaded third-party artifact. Cross-referenced by the fleet catalog
[`issen/docs/corpus-catalog.md`](../../../issen/docs/corpus-catalog.md).

Classification: `SYNTHETIC` (host-minted, `~` inferred ground truth = the input
files we packed).

## Known member contents

Three source files are packed into every multi-member fixture:

| member | bytes (exact) |
|---|---|
| `a.txt` | `alpha member contents\n` |
| `b.txt` | `beta member contents — second file\n` (the dash is U+2014, UTF-8) |
| `sub/c.txt` | `gamma nested member\n` |

## Mint commands

Run in a scratch dir holding the three files above (`sub/` created for `c.txt`):

```sh
printf 'alpha member contents\n'                > a.txt
printf 'beta member contents \342\200\224 second file\n' > b.txt   # \342\200\224 = U+2014
mkdir sub && printf 'gamma nested member\n'      > sub/c.txt

# tar family
tar --format=ustar -cf payload.tar a.txt b.txt sub/c.txt
gzip  -n -k -c payload.tar > payload.tgz
bzip2    -k -c payload.tar > payload.tbz2

# zip + 7z
zip -q -X payload.zip a.txt b.txt sub/c.txt
7zz a -bso0 -bsp0 payload.7z a.txt b.txt sub/c.txt      # LZMA2 (7-Zip default)

# recursive nesting: a bzip2 tar (named .tbz), then zipped -> nested.tbz.zip
bzip2 -k -c payload.tar > foo.tbz
zip -q -X nested.tbz.zip foo.tbz

# double compression wrapper for resolve (.gz.gz -> leaf)
printf 'double gzipped leaf payload\n' > leaf.txt
gzip -n -c leaf.txt | gzip -n -c > leaf.txt.gz.gz
```

## Files

| file | format | consumed by |
|---|---|---|
| `fixtures/payload.tar` | plain `ustar` tar | `archive_tar.rs` |
| `fixtures/payload.tgz` | gzip tar | `archive_tar.rs`, `resolve.rs` |
| `fixtures/payload.tbz2` | bzip2 tar | `archive_tar.rs` |
| `fixtures/payload.zip` | ZIP (Deflate) | `archive_zip.rs`, `resolve.rs` |
| `fixtures/payload.7z` | 7z (LZMA2) | `archive_7z.rs`, `resolve.rs` |
| `fixtures/nested.tbz.zip` | ZIP → `.tbz` → tar | `resolve.rs` (the multi-layer case) |
| `fixtures/leaf.txt.gz.gz` | gzip(gzip(text)) | `resolve.rs` (double bare wrapper) |
| `fixtures/payload.bz2` | bare bzip2 | `peel.rs` (pre-existing) |
