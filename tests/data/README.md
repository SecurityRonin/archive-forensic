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

# single-member archive for the peel_detour single-image case
printf 'RAW-EVIDENCE-IMAGE-BYTES payload for the single-member detour\n' > disk.img
tar --format=ustar -cf oneimg.tar disk.img
gzip -n -c oneimg.tar > oneimg.tgz

# --- phase-1 detect() AccessPlan fixtures (plan.rs) ---
# zip access ladder: one Stored member -> InPlace, one Deflated member -> Zran.
head -c 4096 /dev/zero | tr '\0' 'A' > disk.dd
zip -0 -q -X stored_one.zip disk.dd
head -c 8192 /dev/zero | tr '\0' 'A' > big.dd
zip -9 -q -X deflate_one.zip big.dd

# segment sets (members added OUT of order to prove numeric ordering):
printf 'EWF-SEG-1\n' > img.E01; printf 'EWF-SEG-2\n' > img.E02; printf 'EWF-SEG-3\n' > img.E03
zip -0 -q -X seg_ewf.zip img.E03 img.E01 img.E02
printf 'RAW-1\n' > disk.001; printf 'RAW-2\n' > disk.002
zip -0 -q -X seg_split.zip disk.002 disk.001

# a zip member using a non-seekable codec (bzip2, method 12) -> SpillToTemp.
# The host `zip` lacks bzip2, so mint via Python's zipfile:
python3 -c "import zipfile; zipfile.ZipFile('bzip2_member.zip','w',zipfile.ZIP_BZIP2).writestr('blob.bin', b'Z'*4096)"
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
| `fixtures/oneimg.tgz` | single-member tar.gz (`disk.img`) | `detour.rs` (single-member detour) |
| `fixtures/payload.bz2` | bare bzip2 | `peel.rs`, `plan.rs` (bare-wrapper case) |
| `fixtures/stored_one.zip` | ZIP, one Stored member (`disk.dd`, 4096 B) | `plan.rs` (InPlace access) |
| `fixtures/deflate_one.zip` | ZIP, one Deflated member (`big.dd`, 8192 B) | `plan.rs` (Zran access) |
| `fixtures/seg_ewf.zip` | ZIP of `img.E01/E02/E03` (out of order) | `plan.rs` (SegmentSet Ewf) |
| `fixtures/seg_split.zip` | ZIP of `disk.001/002` (out of order) | `plan.rs` (SegmentSet SplitRaw) |
| `fixtures/bzip2_member.zip` | ZIP, one bzip2 (method 12) member (`blob.bin`) | `plan.rs` (SpillToTemp access) |
