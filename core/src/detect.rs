//! Format determination: content magic is the authority for the compression
//! codec; the file name is a secondary hint (aliases + the magic-absent
//! formats).

/// A recognized outer packing format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Format {
    // Compression wrappers (1 → 1: peel to a single inner stream).
    Gzip,
    Bzip2,
    Xz,
    Zstd,
    Compress,
    // Containers (member lists).
    Zip,
    SevenZip,
    Tar,
    /// Not a recognized packing layer.
    Unknown,
}

impl Format {
    /// A 1→1 compression wrapper that peels to a single inner byte stream.
    #[must_use]
    pub fn is_compression_wrapper(self) -> bool {
        matches!(
            self,
            Format::Gzip | Format::Bzip2 | Format::Xz | Format::Zstd | Format::Compress
        )
    }
}

/// Determine the outer packing format. Content **magic** decides the codec
/// (definitive for compression wrappers + 7z); the file **name** is consulted
/// only for aliases and the magic-absent formats (POSIX tar has a magic; old
/// v7 tar and self-extracting zip do not — those lean on the name).
#[must_use]
pub fn sniff(name: Option<&str>, head: &[u8]) -> Format {
    if head.starts_with(&[0x1F, 0x8B]) {
        return Format::Gzip;
    }
    if head.starts_with(b"BZh") {
        return Format::Bzip2;
    }
    if head.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
        return Format::Xz;
    }
    if head.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
        return Format::Zstd;
    }
    if head.starts_with(&[0x1F, 0x9D]) {
        return Format::Compress;
    }
    if head.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        return Format::SevenZip;
    }
    if head.starts_with(b"PK\x03\x04") {
        return Format::Zip;
    }
    // POSIX/ustar tar: magic at offset 257.
    if head.len() >= 262 && &head[257..262] == b"ustar" {
        return Format::Tar;
    }
    // Magic silent → fall to the name (aliases + v7-tar / SFX-zip).
    name.and_then(format_from_extension)
        .unwrap_or(Format::Unknown)
}

/// Map a file name's (compound) extension to a format. Alias-aware:
/// `.tgz`/`.taz`→gzip, `.tbz`/`.tbz2`→bzip2, `.txz`→xz, `.tzst`→zstd,
/// `.tlz`→xz/lzma — each also implying a tar inside.
fn format_from_extension(name: &str) -> Option<Format> {
    let lower = name.to_ascii_lowercase();
    let table = [
        (".tgz", Format::Gzip),
        (".taz", Format::Gzip),
        (".tbz2", Format::Bzip2),
        (".tbz", Format::Bzip2),
        (".txz", Format::Xz),
        (".tzst", Format::Zstd),
        (".tlz", Format::Xz),
        (".gz", Format::Gzip),
        (".bz2", Format::Bzip2),
        (".xz", Format::Xz),
        (".zst", Format::Zstd),
        (".z", Format::Compress),
        (".7z", Format::SevenZip),
        (".zip", Format::Zip),
        (".tar", Format::Tar),
    ];
    table
        .into_iter()
        .find(|(suf, _)| lower.ends_with(suf))
        .map(|(_, f)| f)
}
