//! Format determination: content magic decides the codec / container; the file
//! name is a secondary hint for the tar-compression aliases (`.tgz`→gzip+tar,
//! `.tbz2`→bzip2+tar) and the magic-absent cases.

/// A recognized packing format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Format {
    /// Bare gzip stream (a single compressed file, e.g. `disk.dd.gz`).
    Gzip,
    /// Bare bzip2 stream (a single compressed file, e.g. `disk.dd.bz2`).
    Bzip2,
    /// tar compressed with gzip (`.tgz` / `.tar.gz`) — a member list.
    TarGz,
    /// tar compressed with bzip2 (`.tbz2` / `.tar.bz2`) — a member list.
    TarBz2,
    /// ZIP archive — a member list.
    Zip,
    /// 7-Zip archive — a member list.
    SevenZip,
    /// Not a recognized packing layer.
    Unknown,
}

impl Format {
    /// A 1→1 bare compression wrapper that peels to a single inner byte stream.
    #[must_use]
    pub fn is_compression_wrapper(self) -> bool {
        matches!(self, Format::Gzip | Format::Bzip2)
    }

    /// A multi-member archive (tar.gz / tar.bz2 / zip / 7z).
    #[must_use]
    pub fn is_archive(self) -> bool {
        matches!(
            self,
            Format::TarGz | Format::TarBz2 | Format::Zip | Format::SevenZip
        )
    }
}

/// Determine the packing format. Container identity (zip / 7z) is decided by
/// **magic**; the tar-compression combos (`.tgz`/`.tbz2`) are distinguished from
/// bare gzip/bzip2 by the file **name** (the outer magic alone can't tell a
/// gzipped tar from a gzipped single file).
#[must_use]
pub fn sniff(name: Option<&str>, head: &[u8]) -> Format {
    // Containers with a definitive magic.
    if head.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        return Format::SevenZip;
    }
    if head.starts_with(b"PK\x03\x04") {
        return Format::Zip;
    }
    // Compression codecs: the name decides tar-inside vs bare single file.
    let lower = name.map(str::to_ascii_lowercase);
    let ends = |suf: &str| lower.as_deref().is_some_and(|n| n.ends_with(suf));
    if head.starts_with(&[0x1F, 0x8B]) {
        return if ends(".tgz") || ends(".tar.gz") {
            Format::TarGz
        } else {
            Format::Gzip
        };
    }
    if head.starts_with(b"BZh") {
        return if ends(".tbz2") || ends(".tar.bz2") {
            Format::TarBz2
        } else {
            Format::Bzip2
        };
    }
    // Magic silent → fall to the name (renamed / stripped-header cases).
    if ends(".7z") {
        return Format::SevenZip;
    }
    // `.clbx` is Cellebrite's extraction container — an ordinary ZIP (per the
    // published cellebrite-labs/clbx spec: files + msgpack metadata inside a ZIP).
    // Its CLBX-specific semantics are a higher layer; here it's read as a ZIP.
    if ends(".zip") || ends(".clbx") {
        return Format::Zip;
    }
    if ends(".tgz") || ends(".tar.gz") {
        return Format::TarGz;
    }
    if ends(".tbz2") || ends(".tar.bz2") {
        return Format::TarBz2;
    }
    if ends(".gz") {
        return Format::Gzip;
    }
    if ends(".bz2") {
        return Format::Bzip2;
    }
    Format::Unknown
}
