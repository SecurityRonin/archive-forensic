//! Member reading for the tar family: plain `ustar`, `.tgz` (gzip), `.tbz2`
//! (bzip2). Byte-for-byte against fixtures minted on the host — see
//! `tests/data/README.md` for the exact mint commands.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use archive_core::{Archive, Format};

const FX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/fixtures/");

const A_TXT: &[u8] = b"alpha member contents\n";
const B_TXT: &[u8] = "beta member contents \u{2014} second file\n".as_bytes();
const C_TXT: &[u8] = b"gamma nested member\n";

fn load(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FX}{name}")).unwrap()
}

/// Find the entry index for a member name (skips directory entries).
fn idx(a: &Archive, name: &str) -> usize {
    a.entries()
        .iter()
        .position(|e| e.name == name && !e.is_dir)
        .unwrap_or_else(|| panic!("member {name} not found in {:?}", a.entries()))
}

fn assert_three_members(bytes: &[u8], name: &str, expect_fmt: Format) {
    let mut a = Archive::open(bytes, Some(name))
        .unwrap()
        .unwrap_or_else(|| panic!("{name} must open as an archive"));
    assert_eq!(a.format(), expect_fmt);

    let files: Vec<String> = a
        .entries()
        .iter()
        .filter(|e| !e.is_dir)
        .map(|e| e.name.clone())
        .collect();
    for want in ["a.txt", "b.txt", "sub/c.txt"] {
        assert!(files.iter().any(|n| n == want), "missing member {want}");
    }

    let ia = idx(&a, "a.txt");
    let ib = idx(&a, "b.txt");
    let ic = idx(&a, "sub/c.txt");
    assert_eq!(a.read(ia).unwrap(), A_TXT);
    assert_eq!(a.read(ib).unwrap(), B_TXT);
    assert_eq!(a.read(ic).unwrap(), C_TXT);

    // Declared sizes match the extracted bytes.
    assert_eq!(a.entries()[ia].size, A_TXT.len() as u64);
    assert_eq!(a.entries()[ib].size, B_TXT.len() as u64);
}

#[test]
fn reads_plain_tar_members() {
    assert_three_members(&load("payload.tar"), "payload.tar", Format::Tar);
}

#[test]
fn reads_tgz_members() {
    assert_three_members(&load("payload.tgz"), "payload.tgz", Format::TarGz);
}

#[test]
fn reads_tbz2_members() {
    assert_three_members(&load("payload.tbz2"), "payload.tbz2", Format::TarBz2);
}

#[test]
fn out_of_range_index_fails_loud() {
    let mut a = Archive::open(&load("payload.tar"), Some("payload.tar"))
        .unwrap()
        .unwrap();
    assert!(a.read(9999).is_err());
}

#[test]
fn non_archive_returns_none() {
    let raw = b"not an archive at all \x00\x01\x02";
    assert!(Archive::open(raw, Some("disk.raw")).unwrap().is_none());
}
