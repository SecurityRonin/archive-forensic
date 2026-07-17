//! Member reading for ZIP (`.zip` / `.clbx`) via the fleet `zip-forensic-core`
//! reader. Byte-for-byte against a host-minted fixture — see
//! `tests/data/README.md`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use archive_core::{Archive, Format};

const FX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/fixtures/");

const A_TXT: &[u8] = b"alpha member contents\n";
const B_TXT: &[u8] = "beta member contents \u{2014} second file\n".as_bytes();
const C_TXT: &[u8] = b"gamma nested member\n";

fn load(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FX}{name}")).unwrap()
}

fn idx(a: &Archive, name: &str) -> usize {
    a.entries()
        .iter()
        .position(|e| e.name == name && !e.is_dir)
        .unwrap_or_else(|| panic!("member {name} not found in {:?}", a.entries()))
}

#[test]
fn reads_zip_members() {
    let mut a = Archive::open(&load("payload.zip"), Some("payload.zip"))
        .unwrap()
        .expect("payload.zip must open");
    assert_eq!(a.format(), Format::Zip);

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
    assert_eq!(a.entries()[ib].size, B_TXT.len() as u64);
}

#[test]
fn clbx_extension_opens_as_zip() {
    // `.clbx` (Cellebrite) is an ordinary ZIP; a zip payload named `.clbx`
    // opens as Zip by magic regardless of extension.
    let a = Archive::open(&load("payload.zip"), Some("evidence.clbx"))
        .unwrap()
        .expect("clbx-named zip must open");
    assert_eq!(a.format(), Format::Zip);
}

#[test]
fn zip_out_of_range_fails_loud() {
    let mut a = Archive::open(&load("payload.zip"), Some("payload.zip"))
        .unwrap()
        .unwrap();
    assert!(a.read(9999).is_err());
}
