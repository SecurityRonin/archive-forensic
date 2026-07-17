//! Recursive multi-layer peeling: `resolve` fully unpacks every nested packing
//! layer to a flat leaf-file list, with bomb guards. The headline case is
//! `nested.tbz.zip` (zip -> `.tbz` -> tar). Fixtures are host-minted; see
//! `tests/data/README.md`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use archive_core::{resolve, Limits, Node};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::Write;

const FX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/fixtures/");

const A_TXT: &[u8] = b"alpha member contents\n";
const B_TXT: &[u8] = "beta member contents \u{2014} second file\n".as_bytes();
const C_TXT: &[u8] = b"gamma nested member\n";

fn load(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FX}{name}")).unwrap()
}

fn files(nodes: &[Node]) -> Vec<(String, Vec<u8>)> {
    nodes
        .iter()
        .filter_map(|n| match n {
            Node::File { name, bytes } => Some((name.clone(), bytes.clone())),
            Node::Dir { .. } => None,
        })
        .collect()
}

fn find<'a>(fs: &'a [(String, Vec<u8>)], suffix: &str) -> &'a [u8] {
    &fs.iter()
        .find(|(n, _)| n.ends_with(suffix))
        .unwrap_or_else(|| panic!("no leaf ending in {suffix}"))
        .1
}

#[test]
fn resolves_nested_tbz_zip_to_leaf_files() {
    // zip -> member foo.tbz (bzip2 tar) -> tar members a.txt / b.txt / sub/c.txt
    let nodes = resolve(
        &load("nested.tbz.zip"),
        Some("nested.tbz.zip"),
        &Limits::default(),
    )
    .unwrap();
    let fs = files(&nodes);
    assert_eq!(find(&fs, "a.txt"), A_TXT);
    assert_eq!(find(&fs, "b.txt"), B_TXT);
    assert_eq!(find(&fs, "c.txt"), C_TXT);
}

#[test]
fn resolves_flat_zip() {
    let nodes = resolve(
        &load("payload.zip"),
        Some("payload.zip"),
        &Limits::default(),
    )
    .unwrap();
    let fs = files(&nodes);
    assert_eq!(find(&fs, "a.txt"), A_TXT);
    assert_eq!(find(&fs, "sub/c.txt"), C_TXT);
}

#[test]
fn resolves_flat_tgz() {
    let nodes = resolve(
        &load("payload.tgz"),
        Some("payload.tgz"),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(find(&files(&nodes), "b.txt"), B_TXT);
}

#[test]
fn resolves_double_gzip_bare_wrapper() {
    // leaf.txt.gz.gz peels twice to the raw leaf text.
    let nodes = resolve(
        &load("leaf.txt.gz.gz"),
        Some("leaf.txt.gz.gz"),
        &Limits::default(),
    )
    .unwrap();
    let fs = files(&nodes);
    assert_eq!(fs.len(), 1, "one leaf expected, got {fs:?}");
    assert_eq!(fs[0].1, b"double gzipped leaf payload\n");
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = GzEncoder::new(Vec::new(), Compression::fast());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

#[test]
fn depth_limit_trips_loud() {
    // Wrap a raw leaf in 10 bare-gzip layers; default max_depth is 8.
    let mut cur = b"deep".to_vec();
    for _ in 0..10 {
        cur = gzip(&cur);
    }
    let err = resolve(&cur, Some("bomb.gz"), &Limits::default()).unwrap_err();
    assert!(
        format!("{err}").contains("depth"),
        "expected a depth error, got: {err}"
    );
}

#[test]
fn entry_count_limit_trips_loud() {
    let limits = Limits {
        max_entries: 2,
        ..Limits::default()
    };
    // payload.zip has 3 members > 2.
    let err = resolve(&load("payload.zip"), Some("payload.zip"), &limits).unwrap_err();
    assert!(format!("{err}").contains("member count"), "got: {err}");
}

#[test]
fn total_inflated_limit_trips_loud() {
    let limits = Limits {
        max_total_inflated: 8, // smaller than any single member
        ..Limits::default()
    };
    let err = resolve(&load("payload.zip"), Some("payload.zip"), &limits).unwrap_err();
    assert!(format!("{err}").contains("inflated"), "got: {err}");
}

#[test]
fn non_packed_input_is_a_single_leaf() {
    let raw = b"just some raw evidence bytes \x00\x01";
    let nodes = resolve(raw, Some("disk.raw"), &Limits::default()).unwrap();
    assert_eq!(nodes.len(), 1);
    assert!(matches!(&nodes[0], Node::File { bytes, .. } if bytes == raw));
}
