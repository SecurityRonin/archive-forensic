//! The unified disk-image detour: `peel_detour` peels a bare gz/bz2 wrapper OR
//! extracts the single member of a one-member archive to inner bytes, and leaves
//! a multi-member archive (a collection) as `NotPacked`. This is the entry point
//! the disk-forensic / 4n6mount consumers relocate onto.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use archive_core::{peel_detour, Detour, Limits};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::Write;

const FX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/fixtures/");

fn load(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FX}{name}")).unwrap()
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = GzEncoder::new(Vec::new(), Compression::fast());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

#[test]
fn peels_bare_bzip2_wrapper() {
    let expected = "archive-detour bzip2 test payload \u{2014} the quick brown fox\n"
        .repeat(30)
        .into_bytes();
    match peel_detour(
        &load("payload.bz2"),
        Some("payload.bz2"),
        &Limits::default(),
    )
    .unwrap()
    {
        Detour::Inner(inner) => assert_eq!(inner, expected),
        Detour::NotPacked => panic!("bare bzip2 with .bz2 name must peel"),
    }
}

#[test]
fn coincidental_magic_without_extension_is_not_packed() {
    // gzip magic but named `.raw` — the coincidental-magic guard must decline.
    let raw = gzip(b"inner raw image bytes that happen to be gzipped");
    // Rename intent: sniff sees gzip magic, but the name has no compression ext.
    match peel_detour(&raw, Some("disk.raw"), &Limits::default()).unwrap() {
        Detour::NotPacked => {}
        Detour::Inner(_) => panic!("must NOT peel a gzip-magic file named .raw"),
    }
}

#[test]
fn extracts_single_member_archive() {
    // oneimg.tgz holds exactly one member (disk.img) -> its bytes.
    match peel_detour(&load("oneimg.tgz"), Some("oneimg.tgz"), &Limits::default()).unwrap() {
        Detour::Inner(inner) => assert_eq!(
            inner,
            b"RAW-EVIDENCE-IMAGE-BYTES payload for the single-member detour\n"
        ),
        Detour::NotPacked => panic!("single-member archive must extract"),
    }
}

#[test]
fn multi_member_archive_is_not_packed() {
    // payload.zip has three members — a collection, not a wrapped image.
    match peel_detour(
        &load("payload.zip"),
        Some("payload.zip"),
        &Limits::default(),
    )
    .unwrap()
    {
        Detour::NotPacked => {}
        Detour::Inner(_) => panic!("multi-member archive must be left to the caller"),
    }
}

#[test]
fn plain_raw_is_not_packed() {
    let raw = b"\x00\x01\x02 not a wrapper or archive";
    assert!(matches!(
        peel_detour(raw, Some("disk.dd"), &Limits::default()).unwrap(),
        Detour::NotPacked
    ));
}

#[test]
fn over_cap_single_extract_fails_loud() {
    // A tiny total-inflated cap trips on the single member's bytes.
    let limits = Limits {
        max_total_inflated: 4,
        ..Limits::default()
    };
    assert!(peel_detour(&load("oneimg.tgz"), Some("oneimg.tgz"), &limits).is_err());
}
