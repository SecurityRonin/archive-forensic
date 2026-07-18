//! Recursive multi-layer peeling. [`resolve`] drives [`crate::peel`] and
//! [`crate::Archive`] together so nested archive layers unwrap **by
//! construction**, not as special cases: a bare gzip/bzip2 wrapper peels to one
//! inner stream that is re-detected; each archive member is re-detected; any
//! member/stream that is itself a archive layer recurses. So `foo.tbz.zip`
//! resolves zip -> member `foo.tbz` -> tar -> leaf files, and `.gz.gz`,
//! `.tar.gz`-in-`.zip`, `.zip`-in-`.7z` all fall out of the same loop.
//!
//! Bomb guards are mandatory and cumulative across the whole recursion.

use crate::archive::Archive;
use crate::detect::sniff;
use crate::error::{ArchiveError, Result};
use crate::peel::{peel_bytes, PeelOutcome};

/// A leaf of a fully-resolved packing tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// A leaf file (not itself a recognized archive layer) and its bytes.
    File { name: String, bytes: Vec<u8> },
    /// A directory entry encountered inside an archive.
    Dir { name: String },
}

/// Bomb guards for [`resolve`]. Every field is a hard cap that fails loud when
/// tripped; the inflated-size cap is tracked cumulatively across all layers, not
/// per layer.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum nesting depth before giving up (archive-bomb nesting guard).
    pub max_depth: usize,
    /// Cumulative inflated bytes across the whole recursion.
    pub max_total_inflated: u64,
    /// Cumulative number of archive members across the whole recursion.
    pub max_entries: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_depth: 8,
            max_total_inflated: 4 << 30, // 4 GiB
            max_entries: 1_000_000,
        }
    }
}

/// Running totals enforced across the whole recursion.
struct Budget {
    total_inflated: u64,
    entries: usize,
}

impl Budget {
    fn add_inflated(&mut self, n: usize, limits: &Limits) -> Result<()> {
        self.total_inflated = self.total_inflated.saturating_add(n as u64);
        if self.total_inflated > limits.max_total_inflated {
            return Err(ArchiveError::TotalInflatedExceeded {
                cap: limits.max_total_inflated,
            });
        }
        Ok(())
    }

    fn add_entry(&mut self, limits: &Limits) -> Result<()> {
        self.entries = self.entries.saturating_add(1);
        if self.entries > limits.max_entries {
            return Err(ArchiveError::TooManyEntries {
                max: limits.max_entries,
            });
        }
        Ok(())
    }
}

/// Fully resolve `data` down through every archive layer to a flat list of leaf
/// files (and the directory entries seen along the way).
///
/// # Errors
/// A bomb-guard trip ([`ArchiveError::DepthExceeded`] /
/// [`ArchiveError::TooManyEntries`] / [`ArchiveError::TotalInflatedExceeded`]),
/// or any decode/open/read failure from an underlying layer.
pub fn resolve(data: &[u8], name: Option<&str>, limits: &Limits) -> Result<Vec<Node>> {
    let mut out = Vec::new();
    let mut budget = Budget {
        total_inflated: 0,
        entries: 0,
    };
    let chain = name.unwrap_or("<input>").to_string();
    resolve_into(data, name, limits, 0, &chain, &mut budget, &mut out)?;
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn resolve_into(
    data: &[u8],
    name: Option<&str>,
    limits: &Limits,
    depth: usize,
    chain: &str,
    budget: &mut Budget,
    out: &mut Vec<Node>,
) -> Result<()> {
    if depth > limits.max_depth {
        return Err(ArchiveError::DepthExceeded {
            max: limits.max_depth,
            chain: chain.to_string(),
        });
    }

    let format = sniff(name, data);

    if format.is_compression_wrapper() {
        // One bare gzip/bzip2 layer. peel_bytes is content-driven here (unlike
        // the disk archive layer): resolve unwraps everything it recognizes.
        let inner = match peel_bytes(data, name)? {
            PeelOutcome::Peeled { inner, .. } => inner,
            // cov:unreachable: is_compression_wrapper() guarantees a Peeled outcome
            PeelOutcome::NotPacked => {
                out.push(leaf(name, data));
                return Ok(());
            }
        };
        budget.add_inflated(inner.len(), limits)?;
        let inner_name = strip_compression_ext(name);
        let child = format!("{chain} -> {}", inner_name.as_deref().unwrap_or("<peeled>"));
        resolve_into(
            &inner,
            inner_name.as_deref(),
            limits,
            depth + 1,
            &child,
            budget,
            out,
        )?;
        return Ok(());
    }

    if format.is_archive() {
        let mut archive = Archive::open(data, name)?.ok_or_else(|| ArchiveError::Open {
            format: "archive",
            detail: format!("{format:?} sniffed as an archive but did not open"),
        })?;
        let members = archive.entries().to_vec();
        for (i, entry) in members.iter().enumerate() {
            budget.add_entry(limits)?;
            if entry.is_dir {
                out.push(Node::Dir {
                    name: entry.name.clone(),
                });
                continue;
            }
            let bytes = archive.read(i)?;
            budget.add_inflated(bytes.len(), limits)?;
            let child = format!("{chain} -> {}", entry.name);
            resolve_into(
                &bytes,
                Some(&entry.name),
                limits,
                depth + 1,
                &child,
                budget,
                out,
            )?;
        }
        return Ok(());
    }

    out.push(leaf(name, data));
    Ok(())
}

/// A leaf file node carrying `data`, named by the (possibly stripped) hint.
fn leaf(name: Option<&str>, data: &[u8]) -> Node {
    Node::File {
        name: name.unwrap_or_default().to_string(),
        bytes: data.to_vec(),
    }
}

/// Strip one trailing bare-compression extension from `name` after a peel, so
/// the inner stream is re-detected under its remaining name (`disk.dd.gz` ->
/// `disk.dd`). Leaves tar-alias names (`.tbz`/`.tgz`) intact — those inner
/// streams are re-detected by their `ustar` magic, not their name.
fn strip_compression_ext(name: Option<&str>) -> Option<String> {
    let name = name?;
    let lower = name.to_ascii_lowercase();
    for ext in [".gz", ".bz2", ".z"] {
        if lower.ends_with(ext) {
            return Some(name[..name.len() - ext.len()].to_string());
        }
    }
    Some(name.to_string())
}
