//! Every other guard in this directory is workspace-member-scoped. This one
//! measures what they cannot see.
//!
//! `architecture_secret_types` asserts `PLAINTEXT_AUTH_SITE_BUDGET == 0` and
//! `architecture_process_execution` pins the unsandboxed-spawn allowlist. Both
//! walk `[workspace] members` — which is correct for what they enforce, and
//! easy to read as a claim about the repository. It is not one.
//!
//! Outside those members sit forty top-level trees, ~1200 Rust files, ~98
//! `Command::new` sites and ~89 lines attaching a credential in plaintext. A
//! reader who sees "plaintext auth sites: 0" and concludes the repository has
//! none is wrong by about ninety.
//!
//! This file does not fix any of that. Deleting or adopting those trees is a
//! product decision — several cannot build standalone, and some are plainly
//! work in progress. What it does is stop the surface from growing silently
//! and make the scope of the other budgets explicit, so "0" is read as
//! "0 among the code CI compiles" rather than "0 anywhere".

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Top-level directories holding Rust sources that no workspace member owns.
///
/// Pinned by name rather than by file count: file counts churn with every
/// edit inside these trees, which would make this test a nuisance without
/// telling anyone anything. A *new tree* is the event worth failing on —
/// it means a subsystem was added that no guard in this directory inspects.
const KNOWN_NON_MEMBER_TREES: &[&str] = &[
    "avid",
    "avid-anticlone-service",
    "avid-rstdp",
    "avid-soullink",
    "backlog",
    "intel-integrations",
    "jit-agentic-engine",
    "neural-store",
    "soulsystem-gateway",
    "openevolve",
    "scirust-bench-schema",
    "scirust-chronos-agent",
    "scirust-cuda",
    "scirust-gpu",
    "scirust-license",
    "scirust-multivariate",
    "scirust-solvers",
    "scirust-special",
    "scirust-stats",
    "scirust-trading",
    "scirust-trading-engine",
    "scirust-trading-monitor",
    "scirust-trading-news",
    "scirust-trading-observer",
    "scirust-trading-persistence",
    "scirust-trading-pipeline",
    "scirust-units",
    "soul-cognition",
    "soul-neural",
    "soul-project",
    "soul-rsi",
    "soul-scheduler",
    "soullink-brain",
    "soullink-node",
    "turboquant",
    "turbovec",
];

/// Workspace members, plus the root crate's own directories.
///
/// `src`, `tests` and `benches` belong to the root package, which is not
/// listed in `members` because it is the workspace root itself. Omitting them
/// would report the root crate — the most heavily guarded code here — as
/// unguarded, and the first version of this scan did exactly that.
fn member_prefixes() -> BTreeSet<String> {
    let manifest = std::fs::read_to_string(repo_root().join("Cargo.toml"))
        .expect("root Cargo.toml is readable");
    let start = manifest
        .find("members = [")
        .expect("root manifest declares workspace members");
    let block = &manifest[start..];
    let block = &block[..block.find(']').expect("members list is closed")];

    let mut prefixes: BTreeSet<String> = block
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with('#') {
                return None;
            }
            let start = line.find('"')? + 1;
            let end = line[start..].find('"')? + start;
            Some(line[start..end].to_string())
        })
        .collect();

    for root_owned in ["src", "tests", "benches"] {
        prefixes.insert(root_owned.to_string());
    }
    prefixes
}

fn is_member_path(rel: &str, prefixes: &BTreeSet<String>) -> bool {
    prefixes
        .iter()
        .any(|p| rel == p || rel.starts_with(&format!("{p}/")))
}

/// Walk the repo, returning top-level trees that contain non-member Rust code.
fn non_member_trees() -> BTreeSet<String> {
    let prefixes = member_prefixes();
    let root = repo_root();
    let mut trees = BTreeSet::new();
    let mut stack = vec![root.clone()];

    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(rel) = path.strip_prefix(&root) else {
                continue;
            };
            let rel = rel.to_string_lossy().replace('\\', "/");
            let name = entry.file_name().to_string_lossy().to_string();

            if path.is_dir() {
                if matches!(name.as_str(), "target" | ".git" | "node_modules" | "vendor")
                    || name.starts_with('.')
                {
                    continue;
                }
                stack.push(path);
            } else if name.ends_with(".rs") && !is_member_path(&rel, &prefixes) {
                if let Some(top) = rel.split('/').next() {
                    trees.insert(top.to_string());
                }
            }
        }
    }
    trees
}

/// No new unguarded tree appears without someone saying so.
#[test]
fn the_non_member_surface_does_not_grow_silently() {
    let found = non_member_trees();
    let known: BTreeSet<String> = KNOWN_NON_MEMBER_TREES
        .iter()
        .map(|s| s.to_string())
        .collect();

    let added: Vec<&String> = found.difference(&known).collect();
    assert!(
        added.is_empty(),
        "new top-level trees hold Rust code that no workspace member owns: \
         {added:?}. Nothing in tests/architecture_*.rs inspects them — not the \
         plaintext-credential scan, not the unsandboxed-spawn allowlist, not \
         the secret-type migration. Either add the crate to [workspace] \
         members so the guards cover it, or add it here with a reason."
    );
}

/// The ratchet: trees that leave must be removed from the list.
///
/// Without this, deleting or adopting a tree would leave a stale entry, and
/// the list would slowly stop describing anything — the same way an allowlist
/// rots when its entries outlive their reason.
#[test]
fn the_known_list_has_no_stale_entries() {
    let found = non_member_trees();
    let stale: Vec<&&str> = KNOWN_NON_MEMBER_TREES
        .iter()
        .filter(|t| !found.contains(**t))
        .collect();

    assert!(
        stale.is_empty(),
        "these trees are listed as non-member but no longer hold non-member \
         Rust code: {stale:?}. They were deleted or adopted into the \
         workspace; remove them from KNOWN_NON_MEMBER_TREES."
    );
}

/// The scan reaches real files rather than passing on an empty walk.
#[test]
fn the_scan_actually_finds_the_workspace() {
    let prefixes = member_prefixes();
    assert!(
        prefixes.len() > 50,
        "only {} workspace members parsed; the manifest parsing broke and \
         every test here would pass vacuously",
        prefixes.len()
    );
    assert!(
        prefixes.contains("src"),
        "the root crate's own src/ must count as member code, or the scan \
         reports the most heavily guarded code in the repo as unguarded"
    );
    assert!(
        Path::new(&repo_root().join("Cargo.toml")).exists(),
        "repo root does not look like a cargo workspace"
    );
}

/// A member directory is never reported as non-member.
///
/// Guards the bug the first version of this scan had: `src/` was classified
/// as unguarded because the root package is not listed in `members`.
#[test]
fn root_crate_sources_are_not_reported_as_unguarded() {
    let trees = non_member_trees();
    for owned in ["src", "tests", "crates", "soul_llm", "soul_gateway"] {
        assert!(
            !trees.contains(owned),
            "{owned} is workspace-member code but was classified as \
             non-member; the member-prefix logic is wrong"
        );
    }
}
