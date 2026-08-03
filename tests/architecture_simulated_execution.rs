//! Guard for HIGH-006: simulated work must not be reported as real work.
//!
//! `SoulEntity::execute_plan` walks a plan's steps and dispatches none of
//! them. That is a defensible state for an experimental feature; what was not
//! defensible was the reporting around it. Every layer claimed success:
//!
//! - each step published `StepExecuted { success: true }`,
//! - the result string read `[OK] {step}`, indistinguishable from real output,
//! - the goal was marked `completed` and counted in `goals_completed`,
//! - the evaluation recorded `score: 0.9` with feedback "Plan exécuté avec
//!   succès", and
//! - the decision archived the goal with `confidence: 0.95`, "Objectif
//!   atteint".
//!
//! The last two are the ones that matter beyond a console line: both are
//! serialized into long-term memory and interpolated into the LLM summary
//! prompt, so the entity was feeding its own fabricated success back into
//! later reasoning. A simulator that says it is simulating is a test fixture;
//! one that records confident success is a corrupted memory.
//!
//! This guard pins the specific strings and literals that carried the claim.
//! It is deliberately narrow — it cannot tell whether execution was *wired*,
//! only whether the old fabrications came back — and it exists because the
//! unit test that should have caught this was asserting the fabrication
//! instead: `assert!(r.contains("[OK]"))`.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    let path: PathBuf = repo_root().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{} unreadable: {e}", path.display()))
}

/// Lines outside comments, so prose describing the old behaviour is allowed.
fn code_lines(source: &str) -> Vec<&str> {
    source
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("//") && !l.starts_with("///") && !l.starts_with('*'))
        .collect()
}

/// The entity does not claim a step succeeded when it ran nothing.
#[test]
fn simulated_steps_are_not_published_as_successes() {
    let source = read("soul_entity/src/entity.rs");
    let lines = code_lines(&source);

    let publishes_bare_success = lines
        .windows(4)
        .any(|w| w[0].contains("StepExecuted") && w.iter().any(|l| l.contains("success: true")));

    assert!(
        !publishes_bare_success,
        "soul_entity publishes StepExecuted {{ success: true }} again. Nothing \
         in execute_plan dispatches a step, so `success: true` asserts an \
         outcome that was never observed. Use `success: false` with \
         `simulated: true` until real execution is wired."
    );
}

/// The result string says the step was simulated.
#[test]
fn the_step_outcome_string_does_not_read_as_real_output() {
    let source = read("soul_entity/src/entity.rs");
    let lines = code_lines(&source);

    assert!(
        !lines
            .iter()
            .any(|l| l.contains(r#"format!("[OK] {}", step)"#)),
        "the per-step outcome is formatted as \"[OK] {{step}}\" again. That \
         string is joined into exec_result, persisted to memory and fed to the \
         LLM summary — it must say the step was simulated."
    );
    assert!(
        lines.iter().any(|l| l.contains("SIMULATED")),
        "no SIMULATED marker found in execute_plan's outcome formatting; the \
         guard may be looking at the wrong place after a refactor"
    );
}

/// The fabricated evaluation and decision literals do not return.
///
/// These are the load-bearing assertions: unlike a console string, both
/// values are persisted and re-read as evidence by later cycles.
#[test]
fn a_simulated_cycle_records_no_confident_evaluation() {
    let source = read("soul_entity/src/entity.rs");
    let lines = code_lines(&source);

    for forbidden in [
        "score: 0.9,",
        "Plan exécuté avec succès",
        "Objectif atteint",
        "confidence: 0.95,",
    ] {
        assert!(
            !lines.iter().any(|l| l.contains(forbidden)),
            "soul_entity records {forbidden:?} again for a cycle that executed \
             nothing. This value is serialized into long-term memory and \
             interpolated into the LLM summary prompt, so it becomes an input \
             to later reasoning rather than a display string."
        );
    }
}

/// A goal whose plan was never dispatched is not counted as completed.
#[test]
fn simulated_goals_do_not_increment_goals_completed() {
    let source = read("soul_entity/src/entity.rs");
    let lines = code_lines(&source);

    let increments_completed = lines.iter().any(|l| l.contains("goals_completed += 1"));
    assert!(
        !increments_completed,
        "execute_plan increments goals_completed again. An operator reads that \
         counter to answer \"is this doing work\"; a simulated run must land in \
         goals_simulated instead."
    );
}

/// The `--entity` flag refuses to start under production.
#[test]
fn the_entity_flag_is_gated_behind_a_non_production_mode() {
    let source = read("src/main.rs");

    let entity_branch = source
        .split_once("if cli.entity {")
        .expect("main.rs still has an `if cli.entity` branch")
        .1;
    // Only the head of the branch matters; the gate must come before any
    // entity construction.
    let head: String = entity_branch
        .lines()
        .take(40)
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        head.contains("RuntimeMode::from_env"),
        "the --entity branch no longer consults RuntimeMode. SoulEntity \
         simulates plan execution, so starting it in production gives an \
         operator a process that reports activity and performs none."
    );
    assert!(
        head.contains("return Err("),
        "the --entity branch consults the runtime mode but does not refuse to \
         start. A warning is not enough here: the failure mode is silent \
         inaction, which looks identical to working correctly."
    );
}

/// The guard is reading real files, not silently passing on empty reads.
#[test]
fn the_guard_reads_the_files_it_claims_to() {
    for rel in ["soul_entity/src/entity.rs", "src/main.rs"] {
        let source = read(rel);
        assert!(
            source.len() > 2_000,
            "{rel} is only {} bytes; the guard would pass vacuously",
            source.len()
        );
    }
    assert!(Path::new(&repo_root().join("soul_entity/src/entity.rs")).exists());
}

// ── Disposition guard ────────────────────────────────────────────────────────
//
// The tests above pin the *fabrications* that HIGH-006 carried. These pin the
// *decisions*: a feature that does less than its name says must have an owner,
// a decision and a review date written down, or this file fails.
//
// A feature parked behind an "experimental" flag with nobody accountable is a
// debt that reads like a capability. Six of them accumulated before anyone
// asked what should happen to them.

/// Features known to do less than their name suggests.
///
/// Each entry names the decision document section that covers it. Adding a
/// simulated feature without a decision fails
/// `every_simulated_feature_has_a_written_decision`.
const SIMULATED_FEATURES: &[(&str, &str)] = &[
    ("HIGH-006", "--entity, simulated SoulEntity autonomy"),
    ("MED-004", "Tree-of-Thought placeholder embeddings"),
    ("LOW-006", "--plan, keyword matching presented as planning"),
    ("LOW-008", "soul_llm silently flattened tools to text"),
    ("MED-010", "soul-wasm placeholder WASI host functions"),
];

fn decision_doc() -> String {
    std::fs::read_to_string(repo_root().join("docs/decisions/simulated-features.md"))
        .expect("docs/decisions/simulated-features.md must exist — it is where the decisions live")
}

/// Every simulated feature is covered by the decision document.
#[test]
fn every_simulated_feature_has_a_written_decision() {
    let doc = decision_doc();
    for (id, subject) in SIMULATED_FEATURES {
        assert!(
            doc.contains(id),
            "{id} ({subject}) is a simulated feature with no section in \
             docs/decisions/simulated-features.md. Write the decision — what it \
             claims, what it does, and whether it is finished, deleted or kept \
             gated — rather than leaving it parked."
        );
    }
}

/// Every entry states a recommendation and an owner.
///
/// A decision document listing problems without saying who decides is a status
/// report, and status reports do not resolve.
#[test]
fn every_decision_names_a_recommendation_and_an_owner() {
    let doc = decision_doc();
    for (id, _) in SIMULATED_FEATURES {
        let section = doc
            .split("\n## ")
            .find(|s| s.starts_with(id))
            .unwrap_or_else(|| panic!("{id} has no section"));
        // Either word: a fresh entry starts as a recommendation and becomes a
        // decision once someone owns it. Both are a stated position; what the
        // guard refuses is an entry that describes the problem and stops.
        assert!(
            section.contains("Recommendation") || section.contains("Decision"),
            "{id} states neither a recommendation nor a decision — describing \
             the problem is not the same as saying what happens to it"
        );
        assert!(
            section.contains("Decided by"),
            "{id} names nobody accountable for the decision"
        );
    }
}

/// A feature marked for deletion must not still be referenced as a dependency.
///
/// Catches the half-done removal: the crate is gone from the manifest but the
/// directory stays, or the reverse. Either leaves a reader believing something
/// that is not true.
#[test]
fn a_feature_recommended_for_deletion_is_either_present_or_fully_gone() {
    let root = repo_root();
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).expect("root manifest");
    let declared = manifest.contains("soul_wasm = { path = \"soul-wasm\" }");
    let present = root.join("soul-wasm").is_dir();
    assert_eq!(
        declared, present,
        "soul-wasm is half-removed: declared in the root manifest = {declared}, \
         directory present = {present}. Remove both or neither — a dangling \
         declaration and an orphan directory are each worse than the crate."
    );
}
