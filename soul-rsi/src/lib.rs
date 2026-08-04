//! # soul_rsi — Recursive self-improvement loop
//!
//! A small, auditable engine that lets SoulSystem improve **its own source
//! code** the way the literature describes recursive self-improvement, without
//! the hand-waving: it proposes a change, *builds and tests it in an isolated
//! copy*, keeps it **only if it provably improves**, archives the surviving
//! variant, and repeats.
//!
//! ## How it maps to the research
//!
//! - **STOP — Self-Taught Optimizer** (Zelikman et al., 2023): the *proposer*
//!   is a swappable "improver" function. [`LlmProposer`] is the LLM version;
//!   any [`traits::CodeModel`] plugs in. The loop never trusts the improver's
//!   self-assessment.
//! - **Darwin Gödel Machine** (Zhang et al., 2025): every validated change is
//!   kept as a stepping stone in an open-ended [`Archive`]; the search may
//!   branch from any of them, and acceptance is decided by *empirical*
//!   evaluation, never by the model's claim.
//! - **Gödel Machine** (Schmidhuber, 2007): improvements are only applied after
//!   a check that they are beneficial — here, the build+test gate in
//!   [`variant::Fitness`], where a change that breaks compilation can never
//!   dominate one that builds.
//! - **Reflexion** (Shinn et al., 2023): rejected rationales are fed back to the
//!   proposer as cheap verbal reinforcement so it avoids repeating dead ends.
//! - **Open-endedness** (Lehman & Stanley, 2015): parent selection mixes quality
//!   with a novelty bonus for under-explored lineages.
//!
//! ## Safety
//!
//! Evaluation always runs on a throwaway [`snapshot::WorkspaceSnapshot`]; the
//! live tree is only ever touched by the explicit [`snapshot::promote_to_live`]
//! call, gated on an all-green evaluation, and every edit goes through
//! `soul_automodify` so it is backed up and reversible.
//!
//! ## Example
//!
//! ```no_run
//! use soul_rsi::{Archive, RsiConfig, RsiEngine, CargoEvaluator};
//! use soul_rsi::{LlmProposer, CodeModel};
//! # use soul_rsi::Result;
//!
//! struct MyModel; // wrap your real LLM client here
//! impl CodeModel for MyModel {
//!     fn complete(&self, _prompt: &str) -> Result<String> { Ok(String::new()) }
//! }
//!
//! # fn demo() -> Result<()> {
//! let proposer = LlmProposer::new(MyModel, vec!["soul_planner/src/lib.rs".into()]);
//! let evaluator = CargoEvaluator { test_args: vec!["-p".into(), "soul_planner".into()], ..Default::default() };
//! let baseline = soul_rsi::Fitness { compiles: true, tests_passed: 0, tests_failed: 0, score: 0.0, notes: String::new() };
//! let mut engine = RsiEngine::new(
//!     Archive::with_root(baseline),
//!     proposer,
//!     evaluator,
//!     RsiConfig::new(".", "make soul_planner faster without breaking tests"),
//!     /* seed */ 42,
//! );
//! engine.run(20)?;
//! if let Some(best) = engine.best() {
//!     println!("best variant: {} (score {:?})", best.id, best.fitness.as_ref().map(|f| f.score));
//! }
//! # Ok(())
//! # }
//! ```

mod archive;
mod engine;
mod error;
mod evaluator;
mod llm;
pub mod meta_neuro_symbolic;
mod rng;
mod snapshot;
mod traits;
mod variant;

pub use archive::Archive;
pub use engine::{RsiConfig, RsiEngine, StepOutcome};
pub use error::{Result, RsiError};
pub use evaluator::{CargoEvaluator, ClosureEvaluator};
pub use llm::LlmProposer;
pub use rng::SplitMix64;
pub use snapshot::{promote_to_live, WorkspaceSnapshot};
pub use traits::{CodeModel, Evaluator, ImprovementContext, Proposal, Proposer};
pub use variant::{Fitness, Patch, Status, Variant};
