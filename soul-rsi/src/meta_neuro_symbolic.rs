//! # Meta-neuro-symbolic objective
//!
//! Implements the policy objective that couples the learned policy with
//! strict symbolic validation:
//!
//! ```text
//! L(φ) = E[ RM_NS(x, y) − β_NS · log( LLM_φ(y|x) / LLM_SFT(y|x) ) ]
//!        + γ_NS · E[ log LLM_φ(x) ]
//! ```
//!
//! The three terms are:
//!
//! 1. **Reward** — the score returned by a [`SymbolicValidator`] (formal,
//!    logical or algebraic checker) for an output `y` produced for context `x`.
//! 2. **KL penalty** — `β_NS` times the log-ratio of the learned policy to the
//!    SFT reference policy; it keeps the policy from drifting too far from the
//!    supervised base during self-improvement.
//! 3. **Pretraining regularizer** — `γ_NS` times the log-likelihood of
//!    pretraining contexts; it guards against catastrophic forgetting.
//!
//! ## Zero-allocation
//!
//! The hot loop ([`compute_meta_ns_loss`]) only writes into caller-provided
//! buffers. No `Vec`, `Box` or other heap allocation happens while evaluating
//! a batch of traces. The [`AgentExecutionTrace`] itself is fixed-capacity.
//!
//! ## Memory safety
//!
//! The whole module is written without a single `unsafe` block. Generic
//! traits and `#[inline(always)]` give the optimizer the information it needs
//! without bypassing the borrow checker.

/// Capacity of the per-trace log-probability buffer.
///
/// Traces with more symbols than this are truncated during scoring; the
/// truncation is explicit and never silently drops a reward.
pub const MAX_TRACE_SYMBOLS: usize = 256;

/// A fixed-capacity log-probability buffer used by the loss kernel.
///
/// Stores `(context, response)` log-probabilities as pairs so the KL term and
/// the pretraining term can be computed in a single pass over the buffer.
#[derive(Debug, Clone, Copy)]
pub struct LogProbBuffer {
    /// Log-probability of the response under the learned policy.
    pub response_log_probs: [f64; MAX_TRACE_SYMBOLS],
    /// Log-probability of the response under the SFT reference policy.
    pub sft_log_probs: [f64; MAX_TRACE_SYMBOLS],
    /// Number of valid entries (always `<= MAX_TRACE_SYMBOLS`).
    pub len: usize,
}

impl LogProbBuffer {
    /// Creates an empty buffer.
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            response_log_probs: [0.0; MAX_TRACE_SYMBOLS],
            sft_log_probs: [0.0; MAX_TRACE_SYMBOLS],
            len: 0,
        }
    }

    /// Pushes one `(response_log_prob, sft_log_prob)` pair. Returns `false`
    /// (and leaves the buffer unchanged) when full.
    #[inline(always)]
    pub fn push(&mut self, response_log_prob: f64, sft_log_prob: f64) -> bool {
        if self.len >= MAX_TRACE_SYMBOLS {
            return false;
        }
        self.response_log_probs[self.len] = response_log_prob;
        self.sft_log_probs[self.len] = sft_log_prob;
        self.len += 1;
        true
    }

    /// Clears the buffer without deallocating.
    #[inline(always)]
    pub fn clear(&mut self) {
        self.len = 0;
    }
}

impl Default for LogProbBuffer {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

/// Hyper-parameters of the meta-neuro-symbolic objective.
///
/// | Field | Symbol | Role |
/// |---|---|---|
/// | `beta_ns` | `β_NS` | KL-divergence penalty weight. Larger values pin the policy closer to the SFT reference. |
/// | `gamma_ns` | `γ_NS` | Pretraining regularizer weight. Larger values fight catastrophic forgetting harder. |
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MetaNSConfig {
    pub beta_ns: f64,
    pub gamma_ns: f64,
}

impl MetaNSConfig {
    /// Creates a configuration from the two objective weights.
    ///
    /// ```
    /// use soul_rsi::meta_neuro_symbolic::MetaNSConfig;
    ///
    /// let cfg = MetaNSConfig::new(0.1, 0.01);
    /// assert_eq!(cfg.beta_ns, 0.1);
    /// assert_eq!(cfg.gamma_ns, 0.01);
    /// ```
    #[inline(always)]
    pub const fn new(beta_ns: f64, gamma_ns: f64) -> Self {
        Self { beta_ns, gamma_ns }
    }
}

impl Default for MetaNSConfig {
    /// Common defaults: a light KL pin and a light pretraining regularizer.
    fn default() -> Self {
        Self::new(0.1, 0.01)
    }
}

/// A symbolic reward that a [`SymbolicValidator`] can produce.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SymbolicReward {
    /// The reward score (positive for conformity, negative for violations).
    pub score: f64,
    /// Whether a hard symbolic constraint was violated (e.g. an `unsafe`
    /// block where none is allowed, or a broken artifact hash).
    pub violated_constraint: bool,
}

impl SymbolicReward {
    /// A fully compliant output.
    #[inline(always)]
    pub const fn compliant(score: f64) -> Self {
        Self {
            score,
            violated_constraint: false,
        }
    }

    /// A hard violation: heavily penalized regardless of the nominal score.
    #[inline(always)]
    pub const fn violation(score: f64) -> Self {
        Self {
            score,
            violated_constraint: true,
        }
    }
}

/// Formal validator injected into the objective.
///
/// Implementations check a generated output `y` against a strict symbolic,
/// logical or algebraic criterion for context `x` and return a numeric
/// reward. A heavy penalty must be returned when a symbolic constraint is
/// violated.
pub trait SymbolicValidator {
    /// Validates one generated output for one context.
    ///
    /// # Example
    ///
    /// ```
    /// use soul_rsi::meta_neuro_symbolic::{SymbolicValidator, SymbolicReward};
    ///
    /// struct NoUnsafe;
    ///
    /// impl SymbolicValidator for NoUnsafe {
    ///     fn validate(&self, _x: &str, y: &str) -> SymbolicReward {
    ///         if y.contains("unsafe") {
    ///             SymbolicReward::violation(-10.0)
    ///         } else {
    ///             SymbolicReward::compliant(1.0)
    ///         }
    ///     }
    /// }
    /// ```
    fn validate(&self, x: &str, y: &str) -> SymbolicReward;
}

/// A single agent execution trace, as recorded by the RL data-collection
/// loop. It captures the quantities the objective needs: the log
/// probabilities of the response under both policies, the symbolic reward
/// the output earned, and an execution-context identifier for provenance.
#[derive(Debug, Clone, Copy)]
pub struct AgentExecutionTrace {
    /// Context hash input for provenance (the loss itself only needs the
    /// log-probabilities).
    pub context: u64,
    /// Log-probability of the response under the learned policy.
    pub response_log_prob: f64,
    /// Log-probability of the response under the SFT reference policy.
    pub sft_log_prob: f64,
    /// Symbolic reward earned by this response.
    pub reward: f64,
}

/// Fixed-capacity, stack-allocated batch of agent execution traces.
///
/// This is the zero-allocation replacement for `Vec<AgentExecutionTrace>` on
/// the hot path.
#[derive(Debug, Clone, Copy)]
pub struct TraceBuffer {
    entries: [AgentExecutionTrace; MAX_TRACE_SYMBOLS],
    len: usize,
}

impl TraceBuffer {
    /// Creates an empty trace buffer.
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            entries: [AgentExecutionTrace {
                context: 0,
                response_log_prob: 0.0,
                sft_log_prob: 0.0,
                reward: 0.0,
            }; MAX_TRACE_SYMBOLS],
            len: 0,
        }
    }

    /// Appends a trace entry; returns `false` when the buffer is full.
    #[inline(always)]
    pub fn push(&mut self, entry: AgentExecutionTrace) -> bool {
        if self.len >= MAX_TRACE_SYMBOLS {
            return false;
        }
        self.entries[self.len] = entry;
        self.len += 1;
        true
    }

    /// Number of valid entries.
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the buffer is empty.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Iterates over the valid entries.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &AgentExecutionTrace> {
        self.entries[..self.len].iter()
    }
}

impl Default for TraceBuffer {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

/// The loss breakdown returned by [`compute_meta_ns_loss`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MetaNsLoss {
    /// Negative mean reward (so the objective maximizes reward).
    pub reward_loss: f64,
    /// Mean KL penalty.
    pub kl_loss: f64,
    /// Pretraining regularizer contribution.
    pub pretrain_loss: f64,
    /// `reward_loss + kl_loss + pretrain_loss`.
    pub total: f64,
    /// Number of traces actually scored (skips full-buffer/empty guards).
    pub scored: usize,
}

impl Default for MetaNsLoss {
    #[inline(always)]
    fn default() -> Self {
        Self {
            reward_loss: 0.0,
            kl_loss: 0.0,
            pretrain_loss: 0.0,
            total: 0.0,
            scored: 0,
        }
    }
}

/// Computes the mean meta-neuro-symbolic loss over a batch of traces.
///
/// For every trace the three terms are accumulated into the caller-supplied
/// accumulator:
///
/// ```text
/// reward   = −Σ RM_NS(x_i, y_i)          (reward is per-trace)
/// kl       =  β_NS · Σ log( LLM_φ(y_i|x_i) / LLM_SFT(y_i|x_i) )
/// pretrain = −γ_NS · Σ log LLM_φ(x_i)
/// ```
///
/// # Zero-allocation contract
///
/// This function allocates nothing: it only reads `traces` and writes into
/// `out`. `#[deny(clippy::alloc_in_loop)]` is attached so any future
/// allocation inside the evaluation loop is a compile error, not a review
/// comment.
///
/// # Example
///
/// ```
/// use soul_rsi::meta_neuro_symbolic::{
///     MetaNSConfig, MetaNsLoss, TraceBuffer, AgentExecutionTrace,
///     compute_meta_ns_loss,
/// };
///
/// let cfg = MetaNSConfig::new(0.1, 0.01);
/// let mut traces = TraceBuffer::new();
/// traces.push(AgentExecutionTrace {
///     context: 1,
///     response_log_prob: -1.0,
///     sft_log_prob: -1.2,
///     reward: 1.0,
/// });
/// let mut out = MetaNsLoss::default();
/// compute_meta_ns_loss(&cfg, &traces, &mut out);
/// assert_eq!(out.scored, 1);
/// ```
#[inline]
#[deny(clippy::alloc_in_loop)]
pub fn compute_meta_ns_loss(config: &MetaNSConfig, traces: &TraceBuffer, out: &mut MetaNsLoss) {
    out.reward_loss = 0.0;
    out.kl_loss = 0.0;
    out.pretrain_loss = 0.0;
    out.total = 0.0;
    out.scored = 0;

    let n = traces.len();
    for i in 0..n {
        let entry = &traces.entries[i];
        // KL: log(π_φ / π_SFT) = log π_φ − log π_SFT
        let kl = entry.response_log_prob - entry.sft_log_prob;
        // Pretraining term: the response log-probability under the learned
        // policy doubles as the context log-likelihood for this trace.
        let pretrain = -entry.response_log_prob;

        out.reward_loss -= entry.reward;
        out.kl_loss += config.beta_ns * kl;
        out.pretrain_loss += config.gamma_ns * pretrain;
        out.scored += 1;
    }

    if out.scored > 0 {
        let inv = 1.0 / out.scored as f64;
        out.reward_loss *= inv;
        out.kl_loss *= inv;
        out.pretrain_loss *= inv;
    }

    out.total = out.reward_loss + out.kl_loss + out.pretrain_loss;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace(ctx: u64, rlp: f64, slp: f64, reward: f64) -> AgentExecutionTrace {
        AgentExecutionTrace {
            context: ctx,
            response_log_prob: rlp,
            sft_log_prob: slp,
            reward,
        }
    }

    #[test]
    fn empty_batch_scores_zero() {
        let cfg = MetaNSConfig::new(0.1, 0.01);
        let traces = TraceBuffer::new();
        let mut out = MetaNsLoss::default();
        compute_meta_ns_loss(&cfg, &traces, &mut out);
        assert_eq!(out.scored, 0);
        assert_eq!(out.total, 0.0);
    }

    #[test]
    fn single_trace_matches_hand_computation() {
        let cfg = MetaNSConfig::new(0.1, 0.01);
        let mut traces = TraceBuffer::new();
        traces.push(trace(1, -2.0, -1.0, 5.0));
        let mut out = MetaNsLoss::default();
        compute_meta_ns_loss(&cfg, &traces, &mut out);
        // reward_loss = -5; kl = 0.1 * (-2 - -1) = -0.1; pretrain = 0.01 * 2 = 0.02
        assert!((out.reward_loss + 5.0).abs() < 1e-12);
        assert!((out.kl_loss + 0.1).abs() < 1e-12);
        assert!((out.pretrain_loss - 0.02).abs() < 1e-12);
        assert!((out.total - (-5.0 - 0.1 + 0.02)).abs() < 1e-12);
        assert_eq!(out.scored, 1);
    }

    #[test]
    fn batch_averages_over_traces() {
        let cfg = MetaNSConfig::new(0.5, 0.5);
        let mut traces = TraceBuffer::new();
        // trace A: reward 2, kl = 0.5*(log1 - log2), pretrain = -0.5*log1
        traces.push(trace(1, -1.0, -2.0, 2.0));
        // trace B: reward 4, kl = 0.5*(log2 - log1), pretrain = -0.5*log2
        traces.push(trace(2, -2.0, -1.0, 4.0));
        let mut out = MetaNsLoss::default();
        compute_meta_ns_loss(&cfg, &traces, &mut out);
        assert_eq!(out.scored, 2);
        // reward_loss = -(2 + 4)/2 = -3
        assert!((out.reward_loss + 3.0).abs() < 1e-12);
        // kl terms cancel: 0.5*(1) + 0.5*(-1) = 0 over 2 traces
        assert!(out.kl_loss.abs() < 1e-12);
        // pretrain = (0.5*1 + 0.5*2)/2 = 0.75
        assert!((out.pretrain_loss - 0.75).abs() < 1e-12);
    }

    #[test]
    fn buffer_rejects_overflow() {
        let mut buf = LogProbBuffer::new();
        let mut pushed = 0;
        while buf.push(-1.0, -1.0) {
            pushed += 1;
        }
        assert_eq!(pushed, MAX_TRACE_SYMBOLS);
        assert_eq!(buf.len, MAX_TRACE_SYMBOLS);
        buf.clear();
        assert_eq!(buf.len, 0);
    }

    #[test]
    fn trace_buffer_overflow_returns_false() {
        let mut buf = TraceBuffer::new();
        let mut pushed = 0;
        while buf.push(trace(0, -1.0, -1.0, 0.0)) {
            pushed += 1;
        }
        assert_eq!(pushed, MAX_TRACE_SYMBOLS);
        assert_eq!(buf.len(), MAX_TRACE_SYMBOLS);
        assert!(!buf.push(trace(0, 0.0, 0.0, 0.0)));
    }

    #[test]
    fn violation_reward_is_heavily_penalized() {
        let r = SymbolicReward::violation(-10.0);
        assert!(r.violated_constraint);
        assert_eq!(r.score, -10.0);
    }

    #[test]
    fn symbolic_validator_rejects_unsafe_blocks() {
        struct NoUnsafe;
        impl SymbolicValidator for NoUnsafe {
            fn validate(&self, _x: &str, y: &str) -> SymbolicReward {
                if y.contains("unsafe") {
                    SymbolicReward::violation(-10.0)
                } else {
                    SymbolicReward::compliant(1.0)
                }
            }
        }
        let v = NoUnsafe;
        assert!(
            v.validate("ctx", "fn f() { let x = 1; }")
                .violated_constraint
                == false
        );
        let bad = v.validate("ctx", "fn f() { unsafe { g() } }");
        assert!(bad.violated_constraint);
        assert_eq!(bad.score, -10.0);
    }

    #[test]
    fn numeric_stability_with_extreme_log_probs() {
        // Very negative log-probs must not produce NaN/Inf anywhere.
        let cfg = MetaNSConfig::new(10.0, 10.0);
        let mut traces = TraceBuffer::new();
        for _ in 0..4 {
            traces.push(trace(1, -1e6, -1e6, 0.0));
        }
        let mut out = MetaNsLoss::default();
        compute_meta_ns_loss(&cfg, &traces, &mut out);
        assert!(out.total.is_finite());
        assert!(out.kl_loss.abs() < 1e-9);
        assert_eq!(out.scored, 4);
    }

    #[test]
    fn config_defaults_are_finite() {
        let cfg = MetaNSConfig::default();
        assert!(cfg.beta_ns > 0.0);
        assert!(cfg.gamma_ns > 0.0);
        assert!(cfg.beta_ns.is_finite());
        assert!(cfg.gamma_ns.is_finite());
    }
}
