# Disposition of simulated and placeholder features

Every feature listed here does less than its name suggests. All of them have
already been **neutralised** — none reports a false success any more, and that
work is recorded in `docs/security/findings.json`. What was missing is a
decision about their future.

A feature parked behind an "experimental" flag with no decision is a debt that
reads like a capability. This file exists so that each one has an owner, a
decision, and a date — and so that
`tests/architecture_simulated_execution.rs` can fail when a new one appears
without them.

**Status of this document:** decided. The repository owner reviewed the
recommendations below and adopted them as written (2026-07-30). Each entry
records that decision rather than a proposal.

---

## HIGH-006 — `--entity`, simulated SoulEntity autonomy

| | |
|---|---|
| Claims | An autonomous entity runtime (`soul_entity`) |
| Actually does | Simulated autonomy; never finished |
| Neutralised | Yes — no longer reports simulated steps as successes |
| **Decision** | **Keep gated**, review by 2026-10-31 |
| Decided by | repository owner, 2026-07-30 (adopted the recommendation as written) |

**Evidence.** The production guard can refuse it —
`GuardViolation::ExperimentalRuntimeInProduction` — but until #161 the posture
was built with a hardcoded `None`, so the refusal never fired for the only
runtime it exists to catch. That wiring is fixed and negative-probed.

**Why keep rather than delete.** It is the intended shape of the canonical
runtime work (Chantier 1). Deleting it would discard the design; finishing it
belongs to that workstream, not this one. The gate now genuinely holds, so the
cost of keeping it is bounded.

---

## MED-004 — Tree-of-Thought placeholder embeddings

| | |
|---|---|
| Claims | Semantic scoring and pruning of reasoning nodes |
| Actually does | Constant placeholder vectors → similarity scores that mean nothing |
| Neutralised | Yes — the literal placeholder is refused, scores are no longer presented as semantic |
| **Decision** | **Finish**, or delete the scoring path if no consumer needs it |
| Decided by | repository owner, 2026-07-30 (adopted the recommendation as written) |

**The trap.** Do not "finish" this by substituting a better-dressed
placeholder. The original defect was exactly that: constant vectors producing
plausible-looking cosine scores. Finishing means a real embedding source, and
the acceptance test is that the score **changes with the input in a way a
reader can predict** — not that a placeholder is correctly refused.

---

## LOW-006 — `--plan`, keyword matching presented as planning

| | |
|---|---|
| Claims | Goal decomposition |
| Actually does | Keyword matching, no LLM reasoning |
| Neutralised | Yes — gated and labelled non-reasoning |
| **Decision** | **Finish** — cost corrected below, it is not the cheap one |
| Decided by | repository owner, 2026-07-30 (adopted the recommendation as written) |

**Correction (2026-07-30).** This entry previously read: *"the planner crate
already holds an LLM client. This is the cheapest of the three finish
candidates."* **Both claims were wrong**, and they were written from the crate's
name and description rather than from its manifest.

`soul_planner/Cargo.toml` declares exactly three dependencies — `uuid`,
`chrono`, `serde`. There is no LLM client, and nothing in the crate reaches
one.

The gap is also wider than "keyword matching instead of reasoning".
`create_plan` performs **no decomposition at all**: it formats step commands
the caller already supplies, and a caller with no steps gets an empty plan.
The crate's own test says so —
`create_plan_does_not_decompose_a_goal`.

So finishing LOW-006 means: adding an LLM dependency to a crate that has
none, designing the decomposition prompt, handling its failure modes, and
deciding what an unreachable model should do to a plan. That is a feature,
not a gap-fill, and it is **not** cheaper than LOW-008.

The decision stays "finish". What changes is the estimate, and the order:
LOW-008 is now the cheapest of the three, because native tool calling is
integration against two documented APIs rather than a new capability.

---

## LOW-008 — `soul_llm` silently flattened tools to text

| | |
|---|---|
| Claims | Tool calling across providers |
| Actually does | Ollama has native tool calling; OpenAI/Anthropic flattened tools into the prompt |
| Neutralised | Yes — no longer silent |
| **Decision** | **Finish** — implement native tool calling for OpenAI and Anthropic |
| Decided by | repository owner, 2026-07-30 (adopted the recommendation as written) |

Both providers have documented native tool-calling APIs. This is ordinary
integration work with a clear acceptance test: a tool call round-trips as a
structured call, not as text the model happened to format correctly.

---

## MED-010 — `soul-wasm` placeholder WASI host functions

| | |
|---|---|
| Claims | A WASM runtime with WASI host functions |
| Actually does | `fd_write` / `proc_exit` / `environ_*` are placeholders |
| Reachable | **No** |
| **Decision** | **Delete** |
| Decided by | repository owner, 2026-07-30 (adopted the recommendation as written) |

**Evidence for deletion**, all measured:

- 550 lines in `soul-wasm/src/lib.rs`.
- **Zero** Rust callers: `grep -rn "soul_wasm::" --include=*.rs` returns nothing.
- **Not a workspace member** — so it is invisible to every architecture guard,
  which parse `members` from the root manifest.
- Its only trace is one line in root `Cargo.toml`
  (`soul_wasm = { path = "soul-wasm" }` in `[workspace.dependencies]`), a
  declaration nothing consumes.

A WASM runtime with placeholder host functions, that nothing builds and no
guard watches, is the most expensive kind of dead code: it will be found later
by someone who assumes it works. Git keeps the history if it is ever wanted.

---

**Executed.** `soul-wasm/` and the `[workspace.dependencies]` line were removed
in the same change, so the guard's "wholly present or wholly gone" assertion
holds. `cargo check --workspace --all-targets` is clean afterwards: nothing
depended on it, which is what the decision rested on.

## LOW-004 — `scirust-gpu-macros` `#[gpu]` attribute

| | |
|---|---|
| Claims | Dispatches a function to the GPU |
| Actually does | Parses the signature looking for `&mut [f32]`; never applied anywhere |
| Reachable | **No** |
| **Decision** | **Delete** | DONE — crate removed; `#[gpu]` was never applied anywhere |
| Decided by | repository owner, 2026-07-30 (adopted the recommendation as written); deleted 2026-08-03 (stub policy) |

`#[gpu]` was applied **nowhere** in the repository, and the crate was not in
`Cargo.lock` (never built by the root workspace). The only in-repo dependent,
`soullink-node/scirust/scirust-core/Cargo.toml`, declares **seven** absolute
path dependencies pointing at `/root/scirust/…`:

```
scirust-autodiff = { path = "/root/scirust/scirust-autodiff" }
scirust-macros   = { path = "/root/scirust/scirust-macros" }
scirust-simd     = { path = "/root/scirust/scirust-simd" }
scirust-gpu      = { path = "/root/scirust/scirust-gpu" }
scirust-gpu-macros = { path = "/root/scirust/scirust-gpu-macros" }
…
```

`/root/scirust` **does not exist**. Those are absolute, machine-specific paths
to a directory outside the repository, so that crate cannot build on any
machine — and `soullink-node` is in `exclude`, so CI never tries.

The `#[gpu]` attribute was a placeholder that parsed the signature for
`&mut [f32]` but never dispatched anything. Deleted 2026-08-03 under the
no-stubs policy, along with its references in `Cargo.toml`, `.github/workflows/
ci.yml`, and the architecture guard allowlists.

---

## Summary

| id | decision | next step |
|---|---|---|
| HIGH-006 | keep gated, review 2026-10-31 | none until the review date |
| MED-004 | finish | needs a real embedding source; see the trap above |
| LOW-006 | finish | **re-estimated**: needs a new LLM dependency and a decomposition design; not the cheap one |
| LOW-008 | finish | now the cheapest — integration against two documented APIs |
| MED-010 | **delete** | DONE — crate and manifest line removed together |
| LOW-004 | **delete** | DONE — crate and references removed together |

The three "finish" items are scheduled work, not blockers: each is neutralised
today, so nothing reports a false success while they wait.
