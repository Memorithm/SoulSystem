# soul-coding

soul-coding is the foundation of the canonical SoulSystem coding harness.

The current slice provides:

- TaskSpec requires explicit acceptance checks.
- TaskResult::completed requires a real change set and passing required checks.
- WorkspaceContext binds file resolution to a canonical worktree.
- CommandSpec keeps process arguments structured and shell-free.
- SandboxCommandRunner executes checks with the existing SoulSystem sandbox.
- GitWorkspace collects porcelain status and a reproducible diff hash.
- Verifier and CodingRuntime preserve check evidence when completion is not
  justified.
- CodingAgent is the single provider-agnostic loop: model turn, typed tool
  calls, bounded budgets, and verifier finalization.
- SessionStore persists task/worktree identity, bounded conversation context,
  budgets, and final evidence; `--resume --session-id ...` reopens an
  interrupted detached worktree without silently losing the prior transcript.
- The `soul-coding` binary provides one command-line entry point for Ollama,
  OpenAI, and Anthropic configurations without putting API keys in arguments.
- `soulsystem.coding-task/v1` provides a strict provider-neutral JSON ingress
  contract for external wrappers and coding-agent adapters. Unknown fields,
  duplicate check names, empty tasks, malformed checks and zero timeouts fail
  closed before a worktree is created.
- CodingFeedback records accepted, rejected, and manually edited artifacts for
  a future preference-learning layer.

The crate intentionally does not implement Command Code's proprietary
taste-1 model. It records auditable feedback events that can later feed a
transparent, project-scoped preference system.

This is the canonical coding runtime for the repository. The existing general
autonomy, daemon, browser, and MCP runtimes remain adapters or follow-up
migrations; they are not duplicated inside this loop. Subagent orchestration
and optional browser/MCP adapters remain explicit follow-up slices. The current
binary is a usable coding harness foundation, not a drop-in replacement for a
mature product such as Cline, OpenCode, or Command Code.

Example:

```text
cargo run -p soul-coding -- \
  --repo . \
  --prompt "Fix the failing parser" \
  --check 'tests=cargo test -p my-crate'
```

`--check` values are persisted as shell-free, whitespace-separated argv. Use
one `--check NAME=COMMAND` per required acceptance check.

External wrappers can avoid shell quoting and translate their native task model
into a versioned JSON file:

```json
{
  "schema": "soulsystem.coding-task/v1",
  "prompt": "Fix the failing parser",
  "acceptance": [
    {
      "name": "tests",
      "command": "cargo test -p my-crate",
      "required": true,
      "timeout_secs": 300
    }
  ]
}
```

Run it with:

```text
cargo run -p soul-coding -- \
  --repo . \
  --task-json task.json
```

`--task-json` is mutually exclusive with `--prompt` and `--check`. External
schema fields are not interpreted as hidden execution policy: unknown fields
are rejected, and the runtime mints its own task identity and creation time at
ingress. This interchange is an adapter boundary, not a claim of native
protocol compatibility with Cline, OpenCode, Command Code, or any other
third-party product.

To resume a session, use the same repository and session identifier:

```text
cargo run -p soul-coding -- \
  --repo . \
  --resume \
  --session-id session-123
```

Resume rejects `--prompt`, `--task-json`, and `--check`; the persisted task is
the sole authority for that session. Session metadata is local repository state
and can include verifier output; do not use it as a channel for credentials.
