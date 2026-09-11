# SoulSystem Agent Bootstrap Contract

Before autonomous coding, coding-harness changes, security/isolation work, session-format changes, cross-repository integration, PR creation, or merge decisions, read:

```bash
git fetch origin agent/ecosystem-roadmap && \
git show origin/agent/ecosystem-roadmap:.agent/SOULSYSTEM_ECOSYSTEM_ROADMAP.yaml
```

If the roadmap cannot be fetched or read, fail closed for major coding-harness, security, session-format, cross-repository integration, or merge decisions. Read-only diagnosis is allowed.

## Repository role

SoulSystem is the autonomous-agent runtime and coding-harness product. Its canonical coding path already uses detached Git worktrees, provider-agnostic LLMs, resumable sessions, explicit acceptance checks, and interactive/autonomous/container execution modes.

The next coding-harness work must strengthen this path rather than create competing runtimes. Repository-aware coding agents must read the target repository's `AGENTS.md` and required off-main roadmap before editing, obey fail-closed project rules, and record the exact base SHA and policy documents used.

## Security boundary

Do not claim untrusted-network production readiness while the repository's own current security assessment remains `NOT_READY`. A sandbox label must correspond to real filesystem/process/network/resource isolation guarantees. Credentials must use environment/native secret paths rather than being exposed or committed.

SoulSystem does not own SciRust scientific semantics, Hub global orchestration, Verify dossier/verdict semantics, SciCapsule format/trust semantics, ElasticXxx resource-control semantics, or Forge search semantics.

Required CI must be green on the exact PR head before merge.

Reread the roadmap at every session start, before coding-harness/security/session changes, before ecosystem integration, after strategy changes, and before relevant PR/merge decisions.

Do not merge the roadmap itself into `main` unless the user explicitly requests it.

## V0-1 vendor freeze (2026-09-12)

Also read `VENDOR_POLICY.md` and `CODEOWNERS` before any edit under `ccos/`, `octasoma/`, `slha-kernel/`, `scirust-*`, `forges/`, or `turboquant/`.

Fail closed: do not add features inside those trees. Do not merge a vendor of a sibling monorepo. Replace copies with git SHA pins. Host work stays in `soul-*` / `soullink-*` / `soulsystem-*`.
