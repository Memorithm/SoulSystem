# SoulSystem

Framework d'entités numériques autonomes avec support multi-fournisseurs LLM.

This repository is a unified Rust workspace that merges the original SoulSystem monolith, the autonomous-agent monolith (`soul_agent_core`, `soul_entity`, `souls`, ...), the SoulLink Neural Mesh, SciRust core, and CCOS (Causal Context Operating System).

## Build

**One-liner (recommended):**

```bash
curl -fsSL https://raw.githubusercontent.com/Memorithm/SoulSystem/main/install.sh | sh
```

This downloads a prebuilt `soulsystem` binary for your platform (Linux/macOS
x86_64/arm64), or builds from source if no release matches — installing the Rust
toolchain automatically if needed. Override the target dir with
`SOULSYSTEM_INSTALL_DIR` or pin a version with `SOULSYSTEM_VERSION`.

**Windows PowerShell (x86-64):**

```powershell
irm https://raw.githubusercontent.com/Memorithm/SoulSystem/main/install.ps1 | iex
```

**npm:**

```bash
npm install -g soulsystem
```

**Cargo (from source):**

```bash
cargo install --git https://github.com/Memorithm/SoulSystem soulsystem
# or, in a clone:
cargo build --release --bin soulsystem
```

<details>
<summary>Legacy <code>souls</code> TUI binary</summary>

```bash
# Fast workspace check
cargo check --workspace

# Run the main binary
cargo run --bin soulsystem -- [--dev] [--repl] [--daemon]

# Release build
cargo build --release
```
</details>

## Utilisation

```bash
# Main binary
cargo run --bin soulsystem -- --help

# First-time configuration
soulsystem --setup

# Installation and environment diagnostics
soulsystem --doctor

# Native secret storage
soulsystem secrets set llm/openai

# Persistent scheduled goals
soulsystem automation add morning --schedule daily@08:30 --goal "Prepare my brief"

# Autonomous REPL
cargo run -p soul_repl --release

# Legacy `souls` TUI binary (when available)
cargo build --release -p souls
sudo cp target/release/souls /usr/local/bin/
```

## Architecture

| Couche | Crates | Rôle |
|--------|--------|------|
| **Runtime** | `soul_scheduler`, `soul_ipc`, `soul_storage`, `soul_matrix_engine` | Ordonnancement temps-réel, IPC, stockage vectoriel, GEMM SIMD |
| **Cognitive** | `soul_llm`, `soul_planner`, `soul_tools`, `soul_sandbox`, `soul_browser`, `soul_mcp`, `soul_skills` | Multi-provider LLM, planification, outils, navigateur, MCP, skills, sandbox |
| **Entity** | `soul_entity`, `soul_gateway`, `soul_repl`, `soul_agent_core` | Entité autonome, API HTTP/WS, TUI |
| **Neuro** | `neural_*`, `semantic_*`, `soullink-*` | Métacognition, CRDT, chaos monkey, auto-guérison, HNN mesh |
| **Persistence** | `soul_journal`, `soul_persistence` | WAL mmap, KV store Sled |
| **Telemetry** | `soul_telemetry` | Métriques Prometheus, profiling thermique |
| **CCOS** | `ccos` | Causal Context Operating System — merged workspace member |

See [Getting started](docs/GETTING_STARTED.md) for the shortest installation
path, provider setup, security defaults, and troubleshooting.

## Providers LLM

| Provider | Streaming | Embeddings |
|----------|-----------|------------|
| Ollama | NDJSON | Batch natif |
| OpenAI | SSE | API `/embeddings` |
| Anthropic | SSE | Non supporté |

## Commandes TUI

| Raccourci | Action |
|-----------|--------|
| `Ctrl+Shift+P` | Palette de commandes |
| `Ctrl+F` | Navigateur de fichiers |
| `Ctrl+R` | Recherche historique |
| `Ctrl+O` | Gestionnaire de sessions |
| `Ctrl+Y` | Copier dans le presse-papier |
| `Ctrl+E` | Exporter le chat |
| `Shift+Enter` | Saisie multi-lignes |

## Commandes CLI

```
/ask, /help, /models, /status, /plan, /run, /observe,
/clear, /save, /export, /files, /search
```

## Licence

The repository-level source-of-truth licensing files are [`LICENSE.md`](LICENSE.md)
and [`LICENSING.md`](LICENSING.md): SoulSystem is available for noncommercial use
under the PolyForm Noncommercial License 1.0.0, with separate commercial licensing.
The Required Notice is `Copyright 2026 Tarek Zekriti (https://github.com/CHECKUPAUTO/)`.

This README correction does not by itself change historical license grants or the
independent licensing/provenance of imported, adapted, vendored, or generated
material. The remaining workspace/package metadata audit is tracked separately.
