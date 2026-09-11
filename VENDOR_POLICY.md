# SoulSystem vendor freeze — V0-1

Effective 2026-09-12. This repository vendors copies of canon owners that live elsewhere in the Memorithm org. Those copies are frozen.

## Frozen trees (do not evolve in this repo)

| Local path | Canon owner | Rule |
|---|---|---|
| `ccos/` | Memorithm/CCOS-Core | no feature work; replace with git pin |
| `octasoma/` | Memorithm/octasoma | no feature work; replace with git pin |
| `slha-kernel/` | Memorithm/SLHAv2 | no feature work; replace with git pin |
| `scirust-core/` and other `scirust-*` copies | Memorithm/scirust | no feature work; replace with git pin |
| `forges/` | Memorithm/Forge | no feature work; replace with git pin |
| `turboquant/` | Memorithm/TurboQuant | already excluded from workspace; do not rejoin |

## Allowed work in this repository

- `soul-*`, `soullink-*`, `soulsystem-*` host crates
- wiring that **consumes** a pinned git dependency
- deleting a vendor tree after the pin compiles

## Forbidden

- merging a vendor tree from a sibling monorepo
- adding workspace members under a frozen prefix
- relaxing `[workspace.lints.rust]` further (`dead_code` / `unused_unsafe` are already allow — that is debt, not a license to add more)
- claiming `repository = "internal"` on new crates; use `https://github.com/Memorithm/SoulSystem`

## Exit criterion (V3)

Workspace members whose names do not start with `soul-` / `soullink-` / `soulsystem-` / `avid-` drop below 40, and every remaining foreign crate is a git pin with a recorded SHA.
