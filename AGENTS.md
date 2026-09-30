# Agent guide (Global Server)

Rust Web-of-Trust resolver (`dtp-global`) and its Sync Server (`dtp-sync`).
Read [README.md](README.md), [PLAN.md](PLAN.md), and the specs before
changing code.

## Stack

- Rust 2024, stable toolchain. Pure-Rust crates only (builds with the GNU or
  MSVC target, no C compiler): `k256` (BIP-340), `sha2`, `redb`, `tokio`,
  `axum`, `tokio-tungstenite`, `serde_json`, `im`, `arc-swap`, `rayon`.
- Workspace crates under `crates/` (see
  [specs/architecture.md § Crates](specs/architecture.md#crates)).

## Commands

```text
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p dtp-server -- --config dtp-global.toml      # resolver
cargo run -p dtp-sync-server -- --config dtp-sync.toml   # Sync Server
cargo test -p dtp-conformance -- --nocapture             # corpus report
```

All three checks must be green before every commit. CI runs the same on
Ubuntu (`.github/workflows/ci.yml`).

## Rules

- **Specs first.** Behaviour comes from `TrustGraph/specs` (model
  `dtp-wot/1`, `identity-binding.md`, `resolver-api.md`, `conformance.md`,
  `telemetry.md`) and `specs/*.md` here. Never edit TrustGraph specs from this
  repo; if a GlobalServer spec must change, change it in the same commit and
  record it in `PLAN.md`.
- **Same API as the Personal Server.** Results must match the TypeScript DTOs
  (`TrustQueryResult`, `RatingQueryResult`, …) field for field.
- **Strictly a WoT graph:** kinds `32009`, `32014`, `10011` and NIP-09 kind
  `5` targeting them. No kind `0`, no X data, no client identity evidence.
- **No fake implementations.** Anything not built answers
  `["DTP-ERR", id, "unsupported", …]` and is listed in `PLAN.md`.
- CPU work runs off the tokio workers (rayon / `spawn_blocking`); every walk
  checks its budgets cooperatively.
- Privacy: never log subjects, roots, or message bodies.
- Tests for every behaviour change; conformance cases live in
  `tests/cases/` in the corpus format of `conformance.md`.

## Specs

| Spec | Topic |
| --- | --- |
| [specs/architecture.md](specs/architecture.md) | Components, crates, threads |
| [specs/graph-engine.md](specs/graph-engine.md) | Packed CSRs, tiers, residency |
| [specs/resolver-engine.md](specs/resolver-engine.md) | Walk, root field, guardrails |
| [specs/ingest-storage.md](specs/ingest-storage.md) | Validation pipeline, event store |
| [specs/identity-bindings.md](specs/identity-bindings.md) | Binds on the server |
| [specs/sync-server.md](specs/sync-server.md) | Ingest endpoint, `dtp-sync` |
| [specs/api-privacy-operations.md](specs/api-privacy-operations.md) | Auth, config, observability |
| [../TrustGraph/specs/resolver-api.md](../TrustGraph/specs/resolver-api.md) | Protocol v1 |
| [../TrustGraph/specs/wot-model.md](../TrustGraph/specs/wot-model.md) | Model `dtp-wot/1` |
