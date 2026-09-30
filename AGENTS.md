# Agent guide (Global Server)

Rust Web-of-Trust resolver (`dtp-global`) and its Sync Server (`dtp-sync`).
Read [README.md](README.md), [PLAN.md](PLAN.md), and the specs before
changing code.

## Stack

- Rust 2024, stable toolchain. `rocksdb` (C++ RocksDB, event store) is the
  one native dependency; everything else is pure Rust: `k256` (BIP-340),
  `sha2`, `tokio`, `axum`, `tokio-tungstenite`, `serde_json`, `im`,
  `arc-swap`, `rayon`.
- Workspace crates under `crates/` (see
  [specs/architecture.md § Crates](specs/architecture.md#crates)).

## Commands

```text
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p dtp-server -- --config dtp-global.toml      # resolver
cargo run -p dtp-sync-server -- --config dtp-sync.toml   # Sync Server
cargo test -p dtp-conformance -- --nocapture             # corpus + session report
$env:DTP_CORPUS_STRICT="1"; cargo test -p dtp-conformance  # fail on any ../TrustGraph miss
node interop/resolver-client.mjs                         # optional: sessions via @dtp/resolver-client
```

Local pins (`tests/cases`, `tests/sessions`) must always pass. The
`../TrustGraph` corpus and sessions are report-only unless
`DTP_CORPUS_STRICT=1`. Gap cases (`gap:*`) assert `expectModel`; session
steps gate on `requires` / `otherwise` like the TS runner.

All three checks must be green before every commit. CI runs the same on
Ubuntu (`.github/workflows/ci.yml`).

### Building on Windows (MSVC pin)

`rust-toolchain.toml` pins `stable-x86_64-pc-windows-msvc` with clippy and
rustfmt; rustup picks it up in this directory whatever the global default
is. Needs Visual Studio 2022 with the C++ workload (`cl.exe`) — RocksDB is
compiled by `librocksdb-sys` through `cc` (no CMake) — and libclang for
bindgen (the crate has no pregenerated bindings). A user-level libclang:

```powershell
rustup toolchain install stable-x86_64-pc-windows-msvc --profile minimal -c clippy,rustfmt
python -m pip install --user libclang
$env:LIBCLANG_PATH = "$env:APPDATA\Python\Python312\site-packages\clang\native"   # before cargo
```

The first build compiles RocksDB (≈ 4 min). The old GNU `llvm-dlltool`
PATH workaround is not needed. Linux CI ignores the pin
(`RUSTUP_TOOLCHAIN=stable`) and installs `g++ clang libclang-dev`.

Keep tokio's `parking_lot` feature (and `full`) off: it crashed at process
start on the former `windows-gnu` setup.

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
  `tests/cases/` in the corpus format of `conformance.md`; session scripts
  are pinned in `tests/sessions/` (copies of `../TrustGraph/corpus/sessions`).

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
