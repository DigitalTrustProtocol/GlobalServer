# Global Server

A public, high-performance Web-of-Trust resolver written in Rust, plus the
Sync Server that feeds it. The resolver keeps as much of a very large WoT
Graph in memory as the machine allows — about 12 bytes per edge — and loads
the rest by subject in one or two contiguous reads. The graph is built from
trust (`32009`), rating (`32014`), and identity-claim (`10011`) events; the
resolver answers queries for any root over long-lived WebSocket connections,
with multi-threaded, guard-railed resolution.

Status: **design** (specs only, no code yet) · 2026-09-30

## Strictly a WoT graph

- Kinds `32009`, `32014`, `10011` only.
- No kind `0` profiles, no X identity or post data, no identity evidence
  supplied by clients. A result depends only on public signed events.
- X data (accounts and posts a user has seen, their Bio evidence) stays in
  the Attention extension.

## Exactly the same API as the Personal Server

- **Protocol:** [resolver protocol v1](../TrustGraph/specs/resolver-api.md) —
  the same messages, operations, defaults, results, errors, auth, ingest,
  deletions, and guardrails as the Personal Server, proven by one shared
  session suite ([conformance.md § One API](../TrustGraph/specs/conformance.md#one-api-the-session-suite)).
  A client switches between the servers by changing the URL.
- **Model:** [TrustGraph wot-model.md](../TrustGraph/specs/wot-model.md)
  (`dtp-wot/1`). Equality with the TypeScript reference is proven by the
  [conformance corpus](../TrustGraph/specs/conformance.md) and nightly
  differential fuzzing.
- **Global configuration** of the shared settings: `auth.reads = open`
  (option `members` with the NIP-43 whitelist and NIP-42 challenge),
  `auth.writes = members` so only whitelisted writers push, tighter deadlines,
  and rate limits. Later the whitelist can be derived from the operator's web
  of trust.
- **Stance:** an optimization, not an oracle. Every answer cites signed events
  anyone can verify. No global rank, no objective score.

## Two binaries

| Binary | Role |
| --- | --- |
| `dtp-global` (resolver) | Compact in-memory graph, resolver, WebSocket endpoint; never connects to relays |
| `dtp-sync` (Sync Server) | Crawls relays and pushes events into one or more resolvers as an authenticated, whitelisted writer |

Any tool that can publish Nostr events with NIP-42 auth can feed a resolver
alongside or instead of the Sync Server. Several writers can push at once;
one Sync Server can feed many resolver replicas.

## Key design ideas

| Idea | Where |
| --- | --- |
| Standard ingest: `AUTH` + `EVENT`, whitelisted writers, TCP backpressure, optional `want` hints | [sync-server.md](specs/sync-server.md) |
| One packed format for disk and RAM (≈ 12 bytes per edge): "loading" is paging, no decoding | [graph-engine.md](specs/graph-engine.md) |
| Clustered by subject and author: a subject that is not in memory loads in one or two contiguous reads; batches and frontiers are prefetched in one submission | [graph-engine.md](specs/graph-engine.md#loading-a-subject-fast) |
| Residency priorities: core always resident, walk-critical files pinned when they fit, active roots kept warm, locality-aware layout | [graph-engine.md](specs/graph-engine.md#residency) |
| Tiered segments (RAM delta → L1 → base) with streaming merges | [graph-engine.md](specs/graph-engine.md#tiered-segments) |
| Memory budget with enforced shares and an RSS watchdog | [graph-engine.md](specs/graph-engine.md#memory-budget) |
| Immutable epoch snapshots; one writer; lock-free reads | [graph-engine.md](specs/graph-engine.md#epochs) |
| **Root field**: walk once per root, answer each subject in O(in-degree) | [resolver-engine.md](specs/resolver-engine.md#root-field) |
| Hard deadlines and node / record budgets with exact partial results | [resolver-engine.md](specs/resolver-engine.md#guardrails) |
| Every eligible winner is in the graph store; reachability from active roots decides warmth and what disk evicts first, and Sybil clusters are never paged in | [ingest-storage.md](specs/ingest-storage.md#retention-and-warmth) |
| Cold field builds return exact partial results within the deadline and finish in the background | [resolver-engine.md](specs/resolver-engine.md#guardrails) |
| Binds decided per root inside the walk from `32009` hints and `10011` claims | [identity-bindings.md](specs/identity-bindings.md) |
| Field mode: the server learns only the root | [api-privacy-operations.md](specs/api-privacy-operations.md#privacy-modes-for-clients) |
| Telemetry pages on localhost (same as the Personal Server): graph, ingest, sources, queries, memory, alerts | [api-privacy-operations.md](specs/api-privacy-operations.md#observability) |

## Specs

| Spec | Contents |
| --- | --- |
| [specs/architecture.md](specs/architecture.md) | Goals, scale targets, components, crates, threads, topology |
| [specs/sync-server.md](specs/sync-server.md) | Ingest endpoint, whitelist for writers, demand hints, the Sync Server |
| [specs/graph-engine.md](specs/graph-engine.md) | Graph store: what a walk touches, bytes per edge and node, packed CSRs, tiered segments, residency and locality, fast subject loading, binding indexes, epochs, restart, memory budget |
| [specs/resolver-engine.md](specs/resolver-engine.md) | Exact walk, root field, validity proof, parallel builds with prefetch, guardrails and background completion, cache, batch plan, warm and cold latency |
| [specs/ingest-storage.md](specs/ingest-storage.md) | Validation pipeline, slot reduction, write path, retention and warmth, root activation, event store |
| [specs/identity-bindings.md](specs/identity-bindings.md) | Why binds matter, public-events-only inputs, lenient vs strict, missing claims, verifier services |
| [specs/api-privacy-operations.md](specs/api-privacy-operations.md) | Authentication (NIP-42 / 43 / 86), quotas, privacy commitments and modes, config, deployment, observability |

## Increments

| ID | Increment |
| --- | --- |
| G0 | Spike: `dtp-model` + packed segment format + exact walk with guardrails; corpus runner green; bytes per edge measured; no network |
| G1 | Event store, delta → L1 flush and merges, restart from segments, WebSocket endpoint with `AUTH` + `EVENT` ingest and the NIP-43 whitelist, `dtp-sync` with relay live + backfill |
| G2 | `DTP` read operations, quotas, telemetry pages and `/metrics`, single-node test deployment |
| G3 | Root fields, parallel batch, residency (pinning, prefetch, warm-up, locality layout), benchmarks at 1 B resident and 5 B disk-backed edges (validates the targets; decides GS-D7) |
| G4 | Retention and warmth classes, root activation, per-root binding (lenient and strict), `want` hints |
| G5 | Frontier and field operations, NIP-86 management, negentropy in `dtp-sync`, public beta with privacy policy |
| Later | WoT-derived whitelist (`wot` membership source) |

## Open decisions

| ID | Decision |
| --- | --- |
| GS-D1 | Event store: RocksDB (recommended) vs a pure-Rust engine (`redb`) |
| GS-D2 | `rust-nostr` relay pool vs a minimal own client (Sync Server) |
| GS-D3 | Whether to run a verifier service (X OAuth, from `nip05-Server`) that publishes `c=identity:attest` witnesses, and whether to recommend it to users |
| GS-D4 | Operator and public endpoint domain; hosting |
| GS-D5 | Default `bindingMode` on the public endpoint (TrustGraph D5) |
| GS-D6 | Keep the Sync Server in this workspace (proposed) or move it to its own repo |
| GS-D7 | Residency mechanism: `mmap` + pinning + `io_uring` prefetch (proposed for v1) vs an explicit buffer pool of runs |
