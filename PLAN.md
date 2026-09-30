# Global Server — implementation plan

Status: **G0 done, G1/G2 largely done, G3 started** · 2026-09-30

This plan maps the README increments G0–G5 to task checklists with
acceptance checks, records the decisions taken while building, and lists
what is not built yet. `[x]` = done and tested in this repository, `[ ]` =
open.

## Session log

| Session | Delivered |
| --- | --- |
| 2026-09-30 (1) | Repository, toolchain, workspace and CI; G0 (model, graph, exact walk with binds and guardrails, lookups, conformance runner); G1/G2 server slice (redb store, WebSocket endpoint with every DTP operation, NIP-42/43, admin telemetry, `dtp-global` binary); `dtp-sync` basic; G3 root-field fast path for batches |

### Results at the end of session 1

| Check | Result |
| --- | --- |
| `cargo fmt --all --check` | clean |
| `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| `cargo test --workspace` | 73 test functions green (unit + integration), including 6 end-to-end server tests and 2 Sync Server tests |
| Local conformance cases (`tests/cases`, corpus format) | 73 / 73 (walk, threshold, all 13 binding situations × 2 modes, rating, lookups, frontier, neighborhood, budgets, NIP-09, ops, 25 signed protocol cases) |
| TrustGraph corpus (`../TrustGraph/corpus`, 106 cases) | 105 / 106 — the remaining case conflicts with wot-model §6.1 (see recommendations) |
| Properties on every model case | order independence (reversed + 2 shuffles), idempotence, batch = single, strict needs a claim, pages add up, counts = items, **field = walk**; plus field = walk on 12 seeded random graphs (> 2 000 comparisons, both modes, trust and rating) |
| Measured (`cargo run --release -p dtp-resolve --example measure`, 200 k edges / 20 k nodes) | hot format 19.6 B/edge (target ≈ 12: `trust_out` still carries edge ids and per-node directories), cold columns 96 B/edge (in-RAM structs), core 44 B/node; graph apply ≈ 190 k edges/s on one thread (signatures excluded); root field build 0.1 ms, 17 µs per subject vs 111 µs per exact walk |

## Decisions

| ID | Decision | Rationale |
| --- | --- | --- |
| D-toolchain | Rust stable 1.98 on `x86_64-pc-windows-gnu` (rustup, user level) on the dev machine; CI on Ubuntu | MSVC build tools are not installed and must not be. The GNU toolchain's `dlltool` cannot run (no assembler), so `llvm-ar` from the `llvm-tools` component is used as `dlltool` (see AGENTS.md). The code is target-independent. |
| D-tokio-features | Explicit tokio features, never `full` / `parking_lot` | With LLVM-generated raw-dylib import libraries on `windows-gnu`, `parking_lot_core` crashes the process before `main`. No functional impact. |
| D-crypto | `k256` (pure Rust) for BIP-340 verify and sign; `sha2` for ids and `d` | No C compiler needed (`secp256k1` crate needs one). Slower verify than libsecp256k1; revisit behind a feature flag with the G3 ingest benchmarks. |
| D-store (GS-D1, provisional) | `redb` behind the `EventStore` trait | Pure Rust, single file, ACID. RocksDB stays the spec's recommendation; the trait keeps the switch local to `dtp-store`. GS-D1 stays open until the G3 ingest benchmarks. Recorded in specs/ingest-storage.md. |
| D-mmap | Base CSR is `Vec<u32>` in the final on-disk layout; memory-mapped segment files deferred | Segment files will hold exactly these arrays (dense offsets, bucket directories, packed entries, parallel edge ids). |
| D-tiers | Two tiers now: immutable base + persistent RAM delta (`im::HashMap<NodeId, Arc<Run>>`), dead bits over base edges, `compact()` = base rebuild (also run after replay and when the delta passes 1 M entries) | Proves tier and dead-bit semantics (tested: reads identical before/after compaction) before files exist. |
| D-edge-ids | Edge ids are allocation order, not renumbered by subject at rebuild | Slots reference edges; renumbering comes with the store-backed rebuild. |
| D-trust-out-ids | `trust_out` runs carry edge ids | Simpler than a binary search into the peer's `trust_in` run; costs ≈ 4 B per person edge (part of the 19.6 B/edge). Noted in specs/graph-engine.md. |
| D-other-out | Non-person outgoing winners (post trust, `e`, other `i`, ratings) have an in-memory per-author index | Lets the pure model answer outgoing lookups without the store. Noted in specs/graph-engine.md. |
| D-epochs | The single writer thread publishes a new epoch after each ingest batch, before answering its `OK`s | A client that got `OK` sees its statement at once; the spec's ≤ 250 ms bound holds trivially. |
| D-witness-degree | `binding.witnessDegree` = witness author's level + 1 (own witness = 1) | Mirrors `degree`. Needs confirmation in TrustGraph. |
| D-budget-count | Node budget = distinct reached `p` nodes (root included) after a level; record budget = entries in the hop buckets of the qualifying frontier authors (active or not), checked before the level is built | Matches the corpus case `gap-g10-node-budget`; wot-model §6.2 should define the counters. |
| D-lookup-selected | `selected` mode: per (author, key, kind) the §4.3 statement over the filter's buckets (inactive records excluded unless `includeInactive`), then `values` / `labels` / `since` / `until`; `contextMatch: any` selects by the tie-break alone (scopeRank, newer, lower id) | `any` follows the corpus; the filter order is not specified in wot-model §8.1. |
| D-neighborhood | `graph.neighborhood` returns 32009 edges (hop context chain, default `identity`) plus 32014 rating arrows (display value 1 if score ≥ 50 else −1); `valueFilter` accepts `all` / `both` / `trust` / `distrust` / `neutral` or value arrays; edges carry `kind` | Follows the corpus (`neighborhood-post-rating-arrows`). |
| D-frontier-via | `graph.frontier` `via` = the discovering author (lowest pubkey among supporters) | Follows the corpus; specs/resolver-engine.md updated (it said "lowest supporting event id"). |
| D-g5 | Node keys keep the case of `web:` paths and `nostr:addr:` identifiers; everything else is lowercased | Gap G5 model rule; corpus `gap-g5-web-subject-case`. |
| D-disconnected-binding | `binding` of a disconnected result is the bind at the last level examined; a subject no record can address stops at level 0 (walk and field alike) | Keeps results independent of which path answered (found by the random field = walk test). |
| D-kind5 | A kind 5 with a malformed `e` tag is invalid; one without held targets (no `e`, no own-author `a` of a held kind, or `k` tags naming only other kinds) is valid but `blocked`; an `e` id the server does not hold leaves a tombstone so a later push by its author is `blocked: deleted` | Corpus protocol cases; avoids reviving events that arrive after their deletion. The kind 5 itself is not stored. |
| D-10011-winner | Any signature-valid kind 10011 is the author's replaceable winner; the claim exists only if the twitter tags validate | "Invalid → treated as none" and "revoked → no claim" (identity-binding §3). |
| D-writer-limit | `maxWriterConnections` is enforced at `AUTH` (the pubkey is unknown at upgrade) | resolver-api says "refused at upgrade". |
| D-coverage | Results omit `coverage` (always complete) | No `want` / root-warming path yet; the TS DTOs have no `coverage` either. |
| D-nip11 | NIP-11 `supported_nips` = 1, 9, 11, 42, 43 (86 omitted until NIP-86 exists) | Honest capability list; resolver-api lists 86. |

## Increments

### G0 — model, graph, walk, corpus runner (no network) — **done**

`dtp-model`
- [x] NIP-01 id hash (JSON.stringify-compatible escaping), BIP-340 verify / sign (`k256`); BIP-340 and NIP-19 vectors
- [x] NIP-32009 / NIP-32014 checklist incl. `d` recomputation (NIP material examples), one-subject rule, hints (npub / structured), `v` / `score` grammar, `x`/`y`, content limit, labels + sanitized descriptions
- [x] Scope profile `x.com` (eligibility, `scopeRank`), `hintPubkey`
- [x] Normalization to `EdgeRecord` (score micro-units, JS-compatible numbers)
- [x] NIP-39 kind 10011 claims; NIP-09 kind 5 parsing
- [x] Integer percent (= JS `Math.round`, exhaustively tested), bands, knob clamps

`dtp-graph`
- [x] Stable `u32` NodeIds; compact keys (hex 32 B, `user:id`/`post:id` `u64` when digits round-trip, strings otherwise)
- [x] Packed entries `node:28|value:2|window:1|siblings:1`
- [x] `trust_in` / `trust_out` / `rating_in` CSRs grouped by bucket; base + delta + dead bits; `compact()`
- [x] Context buckets and chains (32014 exact only — G1 fixed)
- [x] Slot winners, Delete winners, older-discarded, NIP-09 floors (`e` / `a`), tombstones; G3 fixed (a Delete touches its own slot)
- [x] Binding indexes: `witness_in`, `hinted_as`, `claims`
- [x] Stats and bytes-per-edge estimate
- [ ] Memory-mapped segment files (L1 flush, merge, restart from segments) → G1 remainder
- [ ] `u64` entries past 2^28 nodes → G3

`dtp-resolve`
- [x] Exact walk (§6) with §4.3 tie-break (G2 fixed), separate hit / peer counters (G7), disconnected ⇒ no statements (G4)
- [x] Per-walk binding, lenient and strict, own evidence as an optional input (never used by the server); binding provenance
- [x] Guardrails §6.2: node / record budgets, deadline per level and every 4 096 records, `completeDepth`, reasons
- [x] Results identical to the TS DTOs (statements, `contextMatch`, `distance`, `direct`, resolution, rating mean, label filter, `own`, `statementLimit`, path format, `ratingEdges`)
- [x] Lookups §8.1 (incoming / outgoing / counts / batch, filters, `selected` / `raw`, `mergeKeys`, orders, keyset cursor, totals), neighborhood, sync frontier, `graph.field`

`dtp-conformance`
- [x] Runner for `dtp-wot-corpus/1` (placeholders incl. keys, ops incl. `delete`, `modes`, `budgets`, `pages`, `expect.lenient` / `.strict`, `gap:*` → `expectModel`, protocol verdicts with `prefix` / `record` / `claim` / `deletion`), canonical comparison per `corpus/README.md`
- [x] Local cases in `tests/cases` (73); TrustGraph corpus read automatically (report-only unless `DTP_CORPUS_STRICT=1`)
- [x] Properties listed above
- [ ] Differential fuzzing against the TS runner (needs `@dtp/conformance` output) → G3

### G1 — store, ingest endpoint, `dtp-sync`

- [x] `dtp-store`: `EventStore` trait + redb (`slots` incl. 10011 winners, `by_id`, `by_author`, `log`, `tombstones`, `meta`; floors in slot values)
- [x] Replay of the event store into the graph at start-up (floors, tombstones, winners; then `compact()`); tested across a restart
- [x] WebSocket endpoint: NIP-01 framing, `EVENT` pipeline (shape, kind, dedup before signature work, id + signature on the blocking pool, NIP rules, scope profile, slot reduction, store write, epoch publish) with `OK` prefixes, per-connection pending-`OK` window with TCP backpressure (reads pause)
- [x] NIP-42 `AUTH` (kind, ±10 min, challenge, relay URL), `auth.reads` / `auth.writes` with `auth-required:` / `restricted:`
- [x] NIP-43: kind 13534 signed by the server key, 33534 role events, served by `REQ`; members in the store, from config and the `dtp-global members` CLI
- [x] `dtp-sync`: relay backfill (`until` pages) + live subscription for the held kinds and kind 5 (`#k`), dedup and id/signature pre-filter, NIP-42-authenticated push to every target with a pending window, reconnect with backoff; tested against a mock relay and a real resolver
- [ ] Delta → L1 flush and merges, restart from segments (needs mmap)
- [ ] NIP-86 management over HTTP (NIP-98) — `POST /` answers 501 today
- [ ] `dtp-sync`: durable cursors and per-target positions, NIP-11 limits, per-relay health, admin pages

### G2 — read operations, quotas, telemetry, single node

- [x] Every `DTP` operation of resolver-api v1: `session.update`, `info`, `trust.*`, `rating.*`, `lookup.*`, `graph.neighborhood`, `graph.frontier`, `graph.field`, `identity.claims`, `subscribe` / `unsubscribe`, `DTP-CANCEL`, `graph` pushes (coalesced ≤ 4/s, `changed.subjects` up to 500)
- [x] Guardrails: `busy` past `maxInFlight`, batch / key / page caps, deadlines, statement / path / neighborhood limits, message size, unsent-output cap (slow clients dropped), per-IP connections, writer connections per pubkey, keepalive pings and idle close
- [x] NIP-11 document, `/healthz`, `/readyz`
- [x] Admin listener: `/admin/api/telemetry` (all `dtp-telemetry/1` sections, `null` where n/a), `/admin/api/stream` (SSE every 2 s), `/metrics` (`dtp_*` + `dtp_impl_*`), placeholder page
- [x] TOML config (`dtp-global.example.toml`), server key from env / file / generated
- [ ] Cost-unit rate limiting (`rate-limited`)
- [ ] `/admin/api/history` ring buffers (501 today); warm / cold latency split (cold is always empty)
- [ ] Embedded `@dtp/telemetry-ui` assets (not published yet)
- [ ] Session suite against the Personal Server (needs `corpus/sessions`)

### G3 — root fields, parallel batch, residency, benchmarks

- [x] Root field (`dtp-resolve::field`): levels built once, hit test per subject; used by `trust.batch` / `rating.batch` for eligible items (`K = 32014`, or `SC = TC`, not path format); property field = walk
- [ ] Field cache across requests (LRU by bytes, epoch invalidation with Bloom filters of `Q[≤D−2]`, claim filter for strict, `validUntil`)
- [ ] Parallel batch on rayon; prefetch; background completion after the deadline
- [ ] Residency: pinning, `MADV_WILLNEED`, hot-page list, locality layout
- [ ] Benchmarks at 1 B resident / 5 B disk-backed edges; decide GS-D7; bring hot format to ≈ 12 B/edge

### G4 — retention, warmth, activation, binding mode

- [x] Per-root binding (lenient and strict) — in G0
- [ ] Anchors / reached / unreached classes, per-author caps, eviction
- [ ] Root activation, `want` pushes, `coverage` / `claims-pending`

### G5 — frontier / field ops, NIP-86, negentropy, beta

- [x] `graph.frontier`, `graph.field` operations (exact, uncached)
- [ ] NIP-86 management with NIP-98
- [ ] Negentropy (NIP-77) in `dtp-sync`
- [ ] Public beta with privacy policy

## Not built — how the server answers today

| Surface | Answer |
| --- | --- |
| NIP-86 `POST /` (`application/nostr+json+rpc`) | HTTP 501 with `{"error": "unsupported: …"}` |
| `/admin/api/history` | HTTP 501 |
| `want` topic | subscription accepted; no demands are ever pushed |
| `coverage` topic | subscription accepted; never pushes (no warming) |
| `rateLimit` cost units | not enforced (no `rate-limited` answers) |
| Config sections `retention`, `memory`, `residency`, `limits` | accepted, listed under `notImplemented` in the admin config |

Every protocol v1 operation is implemented, so no `DTP-ERR unsupported`
answers exist today.

## Recommended TrustGraph spec changes (not edited from here)

1. **Corpus `context-neutral-occupies-its-bucket`** expects `direct` on a
   disconnected result (TS leaks the last degree's Neutral, gap G4). Either
   tag it `gap:G4` with an `expectModel` without `direct`, or change
   wot-model §6.1 to the G4 alternative.
2. **wot-model §6.2** should define the node and record counters exactly
   (D-budget-count) and whether hit checks count toward the record budget.
3. **identity-binding §8**: define `witnessDegree` (proposal: witness author
   level + 1) and which level a disconnected result's `binding` reports
   (proposal: the last level examined; level 0 when nothing can address the
   subject).
4. **wot-model §8.1**: state that `values` / `labels` / `since` / `until`
   apply after selection in `selected` mode, and that `contextMatch: any`
   selects by the §4.3 tie-break alone.
5. **resolver-api**: `graph.neighborhood` should document rating arrows,
   the `valueFilter` words, and `edges[].kind`; `graph.frontier` `via` should
   say "discovering author"; `statementLimit` should say whether
   `sourceEventIds` lists all evidence (this server: all) or only the listed
   statements; `supported_nips` should only list 86 where it exists.
6. **conformance.md** protocol cases: publish the error-code vocabulary (this
   runner compares only `valid` / `prefix` / `eligible` / record fields
   against the corpus).
7. **JS number formatting**: scores below 0.001 print differently in
   JavaScript (`0.000001`) and in `serde_json` (`1e-6`); the session suite
   should compare numbers, not bytes, or restrict score precision.

## Blockers and open decisions

- **GS-D1** (RocksDB vs redb): redb in use; decide after G3 ingest benchmarks.
- **GS-D7** (mmap vs buffer pool): not started; needs the segment files.
- **GS-D5** (default binding mode): `lenient` (config `model.binding_mode`,
  applied under session defaults together with the threshold knobs).
- **GS-D2** (rust-nostr vs own client): minimal own client in `dtp-relay`.
- **Session suite / telemetry UI**: waiting on `corpus/sessions` and
  `@dtp/telemetry-ui` from TrustGraph.
