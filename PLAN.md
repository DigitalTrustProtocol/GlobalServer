# Global Server — implementation plan

Status: **in progress** · 2026-09-30

This plan maps the README increments G0–G5 to task checklists with
acceptance checks, records the decisions taken while building, and lists
what is not built yet. `[x]` = done and tested in this repository, `[ ]` =
open.

## Session log

| Session | Delivered |
| --- | --- |
| 2026-09-30 (1) | Repository, toolchain, workspace, G0 model + graph + resolver + conformance runner, G1/G2 server slice (see checklists) |

## Decisions

| ID | Decision | Rationale |
| --- | --- | --- |
| D-toolchain | Rust stable `x86_64-pc-windows-gnu` on the dev machine (rustup, user level); CI on Ubuntu | MSVC build tools are not installed and must not be; the GNU toolchain bundles its linker. The code is target-independent. |
| D-crypto | `k256` (pure Rust) for BIP-340 verify and sign; `sha2` for ids and `d` | No C compiler needed (`secp256k1` crate needs one). ~2–3× slower verify than libsecp256k1; revisit with a feature flag when throughput benchmarks (G3) require it. |
| D-store (GS-D1, provisional) | `redb` behind the `EventStore` trait for v1 | Pure Rust, single file, ACID, no C toolchain. RocksDB stays the recommended production option in the spec; the trait keeps the switch local to `dtp-store`. GS-D1 stays open until the G3 ingest benchmarks. |
| D-mmap | Base CSR is `Vec<u32>` in the final on-disk layout; memory-mapped segment files deferred | The in-RAM layout (dense offsets, bucket directories, packed entries, parallel edge ids) is exactly what segment files will hold, so G1's flush writes these arrays and maps them back. |
| D-tiers | Two tiers now: immutable base + persistent RAM delta (`im::HashMap<NodeId, Arc<Run>>`), dead bits over base edges, `compact()` = base rebuild | Proves the tier/dead-bit semantics (property: results identical before/after compaction) before files exist. L1 segments come with mmap. |
| D-edge-ids | Edge ids are stable (allocation order), not renumbered in subject order at rebuild | Slots reference edges; renumbering needs the store-backed rebuild of G1. |
| D-trust-out-ids | Delta and base `trust_out` runs carry edge ids | Simpler than a binary search into the peer's `trust_in` run; 4 B per person edge. Revisit with segment files. |
| D-other-out | Non-person outgoing winners (post trust, `e`, other `i`, ratings) are indexed in memory per author (`other_out`) | The spec reads them from the event store's `by_author`; the in-memory index lets the pure model (conformance runner) answer outgoing lookups without a store. |
| D-witness-degree | `binding.witnessDegree` = witness author's level + 1 (own witness = 1) | Mirrors `degree` (root's own statement = 1). Needs confirmation in TrustGraph (see recommendations). |
| D-budget-count | Node budget = distinct reached nodes (root included) after a level; record budget = entries scanned while expanding (all chain buckets of qualifying frontier authors, active or not). A level that would exceed either is discarded | Deterministic; wot-model §6.2 does not define the counters exactly. Listed as a TrustGraph clarification. |
| D-lookup-selected | Lookup `selected` mode picks per (author, key, kind) the §4.3 statement over the filter's buckets (activity first unless `includeInactive`), then applies `values` / `labels` / `since` / `until`; `contextMatch: any` orders buckets by context string | wot-model §8.1 does not say whether value filters apply before or after selection. |
| D-kind5-unknown | A kind 5 naming an event id the server does not hold stores a tombstone `(id → deleter)`; the event is refused with `blocked: deleted` if its author later pushes it | Avoids reviving a deleted event that arrives after its deletion (writers race). The kind 5 itself is not stored. |
| D-10011-winner | Any signature-valid kind 10011 is the author's replaceable winner; the claim exists only if the twitter tags validate | "Invalid 10011 → treated as none" and "revoked → no claim" (identity-binding §3) both need the newer event to replace the old claim. |
| D-coverage | Results omit `coverage` (always complete): no `want` demand path yet | The TS DTOs have no `coverage` field either; added with G4. |

## Increments

### G0 — model, graph, walk, corpus runner (no network)

`dtp-model`
- [x] NIP-01 id hash (JSON.stringify-compatible escaping) and BIP-340 verify / sign (`k256`)
- [x] NIP-32009 / NIP-32014 validation checklist incl. `d` recomputation, one-subject rule, hints (npub / structured), `v` / `score` grammar, `x`/`y`, content limit, labels + sanitized descriptions
- [x] Scope profile `x.com` (eligibility, `scopeRank`) and `hintPubkey` extraction
- [x] Normalization to `EdgeRecord` (score in micro-units, JS-compatible number output)
- [x] NIP-39 kind 10011 claims; NIP-09 kind 5 parsing
- [x] Integer percent (= JS `Math.round`), bands, knob clamps
- Acceptance: unit tests incl. NIP-32009 material examples and the NIP-19 / BIP-340 vectors — **green**

`dtp-graph`
- [x] Stable `u32` NodeIds with compact keys (hex 32 B, `user:id`/`post:id` `u64` when digits round-trip, string arena otherwise)
- [x] Packed entries `node:28|value:2|window:1|siblings:1`
- [x] `trust_in` / `trust_out` / `rating_in` CSRs grouped by bucket with directories; base + delta + dead bits; `compact()`
- [x] Context buckets and chains (32014 exact only — G1 fixed)
- [x] Slot winners, Delete winners, older-discarded, NIP-09 floors (`e` and `a`), tombstones for unseen ids; G3 fixed (a Delete touches its own slot only)
- [x] Binding indexes: `witness_in` (hints by edge), `hinted_as`, `claims` (by X and by pubkey)
- [x] Stats and a bytes-per-edge estimate
- [ ] Memory-mapped segment files (L1 flush, merge, restart from segments) → G1
- [ ] `u64` entries past 2^28 nodes → G3
- Acceptance: unit tests (slot rules, floors, tombstones, sibling bits, compaction equivalence) — **green**

`dtp-resolve`
- [x] Exact walk (wot-model §6): level-synchronous BFS, nearest hitting degree, §4.3 selection with tie-break (G2 fixed), separate hit / peer counters (G7), disconnected ⇒ no statements (G4)
- [x] Per-walk binding, lenient and strict (identity-binding §4) with own evidence as an optional input (never used by the server)
- [x] Guardrails §6.2: node / record budgets (deterministic), deadline checked per level and every 4 096 records, `completeDepth`, `truncated`, reasons
- [x] Trust and rating result mapping identical to the TS DTOs (statements, `contextMatch`, `distance`, `direct`, `resolution`, rating mean, label filter, `own`, `statementLimit`, `binding` provenance, path format)
- [x] Lookups §8.1: incoming / outgoing / counts / batch, filters, `selected` / `raw`, `mergeKeys`, `recent` / `author` order, keyset cursor, totals
- [x] Neighborhood, sync frontier (lenient binds), `graph.field`
- [ ] Root field cache + hit test fast path with the property test field == walk → G3
- Acceptance: conformance cases in `tests/cases/` — see the report below

`dtp-conformance`
- [x] Runner for the corpus format (`@name` placeholders, ops, protocol and model cases, canonical comparison, `pages`, `expect.lenient` / `expect.strict`, `gap:*` → `expectModel`)
- [x] Reads `../TrustGraph/corpus/manifest.json` when present; local cases in `tests/cases/`
- [x] Properties on every model case: order independence, idempotence, batch = single, lookups ignore the observer, pages add up, counts = items
- [ ] Differential fuzzing against the TS runner (needs `@dtp/conformance` output) → G3

### G1 — store, ingest endpoint, `dtp-sync`

- [x] `dtp-store`: `EventStore` trait + redb (`slots`, `by_id`, `by_author`, `log`, `replaceable`, `claims`, `meta`; floors in slot values)
- [x] Replay the event store into the graph at start-up
- [x] WebSocket endpoint: NIP-01 framing, `EVENT` pipeline with `OK` prefixes, dedup by id, per-connection pending-OK window with TCP backpressure
- [x] NIP-42 `AUTH` (kind, ±10 min, challenge, relay URL), `auth.reads` / `auth.writes`
- [x] NIP-43 membership: kind 13534 signed by the server key, 33534 role events, served by `REQ`; members from config / CLI
- [x] `dtp-sync`: relay live + backfill for the held kinds, push to targets after NIP-42 (basic)
- [ ] Delta → L1 flush and merges, restart from segments (needs mmap)
- [ ] NIP-86 management over HTTP (NIP-98) — answered `unsupported` today
- [ ] `dtp-sync` durable cursors, NIP-11 limits, per-relay backoff telemetry

### G2 — read operations, quotas, telemetry, single node

- [x] Every `DTP` operation of resolver-api v1 (`session.update`, `info`, `trust.*`, `rating.*`, `lookup.*`, `graph.neighborhood`, `graph.frontier`, `graph.field`, `identity.claims`, `subscribe` / `unsubscribe`, `DTP-CANCEL`, `graph` pushes)
- [x] Guardrails: in-flight limit (`busy`), batch caps, deadlines, statement / neighborhood / path limits, message size
- [x] NIP-11 document, `/healthz`, `/readyz`
- [x] Admin listener: `/admin/api/telemetry` (shared field names, `null` where n/a), `/admin/api/stream` (SSE), `/metrics` (`dtp_*`), placeholder page
- [x] TOML config per api-privacy-operations.md
- [ ] Cost-unit rate limiting (`rate-limited`) and per-IP connection caps
- [ ] Embedded `@dtp/telemetry-ui` assets (not published yet)
- [ ] Session-suite run against the Personal Server (needs `corpus/sessions`)

### G3 — root fields, parallel batch, residency, benchmarks

- [ ] Root-field cache with epoch invalidation (Bloom of `Q[≤D−2]`, claim filter for strict), `validUntil`
- [ ] Field hit test (in-edge scan vs. binary search by side), property field == walk
- [ ] Parallel batch on rayon; prefetch; background completion after the deadline
- [ ] Residency: pinning, `MADV_WILLNEED`, hot-page list, locality layout
- [ ] Benchmarks at 1 B resident / 5 B disk-backed edges; decide GS-D7; measure bytes per edge on real segments

### G4 — retention, warmth, activation, binding mode

- [ ] Anchors / reached / unreached classes, per-author caps, eviction
- [ ] Root activation, `want` pushes, `coverage` / `claims-pending`
- [x] Per-root binding (lenient and strict) — done in G0

### G5 — frontier / field ops, NIP-86, negentropy, beta

- [x] `graph.frontier`, `graph.field` operations (exact, no cache)
- [ ] NIP-86 management, NIP-98 auth
- [ ] Negentropy (NIP-77) in `dtp-sync`
- [ ] Public beta with privacy policy

## Unsupported today (answered with `DTP-ERR unsupported` or HTTP 501)

| Surface | Answer |
| --- | --- |
| NIP-86 `POST /` (`application/nostr+json+rpc`) | HTTP 501 with a NIP-86 error body |
| `rateLimit` cost units | not enforced (no `rate-limited` answers yet) |
| `want` topic | subscription accepted, never pushes |

## Blockers and open questions

- **TrustGraph corpus**: not present at `../TrustGraph/corpus` when this
  session started; the runner reads it automatically when it appears.
- **GS-D1** (RocksDB vs redb), **GS-D7** (mmap vs buffer pool), **GS-D5**
  (default binding mode) need the owner's decision; defaults used: redb,
  in-RAM base, `lenient`.
