# Global Server — ingest and storage

Status: **draft** · 2026-09-30

The Global Server is strictly a WoT graph: it ingests kinds `32009`, `32014`,
and `10011` and nothing else — no kind `0`, no X identity or post data, no
client identity evidence. It does not connect to relays; whitelisted writers
push events into its ingest endpoint ([sync-server.md](sync-server.md)).

Two stores, both on disk, one of them mostly in RAM:

| Store | Holds | Medium |
| --- | --- | --- |
| **Graph store** | Every eligible winner, as packed segments clustered by subject and by author ([graph-engine.md](graph-engine.md)) | Memory-mapped files: as much in RAM as the budget allows, the rest paged in by subject |
| **Event store** | Every eligible winner with its signature; slot winners; ingest log | RocksDB |

There is no separate "not loaded" tier: every accepted winner is in the graph
store. RAM decides how much of it is warm, not whether it exists.

## Input

| Source | Kinds | Rule |
| --- | --- | --- |
| `EVENT` on the WebSocket (the shared ingest, [resolver-api.md § Ingest](../../TrustGraph/specs/resolver-api.md#ingest-event)); with the Global setting `auth.writes = members`, only authenticated writers with role `write` | `32009`, `32014`, `10011`, and NIP-09 kind `5` deletions targeting them | Same validation and deletion rules as every server |

Every event goes through the same pipeline, whoever sends it. Several writers
may deliver the same event; it is deduplicated by id.

## Validation pipeline

Stages run in order; each drops what it rejects, counts the reason, and
answers the writer with the matching `OK` prefix.

| # | Stage | Where | Cost | `OK` on reject |
| --- | --- | --- | --- | --- |
| 1 | Size and shape (JSON ≤ 64 KB, kind allowlist, tag arity) | connection task | trivial | `invalid:` / `blocked:` |
| 2 | Duplicate id (recent-ids LRU, then store `by_id`) | connection task | cheap | `true, duplicate:` |
| 3 | Event id = SHA-256 of the NIP-01 serialization | rayon | cheap | `invalid:` |
| 4 | Schnorr signature (`secp256k1`) | rayon | ~30–50 µs | `invalid:` |
| 5 | NIP-32009 / NIP-32014 rules, `d` recomputation, normalization to a record | rayon | cheap | `invalid:` |
| 6 | Scope profile `x.com` eligibility and `scopeRank` | rayon | trivial | `blocked:` |
| 7 | Slot reduction against the stored winner | store read | point lookup | `true, duplicate: older than winner` |
| 8 | Retention check (per-author and total caps, below) | memory | trivial | `rate-limited:` / `blocked:` |
| 9 | Event-store write (winner, `by_id`, log) | store | batched | `error:` |
| 10 | Graph writer: packed entry into the delta, dead bit on the replaced edge | writer thread | ≈ 1 µs | — |
| 11 | `OK true` after the batch is durable | connection task | — | — |

Stage 5 is `dtp-model`, which mirrors `@dtp/trust-protocol` and passes the
protocol corpus ([conformance.md](../../TrustGraph/specs/conformance.md)). It
also extracts `hintPubkey`: the first bare `npub1…` hint on a `user:id`
statement whose scope set contains `x.com`.

Kind `10011` goes through stages 1–4 and a NIP-39 claim check (`twitter` +
matching `twitter_id`), then is stored as the author's replaceable winner. It
never becomes a graph edge; the graph writer updates the `claims` index from
it ([identity-bindings.md](identity-bindings.md)). Only the claim pair
`(pubkey, twitter_id)` is used; the handle is not.

**Backpressure.** At most 5 000 events per connection wait for `OK`; when the
validation queue is full the server stops reading writer sockets, so writers
slow down by TCP instead of growing queues.

## Slot reduction

Per `addressKey` (`kind:pubkey:d`), exactly as the model §2.4:

- newer `created_at` wins; tie → lower `id`;
- older than the stored winner → discard (also after a Delete);
- a new winner replaces the stored event in the same write batch and marks
  the previous graph edge dead;
- a Delete winner is stored, and only marks the previous edge dead;
- a NIP-09 kind `5` from the slot's author removes the named winner (`e`) or
  the slot (`a`), marks its edge dead, and stores the slot's **floor**; events
  for that slot at or below the floor are refused with `blocked: deleted`
  (model §2.4). The kind `5` itself is not stored.

## Write path into the graph store

1. The graph writer appends the packed entry to the delta (RAM) and sets the
   replaced edge's dead bit; the next epoch makes it visible to queries.
2. When the delta passes 256 MB or 60 s, it is flushed as an L1 segment
   (subject-clustered and author-clustered files, cold columns in subject
   order) and the flushed event-store sequence is recorded.
3. Background merges keep the number of segments small and rebuild the base
   when needed ([graph-engine.md § Tiered segments](graph-engine.md#tiered-segments)).

A new statement is queryable within one epoch (≤ 250 ms) of its `OK`, before
any flush.

## Retention and warmth

Author-unfiltered input invites Sybil floods: millions of fresh keys trusting
each other. Resolution is root-relative, so a cluster no real root can reach
changes no answer and is never paged in by a walk; it only costs disk. So
reachability no longer decides what is loaded; it decides what is kept warm
and what is dropped first when disk is short.

| Class | Who | Warmth | Retention |
| --- | --- | --- | --- |
| **Anchors** | Operator seed pubkeys; roots active in the last 30 days (from session defaults) | Frontiers re-touched hourly; pinned first when pins are short | Never evicted |
| **Reached** | Authors reachable from any anchor within `D_reach` (default 6) through the sync frontier walk (positive 32009, no threshold, no fan-out caps) | Resident as the page cache allows | Kept |
| **Unreached** | Everyone else | Paged in only if a walk reaches them | Capped per author (default 20 000 slots) and in total (disk budget); the longest-unreached authors are evicted first when the budget is hit |

- Reachability is recomputed incrementally from each epoch's change summary,
  and fully once per day.
- Eviction deletes the author's winners from the event store (`by_author`)
  and marks their edges dead; the next merge drops them from the files.
- An evicted author who becomes reachable again is simply accepted again when
  a writer delivers their events.
- Kind `10011` winners are kept for every author (they are small); the
  `claims` index covers all of them.

### Root activation

A query for a root that is not an anchor makes it one. Its data is already in
the graph store, so activation is about speed, not completeness:

1. The first query runs immediately. Cold pages are prefetched level by level
   ([graph-engine.md § Loading a subject fast](graph-engine.md#loading-a-subject-fast)).
   If the deadline stops the walk, the result is exact up to its
   `completeDepth` and the build continues in the background
   ([resolver-engine.md § Guardrails](resolver-engine.md#guardrails)).
2. The root's frontier is added to the hourly re-touch set.
3. Authors the event store has never seen are requested from writers with a
   `want` push ([sync-server.md § Optional demand hints](sync-server.md#optional-demand-hints)).
   While such requests are open, results carry `coverage: partial` with
   `root-warming`; a `coverage` push goes to subscribed connections when they
   complete.

Activation work is queued and rate-limited per client.

**Strict-mode claims.** A hinted npub whose `10011` is not in the event store
is also requested with a `want` push; results meanwhile carry
`claims-pending`.

## Event store

RocksDB behind the `EventStore` trait (decision GS-D1: RocksDB vs a
pure-Rust engine such as `redb`). Column families:

| Column family | Key | Value |
| --- | --- | --- |
| `slots` | `kind (u16) ‖ author (32 B) ‖ d (32 B)` | Winner: compact encoding of the seven NIP-01 fields, `first_seen`, ingest `seq`, current graph edge (`segment ‖ index`, or none for a Delete); or, after a NIP-09 deletion, only the slot floor |
| `by_id` | event id | slot key |
| `by_author` | author ‖ slot key | Outgoing lookups for post trust and ratings (they have no in-memory out-entries); retention and eviction |
| `log` | ingest `seq` (u64, big-endian) | slot key — delta replay after a restart, segment rebuilds |
| `replaceable` | `10011 ‖ author` | Kind `10011` winner |
| `claims` | `twitter_id (u64) ‖ pubkey` | Claim event id, for `identity.claims` |
| `reach` | author | Class, last reached time, slot count |
| `meta` | string | Schema version, flushed sequence, watermarks |

> **v1 implementation note (PLAN.md D-store).** The first build uses `redb`
> (GS-D1 still open) with tables `slots`, `by_id`, `by_author`, `log`,
> `tombstones`, `meta`. Kind `10011` winners live in `slots` under
> `10011 ‖ author ‖ ""` (the `replaceable` family); the `claims` and `reach`
> families are not stored yet: claims are rebuilt from the replaceable
> winners at start-up, and retention classes are not built. A kind `5` that
> names an id the store does not hold leaves a `tombstones` entry so the
> event is refused if its author pushes it later.

The event store is on the query path only for `REQ` by id and for outgoing
lookups of post trust and ratings (`by_author`): walks, hit tests, and every
other lookup read the graph store; evidence display reads the cold columns.

Rules carried over from the extension: store the seven signed fields (enough
to re-serve and re-verify), keep only winners, delete superseded events in the
same write batch, never keep local history of replaced statements.

Write batches are grouped (up to 10 ms or 5 000 events) and applied with the
WAL on. The graph edge reference in `slots` removes the need for an in-RAM
slot index.

## Throughput plan

- Signature verification dominates: about 25 000 events/s per core with
  `secp256k1`. With 8 cores for validation the pipeline exceeds the 20 000/s
  target with headroom for backfill bursts.
- Duplicates are rejected at stage 2, before any signature work, so writers
  that re-push after a reconnect cost little.
- The graph writer appends about 1 M entries/s to the delta; flushes and
  merges are sequential I/O in the background.
- Warm-up, re-touch, and eviction run at lower priority than live ingest and
  queries.
