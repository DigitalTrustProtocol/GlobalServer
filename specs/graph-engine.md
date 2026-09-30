# Global Server — graph engine (`dtp-graph`)

Status: **draft** · 2026-09-30

Goal: keep **as much of the graph in memory as the machine allows**, and load
the rest **fast, by subject**, when a query needs it. The engine implements
the node and edge rules of [wot-model.md](../../TrustGraph/specs/wot-model.md)
§2–§4 and the inputs of
[identity-binding.md](../../TrustGraph/specs/identity-binding.md). Reads are
lock-free while a single writer applies new winners.

Three decisions make that work:

1. **One format for disk and memory.** The graph is stored in compact, packed
   files (about 12 bytes per edge for everything a walk touches). They are
   memory-mapped, so "loading" a part of the graph is the OS paging in bytes
   that are already in their final layout: no parsing, no object building.
2. **Clustered by subject and by author.** All statements *about* a subject
   form one contiguous run; all person statements *by* an author form another.
   Loading a subject that is not in memory costs one or two contiguous reads.
3. **Memory is a cache with priorities.** A fixed core is always resident;
   the walk-critical files are pinned when they fit; everything else stays in
   the page cache as long as RAM allows, with prefetch for what queries are
   about to touch.

## What a walk touches, and what it does not

| Data | File | Residency |
| --- | --- | --- |
| Author of each incoming statement, value, flags (packed `u32`) | `trust_in.ent`, `rating_in.ent` | Hot format — pinned when it fits |
| Edge id of each incoming statement | `trust_in.ids`, `rating_in.ids` | Hot format |
| Peer of each outgoing person statement (`32009` with `p` or `user:id` subject) | `trust_out.ent` | Hot format; post and rating statements never expand, so they have no out-entry |
| Npub hint (`hintPubkey`), tie-break siblings, `x` / `y` windows | `hints`, `siblings`, `windows` (sparse, by edge id) | Hot format |
| Offsets and bucket directories per node | `*.off`, `buckets` | **Always resident** |
| Rating score, label set, event id, `created_at`, `scopeRank` | cold columns, by edge id | Page cache, lowest priority |
| `content`, labels with descriptions (display) | `display` blob, by edge id | Page cache, lowest priority |
| Signed events (`REQ` by id), slot winners | Event store (RocksDB) | Block cache |

Edge ids are assigned in **subject order**, so the cold columns and the display
blob for one subject's statements are contiguous too: the evidence for a hit
is one more contiguous read.

## Bytes per edge and per node

| Structure | Bytes per edge |
| --- | --- |
| Incoming entry (author + value + flags, packed `u32`) | 4 |
| Incoming edge id | 4 |
| Outgoing entry, person statements only (about 40 % of edges) | ≈ 1.6 |
| Hints, hinted statements only (about 25 %) | ≈ 2 |
| Dead-edge bits | 0.125 |
| **Hot format** | **≈ 12** |
| Cold columns + display blob | ≈ 50 (disk / page cache) |

| Structure | Bytes per node |
| --- | --- |
| Key: pubkey 32 B, `user:id` / `post:id` as `u64` 8 B, other `i` in a string arena | 8–32 (memory-mapped) |
| Sorted permutation for key lookup | 4 (memory-mapped) |
| Offsets, incoming and outgoing, and bucket directory | ≈ 12 (**always resident**) |

| Graph | Always-resident core | Hot format | Fits fully in RAM on |
| --- | --- | --- | --- |
| 200 M edges, 20 M nodes | ≈ 0.3 GB | ≈ 2.4 GB | 16 GB |
| 1 B edges, 100 M nodes | ≈ 1.4 GB | ≈ 12 GB | 32 GB |
| 5 B edges, 400 M nodes | ≈ 5.5 GB | ≈ 60 GB | 128 GB; on 64 GB the hottest part stays resident and the rest pages in by subject |

The graph's size is bounded by disk, not RAM; RAM decides how much of it is
warm. For comparison, the TypeScript heap uses roughly 300–500 bytes per edge.

## Nodes

`NodeId = u32`, assigned when a key is first seen and **never reused or
renumbered**, so every file and cache can refer to it.

| Node kind | Key storage (in id order) | Lookup |
| --- | --- | --- |
| `p`, `e` | `[u8; 32]` arena | Sorted permutation, binary search; a small hash map for nodes added since the last base rebuild |
| `i` `user:id:<n>`, `post:id:<n>` | `u64` when the digits round-trip (no leading zero, fits `u64`) | Same |
| Any other `i` | String arena (lowercased, model G5) | Hash map (rare) |

`user:id:0123` does not round-trip, so it is stored as a string: it is a
different subject from `user:id:123`, exactly as in TypeScript.

Past 2^28 nodes the packed entries switch to `u64` (see below); ids stay
`u32` up to 4 G nodes.

## Packed adjacency

An entry is a `u32`: `node:28 | value:2 | window:1 | siblings:1`. Value
encoding for `32009`: `0` Neutral, `1` Trust, `2` Distrust. A deployment past
2^28 nodes writes `u64` entries in its next base.

| CSR | Keyed by | Entries | Sort order inside a node |
| --- | --- | --- | --- |
| `trust_in` | subject node | authors of `32009` statements | bucket, then author |
| `trust_out` | author | subjects of person `32009` statements | bucket, then subject |
| `rating_in` | subject node | authors of `32014` ratings | bucket, then author |

`trust_out` carries no edge ids: a path query finds a hop statement in the
peer's sorted `trust_in` run by binary search on the author.

### Tie-breaks resolved at write time

Model §4.3 picks one statement when an author has several active records to
the same subject in one bucket (for example an empty-scope and an `x.com`
slot). When the writer adds such a record, it probes the subject's runs for
that author (binary search) and, if a sibling exists, sets the `siblings` bit
and records the group in the side table, ordered by (`scopeRank`,
`created_at`, `id`). The side table is read only when the head is inactive
(`window` bit) or when a bind puts `p:P` and `user:id:X` records of one
author on the same node, both rare. Base rebuilds fold groups back into one
head per group.

## Tiered segments

The graph is a small LSM of immutable CSR segments, newest first:

| Tier | Contents | Medium | Created by |
| --- | --- | --- | --- |
| Delta | Edges accepted since the last flush; per-node packed runs in a persistent map (`im::HashMap<NodeId, Arc<[u32]>>`) | RAM | Graph writer, every epoch |
| L1 segments (≤ 8) | Nodes touched since the base, with sparse offsets (`(NodeId, offset)` pairs) | Memory-mapped files | Flush when the delta passes 256 MB or 60 s |
| Base segment | Every node, dense offsets | Memory-mapped files | Background rebuild |

- A node's statements are its run in the base, plus its runs in each L1
  segment, plus the delta, minus dead edges. Every run is sorted by bucket
  then author, so reading a node is a small k-way merge.
- **Dead bits** (one per edge, per segment, in RAM) mark edges replaced by a
  newer winner or cleared by a Delete. Deletes are not edges (model's per-slot
  rule; gap G3 fixed by construction).
- **Merges:** L1 segments merge into one when there are more than 8; the base
  is rebuilt when L1 passes 25 % of the base or dead edges pass 20 %. A
  rebuild is a streaming merge by node id: sequential reads and writes, a
  small constant memory footprint, and no second copy of the graph in RAM.
- Swaps happen at an epoch boundary; readers pinned to older segments keep
  them alive until they finish.

## Residency

| Priority | What | How it is kept in RAM |
| --- | --- | --- |
| 1 — always | Offsets, bucket directories, dead bits, delta, node lookup for recent nodes, claims index | Pre-faulted and `mlock`ed |
| 2 — pinned when it fits | Hot format of the base and L1 (`*.ent`, `*.ids`, `hints`, `siblings`, `windows`) | `mlock` up to the pin share of the memory budget; newest segments and `trust_out` first |
| 3 — cached | Unpinned hot format | Page cache; `MADV_WILLNEED` prefetch for queries in flight and for active roots' frontiers |
| 4 — cold | Cold columns, display blob, RocksDB blocks | Page cache, `MADV_RANDOM` (no readahead) |

When the hot format fits in the pin share, the **whole graph a walk touches
is in RAM** and walks never wait on disk. When it does not, the most recently
used parts stay warm, and a background task re-touches the frontiers of roots
active in the last hour so they stay resident.

### Locality-aware layout

A base rebuild also chooses the byte order of nodes in its files (a
"layout position", 4 bytes per node, resident): a breadth-first order from the
most active roots, so authors that are usually reached together share pages.
A root's first levels then fit in few pages, and loading a cold neighborhood
reads fewer, larger contiguous ranges. `NodeId`s do not change; only the file
order does.

## Loading a subject fast

| Step | Cost when not resident |
| --- | --- |
| Key → `NodeId` | Binary search in the memory-mapped permutation (upper levels stay cached) |
| Offsets for the node in each segment | RAM (always resident) |
| Incoming run: entries + edge ids | One contiguous range per file per segment — usually 1–2 pages each |
| Evidence display for the hits | One contiguous range in the cold columns and display blob (edge ids are in subject order) |
| Full signed event (`REQ` by id) | RocksDB point lookup |

On NVMe that is about 0.1–0.3 ms for a cold subject, issued in parallel.

**Batched prefetch.** Before hit-testing a batch, the resolver computes the
page ranges of every subject's runs and submits them at once (`io_uring` reads
into the page cache on Linux, `MADV_WILLNEED` elsewhere), then hit-tests when
they are resident or the deadline nears. A field build does the same per level:
the level-synchronous walk knows the entire next frontier before it expands
it, so all its out-runs are prefetched in one submission. Compute threads
rarely block on a page fault.

The prefetch path is the only place that does I/O on behalf of a query; the
walk itself reads memory. Whether to keep `mmap` + prefetch or move to an
explicit buffer pool (own cache of runs, loaded with `io_uring`) is decided
from G3 benchmarks (decision GS-D7).

## Contexts

`ContextTable` interns bucket strings (`"32009:security:access"`). Each 32009
entry stores its parent id, so `Chain(32009, C)` is a parent walk ending at
bucket `"32009"`. `Chain(32014, C)` is the bucket alone (model §4.2, gap G1
fixed by construction). Chains are cached per `ContextId`. Resident.

## Identity binding indexes

Binds are decided per root and level; the graph holds only the inputs.

| Index | Shape | Used for |
| --- | --- | --- |
| `hints` | Per segment, sorted `(edge id, hinted pubkey NodeId)` pairs for hinted `trust_in` edges | Witnesses of X: read X's `trust_in` run and look up each edge id |
| `hinted_as` | Per segment, sorted `(P, X)` pairs, deduplicated | In-edges of a pubkey subject that may include bound X accounts |
| `claims` | Sorted `(X, P)` pairs from valid `10011` winners, plus the reverse; resident | Strict confirmation; `identity.claims` |

Per walk, a `BindView` computes `bind(R, X, ℓ)` lazily when the walk touches
X, and memoizes it once bound (an unbound answer is re-checked at deeper
levels, where new witnesses may appear):

```text
bind(R, X, ℓ) = R's own witness for X, if any              // strict: only if claimed
             or best witness among X's hinted in-edges whose author qualifies
                at a level ≤ ℓ                              // strict: claimed only
             or unbound
resolve(k, ℓ) = bind(R, k, ℓ) if k is a user:id node and bound, else k
in_edges(N, ℓ) = in(N) ∪ in(X) for X in hinted_as[N] with bind(R, X, ℓ) = N
```

The model's own-evidence step never applies: the Global Server has no X data
([identity-bindings.md](identity-bindings.md)). A strict walk treats a
candidate whose `10011` is not stored yet as unclaimed and reports
`claims-pending`.

## Epochs

- The graph writer (one thread) takes accepted winners and claim changes from
  a channel and publishes a new `Snapshot` through `ArcSwap` every 250 ms or
  every 50 000 changes, whichever comes first.
- `Snapshot { epoch, segments, delta, dead bits, binding indexes, contexts }`.
  `graphVersion` = `epoch`.
- A query loads the current snapshot once and uses it to the end, so every
  result is consistent with one `graphVersion`.
- Each epoch also publishes a **change summary**: the authors whose 32009
  records changed (including hinted records), and the `(P, X)` claims that
  appeared or disappeared. The root-field cache uses it for invalidation
  ([resolver-engine.md](resolver-engine.md)).

## Durability and restart

- The event store (RocksDB) is the durable source; segments are derived and
  can always be rebuilt from it.
- A flush writes an L1 segment and records the event-store sequence it
  covers. After a crash the delta is rebuilt by replaying the event-store log
  above the last flushed sequence.
- Every segment file has a header (format version, model version, sequence
  range) and xxh3 checksums per section; a mismatch triggers a rebuild of that
  segment from the event store.
- **Start-up:** memory-map the segments, pre-fault the always-resident core,
  pin what fits, replay the delta, and start serving. A background task then
  warms the pages listed in the previous run's hot-page list (saved every
  10 minutes from access sampling), so the working set is back in RAM within
  minutes without blocking queries.

## Memory budget

Default shares of the process memory limit:

| Share | Default | Enforcement |
| --- | --- | --- |
| Always-resident core | as needed (≈ 12 B per node + 0.125 B per edge + delta) | Refuse to start if it exceeds 25 % of the limit; the operator must add RAM or lower retention |
| Pinned hot format | up to 50 % | Pin newest segments and `trust_out` first; the rest stays pageable |
| Root-field cache | 10 % | LRU by bytes |
| Walk scratch | 5 % | Dense per-thread arrays only for walks above 64 K nodes, and at most `cores / 2` such walks at once; smaller walks use hash maps |
| Connections, buffers, ingest queue, flush buffers | 5 % | Per-connection output caps; ingest stops reading sockets when its queue is full |
| Page cache (unpinned hot format, cold columns, RocksDB blocks) | remainder | Managed by the OS with the advice above |

An RSS watchdog backs the shares: above 90 % of the limit the server refuses
cold field builds with `busy`, stops reading writer sockets, and unpins the
oldest segments; above 95 % it closes idle connections.
