# Global Server — resolver engine (`dtp-resolve`)

Status: **draft** · 2026-09-30

Two ways to answer a query, with identical results:

1. the **exact walk** — a direct port of the model's walk
   ([wot-model.md §6](../../TrustGraph/specs/wot-model.md#6-the-trust-walk));
2. the **root field** — the walk's level structure computed once per root and
   reused for every subject.

Batch queries from one root (a timeline page) share one field, so a 200-item
batch costs one walk plus 200 small lookups.

## Exact walk

A line-by-line port of the model pseudo-code, over one pinned snapshot.

- **Scratch**: walks start with a hash map of reached nodes; above about
  64 K reached nodes they switch to dense per-thread `level: Vec<u8>` and
  `stamp: Vec<u32>` arrays (reset by bumping the stamp, O(1)). At most
  `cores / 2` dense walks run at once, so scratch memory stays inside its
  budget ([graph-engine.md § Memory budget](graph-engine.md#memory-budget)).
  Counters live in a small arena for reached nodes only.
- **Selection** (`sel`, model §4.3) reads the author's `trust_out` run per
  bucket in chain order; the head entry is the winner unless its `window` or
  `siblings` bit sends it to the side tables.
- **Integer percent**: `(200·trust + s) / (2·s)` with `u64` arithmetic.
- Used for: `format: path`, queries whose parameters rule out the field
  (below), and as the oracle for the field in tests.

## Root field

A root field `F` is the result of running the expansion part of the walk from
root `R` to level `D − 1`, with no subject:

```text
F = (key, epoch, completeDepth, validUntil,
     Q[0..D-1],   // Q[ℓ] = qualifying nodes first reached at level ℓ, with trust count
     B)           // BindView memo: X → (P, level) for binds decided during the build
key = (R, TC, G, D, bindingMode, scopeProfile)
```

Only **qualifying** nodes are stored, as a sorted `Vec<NodeId>` per level plus
a membership hash map holding `(level, trust count)`. The trust count is the
bind ranking's second key. A root reaching 1 M qualifying nodes costs about
16 MB.

### Hit test

For subject `S` at level `ℓ`, in-edges are `in_edges(node(resolve(S, ℓ)), ℓ)`
([graph-engine.md § Identity binding indexes](graph-engine.md#identity-binding-indexes)):
the subject's own statements plus, once a bind exists at level `ℓ`, the
statements about the bound X account or pubkey.

```text
for ℓ in 0 .. D:
    NS = node(resolve(S, ℓ))
    hits = [ sel(A, NS, K, SC) for A ∈ Q[ℓ], A ≠ NS, A has a statement about NS ]
    if counted(hits) > 0: return CONNECTED(degree = ℓ + 1, hits)
    if ℓ ≥ completeDepth: return truncated-or-disconnected
return DISCONNECTED
```

`resolve(S, ℓ)` uses the field's `B` memo, or computes the bind from `Q` and
the witnesses when the build never touched S. Each level uses the cheaper
side: scan the in-edges and look authors up in `Q[ℓ]`, or, when `|Q[ℓ]|` is
smaller (celebrity subjects with millions of in-edges), binary-search the
subject's sorted `trust_in` run for each `A ∈ Q[ℓ]` — only the touched pages
of a huge run are read.

A subject's statements are one contiguous run per segment, so a subject that
is not in memory costs one or two contiguous reads
([graph-engine.md § Loading a subject fast](graph-engine.md#loading-a-subject-fast)).

### When the field is valid

The field equals the exact walk when either:

- `K = 32014` (the subject is expanded like any node in the model), or
- `K = 32009` and `SC = TC`.

With `SC = TC`, a subject reached by a positive hop from a qualifying author
is already a hit at that degree, so the subject's own expansion can never
change the answer. Every product query satisfies one of the two conditions
([wot-model.md §9](../../TrustGraph/specs/wot-model.md#9-product-profile-attention-scope-profile-xcom)).
Anything else uses the exact walk. The conformance property *field = walk*
checks this on every corpus case and fuzz seed.

Binds keep the field valid: `bind(R, X, ℓ)` depends only on levels `≤ ℓ`,
which the field holds exactly, and never changes once bound. Lenient and
strict are different field keys.

### Building a field

Level-synchronous breadth-first expansion of 32009 hop statements, in
parallel:

0. Prefetch: submit the `trust_out` runs of every qualifying node of level
   `ℓ` in one I/O batch and wait until they are resident (or the deadline
   nears). When the hot format is pinned this is a no-op.
1. Split the current frontier (level `ℓ`) into chunks across the rayon pool.
2. Each task, for each qualifying author, selects its hop statements
   (`sel` over `Chain(32009, TC)`). A statement about `user:id:X` resolves
   through the `BindView` at level `ℓ`: bound → the pubkey is the peer;
   unbound → terminal, skipped. It emits `(peer, value)` pairs into a
   thread-local buffer, skipping peers already leveled at an earlier level.
3. Merge buffers by peer (radix sort by `NodeId`), add counters, assign the
   level, compute `qualifies`, and form the next frontier from value-1 peers
   not yet seen.

Bind decisions at level `ℓ` read only `Q[≤ ℓ]`, which is complete before
level `ℓ` expands, so tasks can compute them concurrently; the memo is a
concurrent map and every task computes the same value for the same X.

Counters are commutative and levels are assigned only at level boundaries, so
the result does not depend on thread scheduling (model §11).

### Guardrails

Field builds and exact walks follow the model's budget rules
([wot-model.md §6.2](../../TrustGraph/specs/wot-model.md#62-guardrails)) with
the Global defaults from
[resolver-api.md § Guardrails](../../TrustGraph/specs/resolver-api.md#guardrails):

| Shared guardrail | Global value | Checked |
| --- | --- | --- |
| `operationDeadline` | 250 ms (a client may lower it with `deadlineMs`) | Before each level and every 4 096 scanned records |
| `batchDeadline` | 500 ms | Before each item's hit test; unfinished items get `errors[key] = "timeout"` |
| `maxDepth` | 6 | Clamps `bounds.maxDepth` |
| `maxReachedNodes` | 5 M | Before a level is expanded |
| `maxWalkRecords` | 50 M | Before a level is expanded: one record per (qualifying frontier author, subject) in its hop-chain buckets (wot-model §6.2). Bucket lengths give a cheap upper bound; distinct subjects are counted only when that bound could exceed the budget |
| `maxColdWalks` | `cores / 2` | Further builds queue for up to 50 ms, then `busy` |

Field memory is an implementation limit, not a protocol one: a field that
would not fit its share of the field-cache budget is used once and not
cached. The client sees no difference.

- Levels completed within the budget are exact; `completeDepth` records the
  last complete level. A subject hit at degree `≤ completeDepth + 1` is exact.
- A subject not hit within complete levels returns `connected: false`,
  `truncated: true`, the reason (`timeBudget`, `nodeBudget`, `edgeBudget`),
  and `completeDepth`.
- A field stopped by node or record budgets is cached with its
  `completeDepth`.
- **Cold data and the deadline.** When a field build hits the query deadline
  while it is still waiting on disk (pages not yet resident), the query gets
  its exact-up-to-`completeDepth` answer and the build **continues in the
  background** under a longer background deadline (default 5 s) and the same
  node and record budgets. The finished field is cached and a `coverage` push
  tells subscribed connections to re-query. A field stopped by the background
  deadline is not cached (it depends on machine speed).
- Deadlines are enforced by a cooperative check in the walk loop, never by
  killing threads, so a stopped walk leaves no partial state behind.

### Cache and invalidation

Fields are cached in an LRU bounded by bytes (the field-cache share in
[graph-engine.md § Memory budget](graph-engine.md#memory-budget), default
10 % of the process limit).

A field built at epoch `E` stays valid at epoch `E'` when no epoch between
them changed anything that can alter `Q[0..D−1]`:

- A changed 32009 record whose author is in `Q[ℓ]` with `ℓ ≤ D − 2`
  invalidates it; this includes hinted (witness) records. Changes by other
  authors cannot: unreached or non-qualifying authors never expand or
  witness, and level `D − 1` authors only create level-`D` nodes, which no hit
  uses. Their witnesses at level `D − 1` are read at hit time, not from `B`.
- **Strict only:** a claim `(P, X)` that appeared or disappeared invalidates
  the field if the build consulted X's candidates (a Bloom filter of touched
  X accounts). Lenient ranking ignores claims.
- There is no own-evidence input on the Global Server, so nothing
  client-specific enters a field: every session with the same key shares it.
- Time: the field records `builtNow` and `validUntil`, the earliest future
  instant at which a record scanned during the build changes activity (its
  `activate` if later than `builtNow`, or `expire + 1` if
  `expire ≥ builtNow`). Only queries with `builtNow ≤ now < validUntil` use
  the field; others rebuild or use the exact walk.

Each cached field keeps a Bloom filter of `Q[≤ D − 2]`, so an epoch's change
summary is checked in microseconds. Rating (32014) changes never invalidate a
field; hit tests read the current snapshot.

A query may use a field whose epoch is older than the pinned snapshot only
when that check passes; otherwise it rebuilds, or runs the exact walk if the
build would exceed the budget.

## Batch execution

1. Group items by field key (root, `TC`, `G`, `D`, binding mode). Most
   items from one WebSocket session share the session defaults and so one
   field.
2. Resolve every subject key to a `NodeId` and submit one prefetch for all
   their `trust_in` / `rating_in` runs (a no-op when resident).
3. Get or build each field once (overlapping with the prefetch).
4. Hit-test items in parallel on the rayon pool.
5. Map to `TrustQueryResult` / `RatingQueryResult` exactly as
   `@dtp/trust-query` does (statements, `contextMatch`, `distance`,
   `resolution`, rating mean, label filter, `statementLimit`, and `binding`
   provenance for `user:id` subjects). Evidence display fields come from the
   cold columns, contiguous per subject.

## Lookups

Lookups ([wot-model.md §8.1](../../TrustGraph/specs/wot-model.md#81-lookups))
read one degree and never walk, so they need no field, no binds, and no
budgets beyond page size, scanned records, and the deadline. They map straight
onto the clustered storage:

| Lookup | Source | Cost per key |
| --- | --- | --- |
| Incoming 32009 / 32014 | The key's `trust_in` / `rating_in` runs in each segment + delta | One contiguous run per segment; hot format, usually resident |
| Outgoing person statements (`p`, `user:id` subjects) | The key's `trust_out` runs | One contiguous run per segment |
| Outgoing post trust and ratings | Event store `by_author` range scan (these never expand a walk, so they have no in-memory out-entries) | One RocksDB range per author |
| Counts | Value bits of the packed entries (incoming) or the `by_author` scan (outgoing); no cold columns read | Same runs as above, no display data |
| Item details (event id, `created_at`, content, labels) | Cold columns and display blob, contiguous per subject | One read per page |

- **Filters and selection.** Buckets come from the filter's context and
  `contextMatch`; runs are sorted by bucket then author, so `selected` mode is
  a merge by author across the chain buckets, and `mergeKeys` is a merge by
  author across the keys' runs. Activity and `since` / `until` read
  `window` bits and the `created_at` column.
- **Order and pages.** Runs are stored by bucket and author, not by time. A
  page is a single pass over the key's runs that keeps the next `limit` items
  after the cursor (a bounded top-k by `created_at` or author pubkey). For a
  subject with a million statements that pass reads about 8 MB of hot format
  and 4 MB of `created_at` — a few milliseconds warm — once per page.
  Subjects with more than 5 M candidate records hit the scanned-records
  guardrail and page in smaller steps.
- **Batches.** `lookup.batch` prefetches every key's runs in one submission,
  like a resolver batch, then runs the queries in parallel on the rayon pool.
- **Neighborhood.** An incoming and an outgoing lookup for one center (plus
  outgoing for extra `keys`) over every active 32009 winner in the context
  chain, plus 32014 arrows into a post / `e` center; rows sorted by event id
  before the `limit` cut; node `id` = `NodeId` for this `instanceId`, always
  with `subject`.

## Other read paths

| Result | Implementation |
| --- | --- |
| `format: path` | Exact walk plus backward trace (model §7.2); rate-limited more tightly than default queries |
| Rating queries | Same field (hop threshold `G = 1` in the product profile, so a separate field key from trust queries) |
| Sync frontier | Model §8, parallel per level, sorted and capped; `via` = the discovering author (lowest pubkey among the supporting authors of the previous level), as in the TrustGraph corpus |
| `graph.field` | The cached field's `Q` lists as hex pubkeys, plus the binds decided during the build (`X → P`, level, witness id) for the requested mode |

## Latency budget (targets)

"Warm" means the touched pages are resident; "cold" means they are read from
NVMe during the request.

| Step | Warm | Cold |
| --- | --- | --- |
| Parse + route | < 0.2 ms | — |
| Field lookup (cached) | < 0.05 ms | — |
| Field build (`D = 4`, ≤ 1 M reached nodes) | ≤ 50 ms p99 | ≤ 250 ms p99, then background completion |
| Prefetch of 200 subjects' runs | 0 | ≈ 2–5 ms (parallel reads, queue depth 64) |
| 200 hit tests (parallel) | < 1 ms | < 1 ms after prefetch |
| Evidence display for hits | < 0.5 ms | ≈ 1–3 ms |
| Result mapping + JSON | < 1 ms | < 1 ms |
