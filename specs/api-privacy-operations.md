# Global Server — auth, limits, privacy, operations

Status: **draft** · 2026-09-30

## Protocol

The Global Server implements exactly the same
[resolver protocol v1](../../TrustGraph/specs/resolver-api.md) as the
Personal Server — messages, operations, defaults, results, errors, auth,
ingest, deletions, guardrails — and passes the same session suite
([TrustGraph conformance.md § One API](../../TrustGraph/specs/conformance.md#one-api-the-session-suite)).
Nothing below adds or changes an operation; it only sets values of the shared
settings for a public deployment.

## Global deployment configuration

| Shared setting | Global value | Why |
| --- | --- | --- |
| `listen` | Public, TLS (`wss://<host>/`) | Serves anyone |
| `allowedOrigins` | any | Any app may use it |
| `auth.reads` | `open` (option: `members`) | Anonymous reads under quotas |
| `auth.writes` | **`members`** | Only whitelisted writers (Sync Servers) may push events; do not open it on a public server |
| `auth.admins` | Operator pubkeys | NIP-86 management |
| `maxInFlight` | 16 | Many connections share the machine |
| `maxConnections` | 4 read per IP, 8 write per writer pubkey | Fair use |
| `operationDeadline` / `batchDeadline` | 250 ms / 500 ms (protocol defaults 500 / 1 000) | Tighter latency on a shared server |
| `maxDepth` | 6 (protocol default 7) | Bounds cold work |
| `rateLimit` | Cost units per client (below) | Fair use |

## Authentication

Standard Nostr relay authentication (NIP-42), with a standard whitelist
(NIP-43), managed with a standard API (NIP-86) — the shared mechanism of
[resolver-api.md § Authentication and access](../../TrustGraph/specs/resolver-api.md#authentication-and-access).

| Access | Global value | With `auth.reads = members` |
| --- | --- | --- |
| Resolver and lookup operations, `REQ` | **Open**, anonymous, rate-limited per IP | Members with role `read` only |
| `EVENT` (ingest) | **Members with role `write` only** | same |
| NIP-86 management | Operator pubkeys and members with role `admin`, via NIP-98 | same |

- On connect the server sends `["AUTH", <challenge>]`. A client answers with
  a kind `22242` event (`relay` and `challenge` tags); the server checks it per
  NIP-42 and answers `OK`. Several pubkeys may authenticate on one connection.
- Refusals use the NIP-42 prefixes: `auth-required:` (not authenticated),
  `restricted:` (authenticated but not a member with the needed role).
- **Whitelist:** a NIP-43 kind `13534` membership list signed by the server's
  `self` key (published in NIP-11), with `["member", <pubkey>, <role>…]`
  tags; roles are kind `33534` events with `d` = `read`, `write`, `admin`.
  Anyone can read both with `REQ`. The server re-signs `13534` after each
  change.
- **Management:** NIP-86 `allowpubkey`, `unallowpubkey`,
  `listallowedpubkeys`, `assignrole`, `unassignrole`, `banpubkey`, over HTTP
  with NIP-98 auth; or the CLI (`dtp-global members …`).
- **Later — WoT as the whitelist:** membership source `wot` derives members
  from the operator's web of trust (pubkeys that qualify within a configured
  degree and threshold of the operator root, via the same model). It is
  published as the same `13534` list, recomputed on graph changes. Clients
  and writers see no protocol change.

Authenticated members also get higher quotas than anonymous clients.

## Limits and guardrails

Resolve guardrails are the shared ones of
[resolver-api.md § Guardrails](../../TrustGraph/specs/resolver-api.md#guardrails),
with the Global values above, enforced as in
[resolver-engine.md § Guardrails](resolver-engine.md#guardrails). Memory
guardrails are in [graph-engine.md § Memory budget](graph-engine.md#memory-budget).

| Tier | Quota (default) |
| --- | --- |
| Anonymous | 4 read connections and 20 cost units/s per IP, burst 100 |
| Member (`read`) | Per member, set by the operator (default 10× anonymous) |
| Writer (`write`) | 8 connections per pubkey; 5 000 pending `OK`s per connection |

- Rate limiting counts **cost units**, not messages: a warm batch item costs
  1, a cold field build costs according to the work it did, a path query
  costs more. Expensive requests from anonymous clients queue behind cheap
  ones.
- Past `maxInFlight` (16) the server answers `busy`; over the rate limit,
  `rate-limited` — the same codes every deployment uses.
- Idle read connections are closed after 5 minutes.

## Privacy

A query reveals the root and the subjects it asks about. For Attention, the
subjects are the X accounts and posts on the user's screen, which is
browsing history. Commitments, published in the Global Server privacy policy
on the Website:

1. No logging of subjects or message bodies. Access logs keep time, message
   type, operation, status, latency, and a truncated IP hash, for 7 days.
2. No `(root, subject)` pairs are persisted. Field caches are in memory only.
3. Active roots (needed for admission) are stored as pubkey + last active
   day, deleted after 30 days of inactivity.
4. Metrics are aggregates without identifiers.
5. TLS only. No third-party analytics or trackers.
6. The server never receives X identity or post data; it can only learn the X
   ids that appear as query subjects.

### Privacy modes for clients

| Mode | What the server learns | How |
| --- | --- | --- |
| Query mode | Root and queried subjects | `trust.batch`, `rating.batch`, … |
| Field mode | Root only | Client calls `graph.field` (who counts per level, and the binds decided in the requested mode) and resolves subjects itself from relay data. For each subject, the hitting degree is `min(level(A) + 1)` over counted statements by authors in the field. Results match the server's. |
| Frontier mode | Root only | A Personal Server calls `graph.frontier` for sync hints and runs its own exact heap ([PersonalServer sync.md](../../PersonalServer/specs/sync.md)) |

Attention's use of the Global Server is opt-in and disclosed in Settings.
Field mode needs a hit-test function inside `@dtp/trust-graph` (the one
trust walk may not be re-implemented outside it), which needs the same
approval as any change there. Until then Attention can only offer query mode,
and the Settings disclosure must say what the server learns.

## Verifiability

- Every result carries `sourceEventIds`; `REQ` with `ids` serves the signed
  events, which clients can verify.
- Field and frontier results return evidence ids (`via`) so a client can
  check any listed hop.
- The membership list is itself a signed, readable Nostr event.

## Configuration

`dtp-global.toml` (resolver):

| Section | Keys |
| --- | --- |
| `[server]` | listen address, TLS, `instance_name`, server key reference (NIP-11 `self`) |
| `[model]` | `scope_profile = "x.com"`, default thresholds, default `bindingMode` |
| `[auth]` | `reads = "open" \| "members"`, operator pubkeys, membership source (`nip43`; later `wot`) |
| `[ingest]` | pending-`OK` window, writer connections per pubkey, queue size |
| `[retention]` | seed anchors, `d_reach`, active-root TTL, per-author and total disk caps |
| `[guardrails]` | deadlines (query and background), max degree, node and record budgets, statement / path / neighborhood limits, concurrent cold builds |
| `[memory]` | process limit, the shares of [graph-engine.md § Memory budget](graph-engine.md#memory-budget), pin policy (`auto` pins the hot format when it fits) |
| `[residency]` | prefetch queue depth, re-touch interval for active roots, hot-page list interval |
| `[limits]` | tiers, cost units, connections, in-flight, message sizes |
| `[storage]` | data directory for the graph store and event store, RocksDB options, flush size, merge and base-rebuild thresholds |
| `[admin]` | `listen` (default `127.0.0.1:<port + 1>`), `auth` (`local` or `nip98`), alert thresholds |

`dtp-sync.toml` (Sync Server): relays, backfill policy, target endpoints,
signing key reference, `[admin]` for its own telemetry pages
([sync-server.md § Sync Server](sync-server.md#sync-server-dtp-sync)).

Secrets (server key, writer keys) come from files or environment variables,
never from the TOML.

## Deployment

- Two static binaries for Linux x86_64 and aarch64 (`dtp-global`,
  `dtp-sync`); Docker images; systemd units.
- Sizing: RAM sets how much of the graph is warm, disk sets how large it can
  be. A resolver with 16 cores and 32 GB RAM keeps a 1 B-edge graph fully
  resident; 64 GB RAM and 2 TB NVMe serve a 5 B-edge graph with the hottest
  part resident. Use local NVMe (not network storage) for the graph store:
  cold subjects are read with many small random reads. Sync Server: 4 cores,
  8 GB RAM, small disk.
- Resolver replicas behind a load balancer with root-affinity hashing and
  sticky connections ([architecture.md § Topology](architecture.md#topology));
  root affinity also keeps each replica's page cache focused on its roots.
- Rolling restarts memory-map the segments and replay the delta; `/readyz`
  turns true when replay finishes, and the working set warms in the
  background. Clients and writers reconnect, answer `AUTH`, and resend.

## Observability

**Telemetry pages.** The resolver serves the shared admin telemetry pages,
JSON, and `/metrics` on its admin listener (default `127.0.0.1:<port + 1>`),
exactly as the Personal Server does ([TrustGraph telemetry.md](../../TrustGraph/specs/telemetry.md)).
On a remote machine, reach them through an SSH tunnel; binding the admin
listener to another interface requires `admin.auth = nip98` with an operator
pubkey. The Sync Server serves the same pages for what applies to it
(Sources, Ingest to its targets, Memory, Logs).

| Kind | Examples |
| --- | --- |
| Shared metrics | The `dtp_*` names in [telemetry.md § Metric names](../../TrustGraph/specs/telemetry.md#metric-names): readiness, graph size and bytes, ingest by kind and result, sources, operations and latency (warm vs cold), guardrail hits, field cache, connections, memory shares, roots, alerts |
| Implementation metrics (`dtp_impl_*`) | Page reads per query and prefetch latency, delta size, segment count, dead ratio, pinned vs resident bytes, compaction progress, retention class sizes |
| Health | `/healthz` (process up), `/readyz` (segments mapped, delta replayed, ingest caught up) |
| Logs | Structured (`tracing`), no identifiers at info level; the last warn / error lines appear on the Logs page |

## Abuse

- Anonymous clients can only read, within cost-unit quotas.
- Writers are whitelisted; a misbehaving writer is removed with NIP-86
  `unallowpubkey` or `banpubkey`, and every event it sent was validated anyway.
- Root activation and `want` demands are queued and rate-limited per client.
- Unreached authors are capped per author and in total on disk, and evicted
  first when disk is short; a walk never pages them in unless an anchor's
  web of trust reaches them, so they cost no RAM.
