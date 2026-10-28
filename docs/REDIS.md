# Redis and Redis Cluster

Replicas share limits and bans through Redis: one server, or a Cluster. The client
(`internal/redisx`) is about 800 lines of standard library: RESP2, connection pools, Cluster
routing and pub/sub.

## Connecting

| `--redis` / `REDIS_URL` | Meaning |
|---|---|
| `redis://:pass@host:6379/0` | One server (`rediss://` for TLS, `user:pass@` for ACLs). |
| `redis+cluster://:pass@h1:6379,h2:6379` | A Cluster. The hosts are seeds: any one that answers is enough. db must be 0. |
| `rediss+cluster://...` | A Cluster over TLS. |

Cluster mode is chosen by the URL scheme, not by a flag, so the one setting that already travels
everywhere (the env var, the Helm `redis-url` Secret key) carries the whole choice. The single-server
path doesn't change: one extra nil check per command.

## What lives where

| Key | Type | Slot |
|---|---|---|
| `lp:{acme}:r` | string: GCRA theoretical arrival time, PX expiry | slot of `acme` |
| `lp:{acme}:q:2026-10` | counter: monthly spend, 35-day expiry | slot of `acme` |
| `lp:bans` | hash: client → `"<expiry ms> <reason>"` | one slot |
| channel `lp:bans` | pub/sub: `ban <client> <ttl ms> <reason>`, `unban <client>` | broadcast |

A tenant's keys share a hash tag, so the per-request script touches one slot and works unchanged on a
Cluster. Different tenants spread over all masters.

## The per-request path

One `EVALSHA` per request runs the monthly cap and GCRA, then writes both counters, atomically, on
Redis's clock. Bans are not in the script any more. Before the script runs, the gateway checks bans
in process: an exact-IP map lookup, then one lookup per CIDR length in use (8 to 40 ns).

That is the Cluster fix. The old script took the client's ban key (`lp:ban:<ip>`) next to the tenant's
keys, and those almost never share a slot, so a Cluster would reject every request with `CROSSSLOT`.
Putting the ban key under the tenant's tag doesn't work either, because a ban is per client and a
client can hit any tenant. Checking in process removes the cross-slot key and has two more benefits:

- A banned flood never reaches Redis. Before, every request from a banned IP still cost a round trip.
- One code path for one server and for a Cluster.

The cost is that bans are now eventually consistent across replicas. The next section is how that gap
is kept to a millisecond or so.

## How bans spread

1. **Write.** A ban is one script on the `lp:bans` slot: `HSET` the hash (expiry from Redis `TIME`)
   and `PUBLISH` it, atomically. The replica that made it applies it locally at once.
2. **Push.** Every replica runs `Watch`: a dedicated `SUBSCRIBE lp:bans` connection that applies each
   message as it arrives. On a Cluster any node will do, because a plain `PUBLISH` reaches every
   node's subscribers over the cluster bus. In tests and in `scripts/prove-cluster.sh` a ban reaches
   the other gateway in about 1 to 2 ms.
3. **Safety net.** Every 2s each replica reads the whole hash back (`HGETALL`, one slot, O(bans)) and
   replaces its copy, which repairs anything pub/sub missed. `Watch` also resyncs every time it
   (re)subscribes, so a reconnect has no gap. An idle subscription is PINGed every 10s and redialed if
   that gets no answer.
4. **No lost updates.** The local list has a write counter. A sync that started before a pub/sub
   message arrived doesn't overwrite it; it waits for the next tick.

The old layout (`lp:ban:<ip>` keys found with `SCAN MATCH`) had two Cluster problems: `SCAN` only
walks the node it is sent to, and the multi-key read was cross-slot. Even on one server it walked the
whole keyspace every 2s on every replica, which is O(all keys). The hash is O(bans). Expired entries
are deleted by the read.

`GET /api/bans` and its JSON (`[{"client","until","reason"}]`, which `limitplane-xdp` parses) are
unchanged.

## Bans made during an outage

While Redis (or, on a Cluster, the master holding `lp:bans`) is down, bans and unbans go to the local
list through the fallback and are marked pending. The next successful sync pushes them first, with
their remaining TTL, and only then reads the list back. Their `PUBLISH` delivers them to every other
replica. Before this change, the first sync after recovery replaced the local list with Redis's
version and the ban was gone.

- Unbans made during the outage are pushed too, so an operator's unban doesn't come back.
- If another replica bans or unbans the same client after recovery, that write is newer and replaces
  the pending one.
- A pending ban that expires before Redis comes back is dropped, not pushed.
- This also works when Redis comes back empty, with no persistence.

## Cluster client

- **Slot map.** `CLUSTER SLOTS` from the first node that answers, nodes in their cooldown last. An
  empty host in the reply means "the node you asked"; `?` (unknown endpoint) is skipped. The map is
  16384 atomic pointers, so routing takes no lock: finding the first key plus CRC16 costs 11 ns with 0
  allocations.
- **Routing.** By the first key: for `EVAL`/`EVALSHA`, the first entry of `KEYS`. Keyless commands
  go to a random master.
- **Pools.** One per node, the same pool as the single-server client.
- **MOVED.** Retry on the named node, store it as that slot's owner, and refresh the whole map in the
  background (at most once a second).
- **ASK.** Send `ASKING` and then the command, on the target node, once. The map doesn't change,
  because the slot is mid-migration.
- **Bounded.** At most 3 redirects. After that, and on `TRYAGAIN` or `CLUSTERDOWN`, the error is
  `ErrNodeDown`.
- **Scripts.** `EVALSHA`, then `EVAL` on `NOSCRIPT`, on whichever node the key routes to, so each node
  loads a script the first time it needs it.
- **Node breaker.** A connection failure marks the node down for 1s and returns `ErrNodeDown`
  immediately for its slots, so a dead master costs one timeout a second rather than one per request.
  The failure also triggers a map refresh, which picks up a promoted replica.
- **Partial outages stay partial.** The limiter's fallback sends an `ErrNodeDown` request to the
  local limiter without tripping the global breaker. Tenants on the dead master are marked degraded;
  tenants on the other masters stay shared. A plain error, such as "no node reachable at all", still
  trips it.

### Resharding

Live resharding is covered by `TestRedisClusterIntegration`, which moves slots between masters with
`SETSLOT`/`MIGRATE`:

- A tenant whose slot moves keeps its state, and the next request follows `MOVED`.
- During a migration, single-key commands follow `ASK` to the importing node.
- The two-key script gets `TRYAGAIN` there until both keys exist on one side. Redis won't run a
  multi-key command on an importing slot with keys missing. That request is answered locally
  (degraded) and nobody else is affected. Migrate a tenant's keys in one `MIGRATE ... KEYS` call
  (redis-cli does, per batch) and the window is one batch.

## Failure modes

| What fails | What happens |
|---|---|
| One server, down | The breaker trips: every replica limits locally on 1/n of the budget (`degraded`), or returns 503 with `--fail-closed`. Bans keep applying from the local copy; new ones are pushed on recovery. |
| One Cluster master, down (no replica) | Only tenants in its slots degrade. If it holds `lp:bans`, ban writes go pending and are pushed when it is back. Needs `cluster-require-full-coverage no`, or Redis itself stops serving every slot. |
| One master, with a replica | It fails over after `cluster-node-timeout`; the node error refreshes the map, and requests go to the new master. (Not exercised: the compose file has no replicas.) |
| A pub/sub message is lost | The 2s sync repairs it. |
| The subscriber's node dies | `Watch` redials another node within about 1s and resyncs. |

## Upgrading from `lp:ban:*` keys

The old ban keys are ignored. Bans last minutes, so at worst a ban made just before the upgrade is
forgotten. During a rolling upgrade, old and new replicas don't see each other's bans.

## Try it

```bash
docker compose -f docker-compose.cluster.yml up -d --build   # 3 masters, gateways on :18091, :18092
./scripts/prove-cluster.sh                                   # shared limit, instant bans, master stop/start
docker compose -f docker-compose.cluster.yml down -v
```

The script checks that:

1. acme's burst of 10 holds across both gateways;
2. five IP bans and a CIDR ban are enforced by the other gateway on the very next request;
3. stopping the master that holds `lp:bans` degrades only the clients in its slots;
4. a ban made during the outage reaches the other gateway once the master is back.

`OUTAGE=0` runs steps 1 and 2 only, for example against two gateways on single-node Redis.

Integration tests. The Cluster announces its container IPs, so run them on the compose network:

```bash
LIMITPLANE_REDIS=redis://localhost:16379 go test -race ./internal/limiter -run Redis
docker run --rm --network limitplane-cluster -v "$PWD":/src -w /src \
  -e LIMITPLANE_REDIS_CLUSTER=redis+cluster://10.207.7.11:6379,10.207.7.12:6379 \
  golang:1.26 go test -race ./internal/limiter -run Redis
```

Both variables can be set at once: each test runs once per backend.

## Not covered

- Sentinel.
- Reading from replicas.
- `CLUSTER SHARDS`. `CLUSTER SLOTS` is deprecated but still present in Redis 7.
- Sharded pub/sub (`SPUBLISH`). Ban traffic is tiny, so a broadcast is fine.
- With `rediss+cluster://`, nodes are verified against the host they announce. A Cluster that
  announces bare IPs needs certificates with IP SANs.
