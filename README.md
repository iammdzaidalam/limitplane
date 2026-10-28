# LimitPlane

[![ci](https://github.com/iammdzaidalam/limitplane/actions/workflows/ci.yml/badge.svg)](https://github.com/iammdzaidalam/limitplane/actions/workflows/ci.yml)

A rate limiter you put in front of any site or API. It prices requests by cost
(a health check is 1 unit, an AI call is 5), enforces a burst budget and a monthly quota per
tenant, shares limits across replicas through Redis, bans abusive clients automatically,
and shows every decision on a live dashboard. Go, standard library only.

## Run it

```bash
go install github.com/iammdzaidalam/limitplane/cmd/limitplane@latest

limitplane                                    # demo app + dashboard on :8080
limitplane --upstream http://localhost:3000   # protect an existing site
limitplane --config limitplane.example.json --redis redis://localhost:6379
```

In proxy mode the dashboard lives at `/_limitplane/`. The admin key is printed once at startup
unless you pass `--admin-key`.

## How a request is decided

```
who (API key -> tenant, tier) -> cost (longest route prefix) -> one check: ban? monthly? burst? -> headers
```

The check writes nothing unless every part passes, so a burst reject never counts against the quota
and a monthly reject never uses up burst. When both would fail, monthly wins: it holds until the 1st.
Every response carries `RateLimit-Limit/Remaining/Reset`. A block returns `429` with `Retry-After`
and a JSON body that says why.

## Design

- **GCRA** instead of a token bucket: one int64 per key, no float math, sharded in memory with zero allocations.
- **Redis, one round trip:** one Lua script checks the monthly cap and GCRA, then writes both counters. It reads Redis `TIME`, so replica clock skew can't leak burst and the month rolls over on one clock. A tenant's keys share a hash tag (`lp:{acme}:r`, `lp:{acme}:q:2026-10`), so the script touches one Cluster slot.
- **Redis Cluster:** `--redis redis+cluster://h1:6379,h2:6379`. The client routes by CRC16 slot from `CLUSTER SLOTS` with a pool per node, follows MOVED and ASK (at most 3 redirects), and loads scripts per node. A dead master degrades only the tenants in its slots. See [docs/REDIS.md](docs/REDIS.md).
- **Metrics:** `/metrics` is public unless you set `--metrics-key` (or `LIMITPLANE_METRICS_KEY`); scrapers then send `Authorization: Bearer <key>`. It lists tenant ids, so set it in proxy mode.
- **Redis down:** a circuit breaker routes to the local limiter and marks decisions `degraded`. Each replica then gets 1/n of the budget (n from `--replicas` / `LIMITPLANE_REPLICAS`, or counted from heartbeat Leases with `--kube`), so the fleet still admits about one budget. A Redis that isn't up at startup is retried in the background instead of failing the boot. `--fail-closed` returns 503 instead.
- **Shared bans:** a ban (IP or CIDR) made by any replica, or from the dashboard, holds on all of them. It is written to one Redis hash and published on a channel every replica subscribes to, so it arrives in about a millisecond; a 2s sync repairs anything missed. Requests check bans in process (one map lookup per prefix length in use), so a banned flood never reaches Redis and the script never needs a cross-slot key. Bans made while Redis is down are pushed, with their remaining TTL, when it is back.
- **Autopilot:** bans a client after repeated burst blocks, alerts at 80% of a monthly quota (also exported as `limitplane_quota_used_ratio`), and labels clients (human, bot, crawler, retry bug) from request timing. The labels are a heuristic, not a model.
- **Hot reload:** the policy is validated, then swapped atomically (file change or `SIGHUP`).
- `X-Forwarded-For` is trusted only with `--trust-proxy`, and then only the right-most untrusted hop.

Numbers are in [BENCHMARKS.md](BENCHMARKS.md).

```
            packets                 HTTP                                   one Lua call per request
client ──▶ [ XDP: bans, floods ] ──▶ [ gateway: ban → monthly → burst ] ──▶ Redis / Redis Cluster
              optional, xdp/            │ every replica, any number          ▲ bans: hash + pub/sub
                                        ├─▶ upstream (proxy mode)            │
                                        └─▶ dashboard, SSE, /metrics         │
                           Kubernetes: RateLimitPolicy / Tenant CRDs ──▶ hot swap on every replica
```

## Deploy

```bash
make compose-up && make prove     # 2 replicas + Redis behind nginx; checks the limit is shared
kubectl apply -k deploy/k8s/overlays/dev
helm install limitplane deploy/helm/limitplane
```

- [docs/DEPLOY.md](docs/DEPLOY.md): Compose, Kustomize, Helm, ingress and Gateway API.
- [docs/REDIS.md](docs/REDIS.md): single node vs Cluster, key layout, how bans propagate, outage behaviour.
- [docs/XDP.md](docs/XDP.md): the optional eBPF fast path that drops banned sources and floods at the NIC.
- [docs/OPERATOR.md](docs/OPERATOR.md): `--kube` mode. Policy and tenants as `RateLimitPolicy` / `Tenant` resources, every replica hot-swaps, one Lease-elected leader writes status and events.

## Code map

| Path | What |
|---|---|
| `internal/limiter` | GCRA, monthly quota, bans, Redis script, fallback breaker |
| `internal/redisx` | RESP2 client: pool, Cluster routing, pub/sub |
| `internal/gateway` | the middleware: who, cost, check, headers |
| `internal/policy` | policy file, validation, atomic hot swap |
| `internal/autopilot` | storm bans, quota alerts, client labels |
| `internal/server` | admin API, JWT, SSE hub, metrics, dashboard |
| `internal/kube` | stdlib Kubernetes client, watches, Lease election |
| `web/`, `site/` | dashboard (embedded) and landing page, no build step |
| `xdp/` | eBPF program and loader, its own module |
| `deploy/` | Kustomize, Helm chart, CRDs, observability, Gateway API examples |

## Develop

```bash
make test    # go test -race ./...
make lint    # go vet + gofmt
make bench
make prove-cluster   # 3-master Redis Cluster, two gateways
cd xdp && ./test.sh  # XDP proof in a privileged Docker container
```
