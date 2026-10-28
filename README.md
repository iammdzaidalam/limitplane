# LimitPlane

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
- **Redis, one round trip:** one Lua script checks the ban, the monthly cap and GCRA, then writes both counters. It reads Redis `TIME`, so replica clock skew can't leak burst and the month rolls over on one clock. A tenant's keys share a hash tag (`lp:{acme}:r`, `lp:{acme}:q:2026-10`), so they sit in one Cluster slot.
- **Metrics:** `/metrics` is public unless you set `--metrics-key` (or `LIMITPLANE_METRICS_KEY`); scrapers then send `Authorization: Bearer <key>`. It lists tenant ids, so set it in proxy mode.
- **Redis down:** a circuit breaker routes to the local limiter and marks decisions `degraded`. Each replica then gets 1/n of the budget (n from `--replicas` / `LIMITPLANE_REPLICAS`, or counted from heartbeat Leases with `--kube`), so the fleet still admits about one budget. A Redis that isn't up at startup is retried in the background instead of failing the boot. `--fail-closed` returns 503 instead.
- **Shared bans:** with Redis a ban is a key (`lp:ban:<ip or cidr>`) with an expiry, so a ban made by any replica, or from the dashboard, holds on all of them. Exact IPs are checked inside the script; CIDRs are synced every 2s and matched in process (one map lookup per prefix length in use).
- **Autopilot:** bans a client after repeated burst blocks, alerts at 80% of a monthly quota (also exported as `limitplane_quota_used_ratio`), and labels clients (human, bot, crawler, retry bug) from request timing. The labels are a heuristic, not a model.
- **Hot reload:** the policy is validated, then swapped atomically (file change or `SIGHUP`).
- `X-Forwarded-For` is trusted only with `--trust-proxy`, and then only the right-most untrusted hop.

Numbers are in [BENCHMARKS.md](BENCHMARKS.md).

## Deploy

```bash
make compose-up && make prove     # 2 replicas + Redis behind nginx; checks the limit is shared
kubectl apply -k deploy/k8s/overlays/dev
helm install limitplane deploy/helm/limitplane
```

- [docs/DEPLOY.md](docs/DEPLOY.md): Compose, Kustomize, Helm, ingress and Gateway API.
- [docs/OPERATOR.md](docs/OPERATOR.md): `--kube` mode. Policy and tenants as `RateLimitPolicy` / `Tenant` resources, every replica hot-swaps, one Lease-elected leader writes status and events.

## Develop

```bash
make test    # go test -race ./...
make lint    # go vet + gofmt
```
