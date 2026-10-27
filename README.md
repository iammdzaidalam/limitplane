# LimitPlane

A rate limiter you put in front of any site or API. It prices requests by cost
(a health check is 1 unit, an AI call is 5), enforces a burst budget and a monthly plan per
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
ban? -> who (API key -> tenant, tier) -> cost (longest route prefix) -> burst -> monthly -> headers
```

Burst runs before monthly, so a request the burst limit rejects never uses up the plan.
Every response carries `RateLimit-Limit/Remaining/Reset`. A block returns `429` with `Retry-After`
and a JSON body that says why.

## Design

- **GCRA** instead of a token bucket: one int64 per key, no float math, sharded in memory with zero allocations.
- **Redis:** the same algorithm in one Lua script that reads Redis `TIME`, so replica clock skew can't leak extra burst.
- **Redis down:** a circuit breaker routes to the local limiter and marks decisions `degraded`. `--fail-closed` returns 503 instead.
- **Autopilot:** bans a client after repeated burst blocks, alerts at 80% of a monthly plan, and labels clients (human, bot, crawler, retry bug) from request timing. The labels are a heuristic, not a model.
- **Hot reload:** the policy is validated, then swapped atomically (file change or `SIGHUP`).
- `X-Forwarded-For` is trusted only with `--trust-proxy`, and then only the right-most untrusted hop.

Numbers are in [BENCHMARKS.md](BENCHMARKS.md).

## Deploy

```bash
make compose-up && make prove     # 2 replicas + Redis behind nginx; checks the limit is shared
kubectl apply -k deploy/k8s/overlays/dev
```

## Develop

```bash
make test    # go test -race ./...
make lint    # go vet + gofmt
```
