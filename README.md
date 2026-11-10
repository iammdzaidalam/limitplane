# LimitPlane

[![ci](https://github.com/iammdzaidalam/limitplane/actions/workflows/ci.yml/badge.svg)](https://github.com/iammdzaidalam/limitplane/actions/workflows/ci.yml) · [Website](https://limitplane-eight.vercel.app) · [Releases](https://github.com/iammdzaidalam/limitplane/releases)

LimitPlane is a rate limiter you put in front of a website or API. For every request it decides
whether the caller still has budget left, and tells them clearly when they don't.

- **Requests have a price.** A health check might cost 1 unit and an AI call 5, so expensive routes
  use up the budget faster.
- **Every customer gets a plan.** Each plan has a short-term budget (how fast you may go) and a
  monthly quota (how much you may use in total).
- **Limits hold across servers.** Run as many copies as you like; they share one budget through Redis.
- **Abusers get banned automatically**, on every copy at once, and can be dropped at the network
  card before they cost any CPU.
- **You can see everything.** A live dashboard shows each decision, and "why was this blocked?"
  gets a plain answer.

Written in Go with only the standard library: the main program has no third-party packages.

## Try it in a minute

```bash
go install github.com/iammdzaidalam/limitplane/cmd/limitplane@latest
limitplane            # demo API + dashboard on http://localhost:8080
```

```bash
curl -i localhost:8080/v1/ping                               # no key: the free plan
curl -i -H "X-Api-Key: demo-pro-key" localhost:8080/v1/ping   # a customer on the pro plan
```

Every response says where you stand:

```
RateLimit-Limit: 100
RateLimit-Remaining: 99
RateLimit-Reset: 1
```

Send too many and you get `429 Too Many Requests`, a `Retry-After` header and a JSON body that
says why (`burst`, `monthly`, `banned`, ...). The dashboard's admin key is printed at startup.

To protect a site you already run, point LimitPlane at it and send your traffic through LimitPlane:

```bash
limitplane --upstream http://localhost:3000 --config limitplane.example.json --redis redis://localhost:6379
```

The dashboard then moves to `/_limitplane/` so it can't clash with your site's own pages.

## Architecture

```
                      ┌─────────────── your servers ────────────────┐
clients ─▶ [ XDP ] ─▶ │  LimitPlane   LimitPlane   LimitPlane  ...  │ ─▶ your app
           optional   │      │            │            │            │
                      │      └────────────┼────────────┘            │
                      │                   ▼                         │
                      │   Redis or Redis Cluster: budgets and bans  │
                      └─────────────────────────────────────────────┘
```

- **XDP** (optional, Linux) drops banned IPs and packet floods at the network card.
- **Each LimitPlane copy** serves the dashboard, a live event feed and `/metrics`.
- **Kubernetes** (optional) can hold the policy and customers as resources that every copy watches.

Every copy of LimitPlane is identical. Redis holds the shared counters, so it doesn't matter which
copy a request lands on. There are three ways to put it in your traffic path:

| Mode | How | When to use it |
|---|---|---|
| Proxy | `--upstream URL`: LimitPlane forwards allowed requests to your app | simplest setup |
| Forward auth | Envoy, nginx or Traefik ask LimitPlane "allow this?" and route the request themselves | you already run one of those ([docs/AUTHZ.md](docs/AUTHZ.md)) |
| Demo | no flags: a built-in sample API | trying it out |

## What happens to one request

```
1. Who is it?          API key → customer and plan (no key → the anonymous plan)
2. What does it cost?  the longest matching route, e.g. /v1/generate = 5 units
3. One check:          banned? → monthly quota left? → org budget left? → short-term budget left?
4. Answer:             pass it on with RateLimit-* headers, or 429 with the reason
```

Step 3 is a single trip to Redis. Nothing is charged unless every part passes, so being blocked
for going too fast never eats into the monthly quota.

The short-term budget uses **GCRA**. It behaves like a token bucket but stores just one number per
customer: the time at which their budget will be full again. That makes it cheap (about 45 ns in
memory, with no allocations) and exact.

## Features

**Plans and prices.** Plans, route costs and API keys live in one JSON file. Edits are checked and
applied without a restart; a bad file is rejected and the old one keeps running.

```json
{
  "tiers": {
    "free": { "rate": { "limit": 5,  "period": "1s", "burst": 10 },  "monthly": 10000 },
    "pro":  { "rate": { "limit": 50, "period": "1s", "burst": 100 }, "monthly": 1000000 }
  },
  "routes": [{ "prefix": "/v1/generate", "cost": 5 }],
  "keys": { "demo-pro-key": { "id": "globex", "tier": "pro" } },
  "anonymous": "free"
}
```

`limit` per `period` is the steady rate, `burst` is how much can be spent at once, and `monthly`
is the total for the calendar month (0 means no cap).

**Shared limits.** With `--redis`, every copy shares one budget. The check runs as one script inside
Redis using Redis's own clock, so servers whose clocks drift apart can't hand out extra requests.
Redis Cluster works too: `--redis redis+cluster://h1:6379,h2:6379`.

**When Redis goes down.** LimitPlane doesn't just let everything through. Each copy limits on its
own with its fair share of the budget (1/n for n copies), marks decisions as `degraded`, and goes
back to Redis when it returns. Use `--fail-closed` to answer 503 instead.

**Bans.** Ban an IP or a whole range from the dashboard, or let autopilot do it. A ban reaches every
copy in about a millisecond and is checked in memory, so a banned flood never touches Redis. Bans
made while Redis is down are shared once it's back.

**Autopilot.** Bans clients that keep hammering, warns at 80% of a monthly quota, and labels clients
by how they behave (human, bot, crawler, retry bug). A plan can give a label a little more or less
burst room, but never a higher steady rate or quota, because labels are only guesses.

**Organisations.** Teams sign in with email and password, have owner, admin or viewer roles, and see
only their own customers. An org can have one monthly budget shared by all its customers.
See [docs/ORGS.md](docs/ORGS.md).

**Explain and ask.** Pick any blocked request, customer or client and get a short explanation of
which limit stopped it and the numbers behind it. An ops chat answers questions such as "what
happened last night?" from remembered incidents (bans, floods, quota alerts, outages). The answers
are built from rules. An AI model (Anthropic, or any OpenAI-compatible API such as Groq or Ollama)
is optional and may only reword the facts it is given; client IPs are hashed first.
See [docs/AI.md](docs/AI.md).

**Kubernetes.** With `--kube`, the policy and customers become Kubernetes resources
(`RateLimitPolicy`, `Tenant`) that every copy watches. One copy is elected leader and writes status
back. See [docs/OPERATOR.md](docs/OPERATOR.md).

**XDP fast path (Linux, optional).** A small eBPF program drops banned IPs and packet floods inside
the network driver, before Linux spends any work on them. See [docs/XDP.md](docs/XDP.md).

**Metrics.** Prometheus metrics at `/metrics`, protected with `--metrics-key` if you set one.

## Tested for real

Besides the unit tests, each part has a script that runs it against the real thing:

| Command | What it shows |
|---|---|
| `make prove` | two copies behind nginx share one limit |
| `make prove-cluster` | a 3-node Redis Cluster: shared limits, instant bans, a node killed and brought back |
| `make prove-authz` | forward auth behind real Envoy, nginx and Traefik |
| `make prove-orgs` | two orgs on two copies: isolation, a shared org budget, revoked logins |
| `make prove-operator` | a real Kubernetes cluster (kind): Helm install, live policy edits, leader failover. Runs in CI |
| `./xdp/test.sh` | a 2.4M packets/s flood cut to its 1,000 packets/s budget, in both XDP modes |

Speed numbers are in [BENCHMARKS.md](BENCHMARKS.md). In short, on a laptop: about 45 ns for the
short-term check and 105 ns for the full in-memory check (ban, monthly, short-term), with no
allocations.

## Deploy

```bash
make compose-up                                  # Docker Compose: 2 copies, Redis and nginx
helm install limitplane deploy/helm/limitplane   # Kubernetes, with the Helm chart
kubectl apply -k deploy/k8s/overlays/dev         # Kubernetes, with Kustomize
```

[docs/DEPLOY.md](docs/DEPLOY.md) covers each of these, plus ingress and Gateway API.

## Docs

| Doc | About |
|---|---|
| [DEPLOY.md](docs/DEPLOY.md) | Compose, Helm, Kustomize, ingress, Gateway API |
| [AUTHZ.md](docs/AUTHZ.md) | running behind Envoy, nginx or Traefik |
| [REDIS.md](docs/REDIS.md) | single Redis vs Cluster, how keys are laid out, outages |
| [ORGS.md](docs/ORGS.md) | orgs, users, roles, shared budgets |
| [AI.md](docs/AI.md) | explanations, ops chat, model options, privacy |
| [OPERATOR.md](docs/OPERATOR.md) | Kubernetes mode |
| [XDP.md](docs/XDP.md) | the eBPF fast path |

## Code map

| Path | What's in it |
|---|---|
| `cmd/limitplane` | the program: flags and wiring |
| `internal/limiter` | GCRA, monthly quotas, bans, the Redis script, the fallback for when Redis is down |
| `internal/redisx` | a small Redis client: connection pool, Cluster routing, pub/sub |
| `internal/gateway` | the per-request logic (who, cost, check, headers) and forward auth |
| `internal/policy` | the policy file: parsing, validation, live reload |
| `internal/autopilot` | automatic bans, quota alerts, client labels |
| `internal/org` | orgs, users, roles, dashboard keys |
| `internal/ai` | explanations, incident memory, ops chat, model clients |
| `internal/server` | admin API, login, live feed, metrics, dashboard |
| `internal/kube` | a small Kubernetes client, watches, leader election |
| `web/`, `site/` | the dashboard (built into the binary) and the website |
| `xdp/` | the eBPF program and its loader (a separate Go module) |
| `deploy/` | Helm chart, Kustomize, Kubernetes resources, Prometheus alerts, Gateway API examples |

## Develop

```bash
make test    # all tests, with the race detector
make lint    # go vet + gofmt
make bench   # benchmarks
```
