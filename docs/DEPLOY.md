# Deploying LimitPlane

LimitPlane is a reverse proxy. Traffic goes `client -> your ingress -> LimitPlane -> your app`, and
`--upstream` points LimitPlane at the app. Without `--upstream` it serves a demo API, which is handy
for a first look. Share limits between replicas with Redis; without it each replica counts on its own.

Images: `ghcr.io/iammdzaidalam/limitplane:<version>` (amd64 and arm64). Binaries, checksums and the
packaged chart are attached to each [GitHub release](https://github.com/iammdzaidalam/limitplane/releases).

## Docker Compose

Two replicas and Redis behind nginx, on port 8080:

```bash
make compose-up    # docker compose up -d --build
make prove         # checks the two replicas share one limit
make compose-down
```

## Kustomize

```bash
kubectl apply -k deploy/k8s/overlays/dev     # 1 replica
kubectl apply -k deploy/k8s/overlays/prod    # 3-20 replicas
```

Before production, change `admin-key` in `deploy/k8s/base/secret.yaml` (better: generate the Secret
outside git), put your policy in `configmap.yaml` and add `--upstream=http://my-app.my-ns.svc` to the
Deployment args.

Prometheus Operator users can add the ServiceMonitor and alerts as a component:

```yaml
# your overlay's kustomization.yaml
resources: [../../base]
components: [../../observability]
```

## Helm

```bash
helm install limitplane deploy/helm/limitplane -n limitplane --create-namespace \
  --set upstream=http://my-app.default.svc
```

Or from a release: `helm install limitplane https://github.com/iammdzaidalam/limitplane/releases/download/vX.Y.Z/limitplane-X.Y.Z.tgz`.

The install notes print the admin key and the port-forward for the dashboard. In short:

```bash
kubectl -n limitplane get secret limitplane -o jsonpath='{.data.admin-key}' | base64 -d
kubectl -n limitplane port-forward svc/limitplane 18080:80
# http://localhost:18080/_limitplane/  (or / in demo mode)
```

Useful values (see `values.yaml` for all of them):

| Value | Default | What it does |
| --- | --- | --- |
| `upstream` | `""` | App to protect. Empty runs the demo API. |
| `policy` | one `free` tier | The policy file, same shape as `limitplane.example.json`. Hot-reloaded. |
| `existingSecret` | `""` | Use your own Secret with `admin-key`, `metrics-key`, `redis-url`. For Redis Cluster set `redis-url` to `redis+cluster://h1:6379,h2:6379` (see [REDIS.md](REDIS.md)). |
| `redis.enabled` | `true` | Bundled single-node Redis. Set `redisUrl` to use your own. |
| `authz.enabled` | `false` | Forward-auth port and its `<release>-authz` Service for Envoy, ingress-nginx, Traefik. `authz.allowFrom` lists the namespaces the NetworkPolicy lets in. |
| `operator.enabled` | `false` | Read policy and tenants from `RateLimitPolicy`/`Tenant` CRs (see [OPERATOR.md](OPERATOR.md)). |
| `serviceMonitor.enabled` | `false` | Scrape `/metrics` with the metrics key. |
| `prometheusRule.enabled` | `false` | Alerts: high block rate, Redis fallback active, fail-closed errors, tenant past 80% of its quota, tenant out of quota. |

Without `existingSecret` the chart generates the admin and metrics keys on first install and keeps
them on upgrade. Policy changes roll out without a restart; key changes restart the pods.

## Behind an ingress or gateway

Two ways to put LimitPlane behind a proxy:

- **Inline:** the proxy routes to the `limitplane` Service and LimitPlane forwards to `--upstream`.
  Keep `--trust-proxy` on (the chart default) so LimitPlane limits by the client address in
  `X-Forwarded-For` instead of by the ingress pod. Only do that when every request reaches
  LimitPlane through that proxy, otherwise clients can spoof the header.
- **Forward auth:** the proxy asks LimitPlane about each request and sends it straight to your app.
  Run with `--authz-addr :9091` (Helm: `--set authz.enabled=true` plus `authz.allowFrom` set to the
  proxy's namespace). `deploy/k8s/gateway-api` has one example per proxy:
  - `envoy-gateway.yaml`: `SecurityPolicy` with `extAuth.http` on `/authz/envoy`
  - `ingress-nginx.yaml`: `auth-url` on `/authz/nginx`, plus the snippet that turns its 403 into a 429
  - `traefik.yaml`: `ForwardAuth` middleware on `/authz/traefik`
  - `authz.yaml`: the `limitplane-authz` Service and the NetworkPolicy, for the Kustomize base

  The forward-auth port must be reachable only by the proxy: it believes the path and client IP the
  caller names. [AUTHZ.md](AUTHZ.md) covers the headers each proxy needs, why the port is separate
  and what fails how. `make prove-authz` runs all three proxies in Docker.

The dashboard and admin API are under `/_limitplane/` on the same host in inline mode (at `/` on the
main port otherwise). They need the admin key, but you can also block that path at the ingress and
use a port-forward instead.
