# Forward auth: LimitPlane next to the traffic, not in it

Inline, LimitPlane is a reverse proxy: every byte of every request goes through it. With forward
auth the proxy you already run (Envoy, ingress-nginx, Traefik) asks LimitPlane one question per
request, "may this through?", and sends the traffic straight to your app. LimitPlane sees headers
only, never bodies, and no app has to change.

```
client ──▶ Envoy / nginx / Traefik ─────────────────────────────▶ your app
                 │ check: method, path, X-Api-Key, X-Forwarded-For    ▲ X-Limitplane-Tenant, RateLimit-*
                 ▼                                                    │
           LimitPlane :9091 ── 200 + RateLimit-*  ── or ── 429 + Retry-After + JSON ──▶ client
```

Turn it on with `--authz-addr :9091` (or `LIMITPLANE_AUTHZ_ADDR`; Helm: `authz.enabled=true`).
`deploy/k8s/gateway-api` has a working setup for each proxy and `make prove-authz` runs all three in
Docker against one LimitPlane.

## Same decision as inline

The middleware and the check endpoints call the same `Gateway.Check`: one Meter call (ban, monthly,
burst, nothing spent unless all pass), the same `RateLimit-*` headers, the same 429 body. So bans,
degraded mode while Redis is down, `--fail-closed` (503), the audit ring, SSE, metrics and the
autopilot all work exactly as inline. The API key comes from `X-Api-Key`, the client IP from
`X-Forwarded-For` under `--trust-proxy` (right-most hop that isn't one of our proxies).

| | Endpoint | Original request from | Allow | Block |
|---|---|---|---|---|
| Envoy `ext_authz` (HTTP) | `/authz/envoy` + original path (`path_prefix`) | the check request's own method and path | 200 | 429, or 503 |
| nginx `auth_request` | `/authz/nginx` | `X-Original-URI`, `X-Original-Method` | 200 | 403 (see below), or 503 |
| Traefik `ForwardAuth` | `/authz/traefik` | `X-Forwarded-Uri`, `X-Forwarded-Method` | 200 | 429, or 503 |

Every answer also carries `X-Limitplane-Tenant` and `X-Limitplane-Tier`, for the proxy to copy onto
the request to your app; a block adds `X-Limitplane-Reason`.

How the original path is read:

- **One dialect per endpoint, never a guess.** Each endpoint reads only the headers its proxy
  writes. An endpoint that tried `X-Original-URI`, then `X-Forwarded-Uri`, would let a client behind
  Traefik (which forwards client headers to the auth server) send `X-Original-URI: /v1/ping` and pay
  1 unit for `/v1/generate`.
- **The query is dropped**, so `?page=2` never changes the price.
- **Escapes are decoded and dot segments resolved**, as inline: nginx and Traefik send the raw
  request URI, so without this `/v1/%67enerate` or `/v1/ping/../generate` would be priced as a
  cheap route and then served by the app as the expensive one.
- **A missing header is a 400**, not a request for `/`: a misconfigured proxy should fail loudly,
  not undercharge.
- The Envoy endpoint is routed by hand. A `ServeMux` answers `//v1` with a redirect, which Envoy would
  hand to the client instead of a decision.

## Getting the headers through

Each proxy drops the check response's headers unless told otherwise.

- **Envoy:** `allowed_headers` must list `x-api-key` and `x-forwarded-for` (only Host, Method, Path,
  Content-Length and Authorization go by default). `allowed_upstream_headers` copies tenant, tier and
  `ratelimit-*` to the app, replacing any the client sent; `allowed_client_headers` passes
  `ratelimit-*`, `retry-after` and `content-type` on a block, `allowed_client_headers_on_success`
  passes `ratelimit-*` on an allow. Envoy Gateway's `SecurityPolicy` exposes `headersToExtAuth` and
  `headersToBackend` but not the on-success list.
- **nginx:** `auth_request` treats anything but 2xx, 401 and 403 as an error and returns 500, so the
  nginx endpoint blocks with 403 and the config turns it back into a 429:
  `auth_request_set` captures the headers, `add_header ... always` returns them, and
  `error_page 403 = @limited` answers `429` with a JSON body built from `X-Limitplane-Reason` and
  `Retry-After` (nginx discards the subrequest body). On ingress-nginx this needs snippet annotations;
  without them the client gets a plain 403. A 503 from `--fail-closed` reaches the client as 500.
- **Traefik:** `authResponseHeaders` copies the headers to the app on an allow; a block (status,
  headers, body) reaches the client whole. Traefik can't add response headers to an allowed request,
  so clients see `RateLimit-*` only on a block.

## Which port, and who may call it

The check endpoints are on their own listener, not on the public or the admin mux.

- **Not public.** The endpoint believes the path and, with `--trust-proxy`, the client address that
  the caller names. A client who could call it directly would price its own requests, and could
  forge `X-Forwarded-For: <victim>` to drain the victim's anonymous budget until the autopilot
  storm-bans the victim's IP on every replica.
- **Not admin.** The admin mux wants a JWT from a login. Proxies can't log in, and handing them an
  admin credential would let a compromised ingress pod edit the policy.
- **No per-request secret.** The check request carries the client's credentials, so it can't also
  authenticate the proxy by them. Envoy and nginx could add a static header, Traefik `ForwardAuth`
  can't. So the boundary is the network: a ClusterIP Service (`limitplane-authz`) and a NetworkPolicy
  that admits only the proxy's namespace on that port (`authz.yaml`, or Helm `authz.allowFrom`).

The cost of this choice: anything that runs in the allowed namespace can call the port. If that is
too wide, put the proxy pods in a namespace of their own.

## Failing open or closed

If LimitPlane is unreachable, the proxy decides: Envoy `failure_mode_allow` (`failOpen` in Envoy
Gateway); nginx and Traefik answer 500. The examples fail open on Envoy to match LimitPlane's own
default with Redis down: an outage of the limiter costs you limiting, not the site. Keep the check
timeout short (the proof uses 250ms); a decision is a map lookup and at most one Redis round trip.

## Proof

`make prove-authz` builds the image and starts LimitPlane, a backend that counts hits and echoes
what it was told, a client with a fixed IP, and real Envoy, nginx and Traefik containers. For each
proxy it checks that allows carry the headers, that a burst gets 429 with `Retry-After`,
`RateLimit-*` and the JSON body at the client, that `POST /v1/generate/run?prompt=hi` costs 5 while
the client forges `X-Original-URI`, `X-Forwarded-Uri` and `X-Limitplane-Tenant`, that
`/v1/%67enerate` costs 5, that the audit log shows the client's IP from `X-Forwarded-For`, that a
ban blocks, and that the backend's hit count never moves on a block. Then it removes everything.
