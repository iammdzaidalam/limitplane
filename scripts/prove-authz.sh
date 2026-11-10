#!/usr/bin/env bash
# LimitPlane as forward auth: real Envoy (ext_authz, HTTP), nginx (auth_request) and Traefik
# (ForwardAuth) in Docker, each in front of a tiny backend, all asking one LimitPlane on :9091.
# For each proxy it proves: allows carry RateLimit headers, a burst gets 429 with its headers and
# JSON body at the client, the original path is priced (route prefix, query dropped, escapes
# decoded, another proxy's header ignored), the identity header the backend sees can't be forged,
# the client IP comes from X-Forwarded-For, a ban blocks, and the backend is never hit on a block.
set -euo pipefail
cd "$(dirname "$0")/.."
P=lp-authz          # name prefix for everything this script starts
NET=10.207.88       # its own /24
CLIENT=$NET.100     # the only client
ADMIN_KEY=prove-authz-key
ENVOY_IMAGE=${ENVOY_IMAGE:-envoyproxy/envoy:v1.34.1}
TRAEFIK_IMAGE=${TRAEFIK_IMAGE:-traefik:v3.4}

down() {
  docker rm -f $P-client $P-backend $P-limitplane $P-envoy $P-nginx $P-traefik >/dev/null 2>&1 || true
  docker network rm $P >/dev/null 2>&1 || true
}
down # leftovers from an interrupted run
tmp=$(mktemp -d)
trap 'down; rm -rf "$tmp"' EXIT

fail() { echo "FAIL: $*"; exit 1; }
pass() { echo "PASS: $*"; }

# Burst 5 refilling one unit per 10s, so a few seconds of testing see no refill. One tenant per
# proxy and step, so steps don't share a bucket.
keys=""
for p in envoy nginx traefik; do
  for s in burst cost enc ban; do keys="$keys\"$p-$s\": {\"id\": \"$p-$s\", \"tier\": \"free\"},"; done
done
cat >"$tmp/policy.json" <<EOF
{
  "tiers": {"free": {"rate": {"limit": 1, "period": "10s", "burst": 5}, "monthly": 100000}},
  "routes": [{"prefix": "/v1/generate", "cost": 5}],
  "keys": {${keys%,}},
  "anonymous": "free"
}
EOF

# Counts every hit except /_hits, and echoes what LimitPlane told it through the proxy.
cat >"$tmp/backend.py" <<'EOF'
import http.server, json
hits = 0
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        global hits
        if self.path == "/_hits":
            body = str(hits)
        else:
            hits += 1
            body = json.dumps({"path": self.path, "tenant": self.headers.get("X-Limitplane-Tenant", ""),
                               "remaining": self.headers.get("RateLimit-Remaining", "")})
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    do_POST = do_GET
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("", 9000), H).serve_forever()
EOF

cat >"$tmp/envoy.yaml" <<'EOF'
static_resources:
  listeners:
    - name: web
      address: {socket_address: {address: 0.0.0.0, port_value: 80}}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: web
                use_remote_address: true # append the client to X-Forwarded-For
                route_config:
                  virtual_hosts:
                    - {name: app, domains: ["*"], routes: [{match: {prefix: /}, route: {cluster: backend}}]}
                http_filters:
                  - name: envoy.filters.http.ext_authz
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
                      failure_mode_allow: false
                      allowed_headers: {patterns: [{exact: x-api-key}, {exact: x-forwarded-for}]}
                      http_service:
                        server_uri: {uri: "http://limitplane:9091", cluster: limitplane, timeout: 0.25s}
                        path_prefix: /authz/envoy
                        authorization_response:
                          allowed_upstream_headers: {patterns: [{exact: x-limitplane-tenant}, {exact: x-limitplane-tier}, {prefix: ratelimit-}]}
                          allowed_client_headers: {patterns: [{prefix: ratelimit-}, {prefix: x-ratelimit-}, {exact: retry-after}, {exact: content-type}]}
                          allowed_client_headers_on_success: {patterns: [{prefix: ratelimit-}, {prefix: x-ratelimit-}]}
                  - name: envoy.filters.http.router
                    typed_config: {"@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router}
  clusters:
    - name: backend
      type: STRICT_DNS
      load_assignment: {cluster_name: backend, endpoints: [{lb_endpoints: [{endpoint: {address: {socket_address: {address: backend, port_value: 9000}}}}]}]}
    - name: limitplane
      type: STRICT_DNS
      load_assignment: {cluster_name: limitplane, endpoints: [{lb_endpoints: [{endpoint: {address: {socket_address: {address: limitplane, port_value: 9091}}}}]}]}
EOF

cat >"$tmp/nginx.conf" <<'EOF'
server {
  listen 80;
  location = /_limitplane {
    internal;
    proxy_pass http://limitplane:9091/authz/nginx;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Original-Method $request_method;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  }
  location / {
    auth_request /_limitplane;
    auth_request_set $lp_tenant $upstream_http_x_limitplane_tenant;
    auth_request_set $lp_limit $upstream_http_ratelimit_limit;
    auth_request_set $lp_remaining $upstream_http_ratelimit_remaining;
    auth_request_set $lp_reset $upstream_http_ratelimit_reset;
    auth_request_set $lp_retry $upstream_http_retry_after;
    auth_request_set $lp_reason $upstream_http_x_limitplane_reason;
    add_header RateLimit-Limit $lp_limit always;
    add_header RateLimit-Remaining $lp_remaining always;
    add_header RateLimit-Reset $lp_reset always;
    proxy_set_header X-Limitplane-Tenant $lp_tenant;
    proxy_set_header RateLimit-Remaining $lp_remaining;
    # auth_request passes only 401 and 403 on, so LimitPlane answers a block with 403; make it a 429.
    error_page 403 = @limited;
    proxy_pass http://backend:9000;
  }
  location @limited {
    add_header RateLimit-Limit $lp_limit always;
    add_header RateLimit-Remaining $lp_remaining always;
    add_header RateLimit-Reset $lp_reset always;
    add_header Retry-After $lp_retry always;
    default_type application/json;
    return 429 '{"error":"rate_limited","reason":"$lp_reason","retryAfter":$lp_retry}\n';
  }
}
EOF

cat >"$tmp/traefik.yml" <<'EOF'
http:
  routers:
    app: {rule: "PathPrefix(`/`)", entryPoints: [web], middlewares: [limitplane], service: backend}
  middlewares:
    limitplane:
      forwardAuth:
        address: http://limitplane:9091/authz/traefik
        authResponseHeaders: [X-Limitplane-Tenant, X-Limitplane-Tier, RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset]
  services:
    backend: {loadBalancer: {servers: [{url: "http://backend:9000"}]}}
EOF
chmod 755 "$tmp" && chmod 644 "$tmp"/*

echo "== building LimitPlane and starting Envoy, nginx, Traefik, a backend and a client"
docker build -q -t limitplane:prove-authz . >/dev/null
docker network create --subnet $NET.0/24 $P >/dev/null
run() { docker run -d --name "$P-$1" --network $P --network-alias "$1" "${@:2}" >/dev/null; }
run backend -v "$tmp/backend.py:/backend.py:ro" python:3.12-alpine python -u /backend.py
run limitplane -v "$tmp/policy.json:/etc/lp/policy.json:ro" limitplane:prove-authz \
  --config /etc/lp/policy.json --addr :8090 --authz-addr :9091 --trust-proxy --admin-key $ADMIN_KEY
run envoy -v "$tmp/envoy.yaml:/etc/envoy/envoy.yaml:ro" "$ENVOY_IMAGE" -c /etc/envoy/envoy.yaml --log-level warn
run nginx -v "$tmp/nginx.conf:/etc/nginx/conf.d/default.conf:ro" nginx:alpine
run traefik -v "$tmp/traefik.yml:/etc/traefik/dynamic.yml:ro" "$TRAEFIK_IMAGE" \
  --entryPoints.web.address=:80 --providers.file.filename=/etc/traefik/dynamic.yml --log.level=ERROR
docker run -d --name $P-client --network $P --ip $CLIENT --entrypoint sleep nginx:alpine infinity >/dev/null

cx() { docker exec $P-client "$@"; }
# req PROXY KEY PATH [curl args]: "code|RateLimit-Remaining|Retry-After|body" as the client sees it
req() {
  local raw
  raw=$(cx sh -c 'p=$0 k=$1 u=$2; shift 2
    curl -s -D /tmp/h -o /tmp/b -w "%{http_code}\n" -H "X-Api-Key: $k" "$@" "http://$p$u"; cat /tmp/h; echo "~"; cat /tmp/b' "$@")
  hdr() { echo "$raw" | awk -F': ' -v h="$1" '/^~/{exit} tolower($1)==h{print $2}' | tr -d '\r'; }
  echo "$(echo "$raw" | head -1)|$(hdr ratelimit-remaining)|$(hdr retry-after)|$(echo "$raw" | sed '1,/^~/d' | tr -d '\n')"
}
hits() { cx curl -s http://backend:9000/_hits; }
field() { echo "$1" | cut -d'|' -f"$2"; }
api() { cx curl -s -X "$1" -H "Authorization: Bearer $TOKEN" "http://limitplane:8090/api/$2" "${@:3}"; }

for u in limitplane:9091/healthz envoy/ nginx/ traefik/; do
  for _ in $(seq 60); do
    c=$(cx curl -s -o /dev/null -w '%{http_code}' "http://$u" || true)
    [ "$c" = 200 ] && break
    sleep 0.25
  done
  [ "$c" = 200 ] || { docker logs "$P-${u%%[:/]*}" 2>&1 | tail -20; fail "$u not up ($c)"; }
done
TOKEN=$(cx curl -s -X POST http://limitplane:8090/api/login -d "{\"key\":\"$ADMIN_KEY\"}" | sed -E 's/.*"token":"([^"]+)".*/\1/')
[ -n "$TOKEN" ] || fail "admin login"
c=$(cx curl -s -o /dev/null -w '%{http_code}' -H 'X-Original-URI: /' http://limitplane:8090/authz/nginx)
echo "public port :8090 answers $c for /authz/nginx (the checks live only on :9091)"
[ "$c" = 404 ] || fail "authz reachable on the public port"

for p in envoy nginx traefik; do
  echo
  echo "== $p"
  # 1. allow, then burst
  h0=$(hits)
  out=$(for _ in $(seq 7); do req $p $p-burst /v1/ping; done)
  ok=$(echo "$out" | grep -c '^200|' || true)
  first=$(echo "$out" | head -1)
  last=$(echo "$out" | tail -1)
  echo "7 rapid GET /v1/ping (burst 5): $ok x 200, then: $(field "$last" 1) Retry-After=$(field "$last" 3) RateLimit-Remaining=$(field "$last" 2) body=$(field "$last" 4)"
  [ "$ok" = 5 ] || fail "$p admitted $ok of 7, want 5"
  if [ $p = traefik ]; then # ForwardAuth copies headers to the backend on allow, not to the client
    echo "allow: backend saw $(field "$first" 4)"
    echo "$first" | grep -q '"remaining": "4"' || fail "$p: backend didn't get RateLimit-Remaining"
  else
    echo "allow: client saw RateLimit-Remaining=$(field "$first" 2)"
    [ "$(field "$first" 2)" = 4 ] || fail "$p: no RateLimit-Remaining on allow"
  fi
  [ "$(field "$last" 1)" = 429 ] && [ -n "$(field "$last" 3)" ] && [ "$(field "$last" 2)" = 0 ] &&
    echo "$last" | grep -q '"reason":"burst"' || fail "$p: burst block missing status, headers or body"
  [ "$(($(hits) - h0))" = 5 ] || fail "$p: backend hit $(($(hits) - h0)) times, want 5"
  pass "$p: 5 allowed with headers, 2 blocked with 429 + Retry-After + JSON, backend hit 5 times"

  # 2. the original path is priced: /v1/generate costs 5 even with a query, a forged
  #    other-proxy header and a forged tenant header; the backend sees the real tenant
  h0=$(hits)
  out=$(req $p $p-cost '/v1/generate/run?prompt=hi' -X POST -H 'X-Original-URI: /v1/ping' -H 'X-Forwarded-Uri: /v1/ping' -H 'X-Limitplane-Tenant: evil')
  echo "POST /v1/generate/run?prompt=hi (forged X-Original-URI, X-Forwarded-Uri, X-Limitplane-Tenant): $(field "$out" 1), backend saw $(field "$out" 4)"
  echo "$out" | grep -q "\"tenant\": \"$p-cost\"" || fail "$p: backend saw a forged or missing tenant"
  audit=$(api GET 'audit?limit=1')
  echo "audit: $(echo "$audit" | sed -E 's/.*"client":"([^"]*)","method":"([^"]*)","path":"([^"]*)","cost":([0-9]+).*/client=\1 \2 \3 cost=\4/')"
  echo "$audit" | grep -q "\"client\":\"$CLIENT\",\"method\":\"POST\",\"path\":\"/v1/generate/run\",\"cost\":5" ||
    fail "$p: audit should show $CLIENT (from X-Forwarded-For) POST /v1/generate/run at cost 5"
  out=$(req $p $p-cost /v1/ping)
  echo "then GET /v1/ping: $(field "$out" 1) ($(field "$out" 4))"
  [ "$(field "$out" 1)" = 429 ] || fail "$p: cost 5 not applied"
  out=$(req $p $p-enc '/v1/%67enerate')
  then=$(req $p $p-enc /v1/ping)
  echo "GET /v1/%67enerate: $(field "$out" 1), then GET /v1/ping: $(field "$then" 1)"
  [ "$(field "$out" 1)" = 200 ] && [ "$(field "$then" 1)" = 429 ] || fail "$p: escaped path not priced as /v1/generate"
  [ "$(($(hits) - h0))" = 2 ] || fail "$p: backend hit $(($(hits) - h0)) times, want 2 (blocks must not reach it)"
  pass "$p: original path priced at cost 5, forged headers ignored, client $CLIENT"

  # 3. a ban blocks, and the backend never sees it
  h0=$(hits)
  c=$(api POST bans -o /dev/null -w '%{http_code}' -d "{\"client\":\"$CLIENT\",\"minutes\":5,\"reason\":\"prove\"}")
  [ "$c" = 204 ] || fail "ban: $c"
  out=$(req $p $p-ban /v1/ping)
  echo "banned $CLIENT: $(field "$out" 1) Retry-After=$(field "$out" 3) body=$(field "$out" 4)"
  api DELETE "bans/$CLIENT" >/dev/null
  echo "$out" | grep -q '"reason":"banned"' && [ "$(field "$out" 1)" = 429 ] || fail "$p: ban not enforced"
  [ "$(hits)" = "$h0" ] || fail "$p: backend hit on a ban"
  out=$(req $p $p-ban /v1/ping)
  [ "$(field "$out" 1)" = 200 ] || fail "$p: unban not applied"
  pass "$p: ban blocks with 429, backend not hit; unban lets it through"
done

echo
pass "Envoy, nginx and Traefik all enforce LimitPlane's decisions as forward auth"
