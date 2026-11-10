#!/usr/bin/env bash
# Organisations end to end: Redis and two LimitPlane replicas in Docker. Two orgs, each with an
# owner and a viewer, and tenants with keys made from the API. It proves that
#   1. the directory is shared: users, tenants and keys made on one replica work on the other;
#   2. orgs are isolated over the API: lists are scoped, cross-org reads and writes get 404,
#      a viewer's writes get 403;
#   3. one org budget is shared by two tenants and enforced across both replicas, with
#      reason org_monthly and the usual headers, while another org is unaffected, and the
#      explainer names the org budget to acme while globex can't ask about acme at all;
#   4. a revoked token is rejected by the other replica, and signing in again works.
# Then it removes everything it started.
set -euo pipefail
cd "$(dirname "$0")/.."
P=lp-orgs
R1=18301 R2=18302 # host ports, loopback only
ADMIN_KEY=prove-orgs-admin-key
PW="correct horse battery staple"
BUDGET=30

down() {
  docker rm -f $P-redis $P-1 $P-2 >/dev/null 2>&1 || true
  docker network rm $P >/dev/null 2>&1 || true
}
down
tmp=$(mktemp -d)
trap 'down; rm -rf "$tmp"' EXIT

fail() { echo "FAIL: $*"; exit 1; }
pass() { echo "PASS: $*"; }

cat >"$tmp/policy.json" <<EOF
{
  "tiers": {"free": {"rate": {"limit": 100, "period": "1s", "burst": 100}, "monthly": 100000}},
  "anonymous": "free"
}
EOF

echo "building the image..."
docker build -q -t limitplane:prove-orgs . >/dev/null
docker network create $P >/dev/null
docker run -d --name $P-redis --network $P redis:7-alpine >/dev/null
for i in 1 2; do
  port=$([ $i = 1 ] && echo $R1 || echo $R2)
  # --trust-proxy so each sign-in below can come from its own address (the login limit is per IP)
  docker run -d --name $P-$i --network $P -p 127.0.0.1:$port:8080 -v "$tmp/policy.json:/etc/limitplane/config.json:ro" \
    -e LIMITPLANE_ADMIN_KEY=$ADMIN_KEY limitplane:prove-orgs \
    --config /etc/limitplane/config.json --redis redis://$P-redis:6379 --trust-proxy >/dev/null
done
for port in $R1 $R2; do
  for _ in $(seq 50); do curl -sf "http://127.0.0.1:$port/healthz" >/dev/null && break; sleep 0.2; done
  curl -sf "http://127.0.0.1:$port/healthz" >/dev/null || fail "replica on :$port didn't start"
done

# call PORT METHOD PATH TOKEN [BODY]: prints the status; the body lands in $tmp/out.
call() {
  local args=(-s -o "$tmp/out" -w '%{http_code}' -X "$2" -H 'Content-Type: application/json')
  [ -n "$4" ] && args+=(-H "Authorization: Bearer $4")
  [ -n "${5:-}" ] && args+=(--data "$5")
  curl "${args[@]}" "http://127.0.0.1:$1$3"
}
expect() { # expect WANT what PORT METHOD PATH TOKEN [BODY]
  local want=$1 what=$2; shift 2
  local got
  got=$(call "$@")
  [ "$got" = "$want" ] || fail "$what: got $got, want $want ($(cat "$tmp/out"))"
}
n=0
signin() { # signin PORT EMAIL: prints a token
  n=$((n + 1))
  curl -sf -H "X-Forwarded-For: 203.0.113.$n" -H 'Content-Type: application/json' \
    --data "{\"email\":\"$2\",\"password\":\"$PW\"}" "http://127.0.0.1:$1/api/login" | jq -r .token
}
ids() { jq -r '[.[].id] | sort | join(",")' "$tmp/out"; }

SUPER=$(curl -sf -H 'Content-Type: application/json' --data "{\"key\":\"$ADMIN_KEY\"}" "http://127.0.0.1:$R1/api/login" | jq -r .token)

# 1. One directory for both replicas.
expect 201 "create org acme" $R1 POST /api/orgs "$SUPER" "{\"name\":\"Acme\",\"budget\":$BUDGET}"
expect 201 "create org globex" $R2 POST /api/orgs "$SUPER" '{"name":"Globex"}'
expect 201 "acme owner" $R1 POST /api/orgs/acme/members "$SUPER" "{\"email\":\"alice@acme.test\",\"role\":\"owner\",\"password\":\"$PW\"}"
expect 201 "globex owner" $R2 POST /api/orgs/globex/members "$SUPER" "{\"email\":\"bob@globex.test\",\"role\":\"owner\",\"password\":\"$PW\"}"
ALICE=$(signin $R2 alice@acme.test) # made on R1, signs in on R2
BOB=$(signin $R1 bob@globex.test)
[ -n "$ALICE" ] && [ "$ALICE" != null ] && [ -n "$BOB" ] && [ "$BOB" != null ] || fail "owners can't sign in on the other replica"
expect 201 "alice invites a viewer" $R2 POST /api/orgs/acme/members "$ALICE" "{\"email\":\"carol@acme.test\",\"role\":\"viewer\",\"password\":\"$PW\"}"
CAROL_ID=$(jq -r .id "$tmp/out")
expect 201 "bob invites a viewer" $R1 POST /api/orgs/globex/members "$BOB" "{\"email\":\"dave@globex.test\",\"role\":\"viewer\",\"password\":\"$PW\"}"
CAROL=$(signin $R1 carol@acme.test)
DAVE=$(signin $R2 dave@globex.test)

for t in acme-web:$R1:$ALICE acme-api:$R2:$ALICE globex-app:$R1:$BOB; do
  IFS=: read -r id port tok <<<"$t"
  expect 201 "create tenant $id" "$port" POST /api/tenants "$tok" "{\"id\":\"$id\",\"tier\":\"free\"}"
  expect 201 "key for $id" "$port" POST "/api/tenants/$id/keys" "$tok"
  jq -r .key "$tmp/out" >"$tmp/key.$id" # shown once; the directory keeps only its hash
done
# Keys are stored hashed; wait until the other replica lists them (pub/sub, normally ~1ms).
for _ in $(seq 50); do
  call $R2 GET /api/tenants "$ALICE" >/dev/null
  [ "$(jq '[.[].keys | length] | add' "$tmp/out")" = 2 ] && break
  sleep 0.05
done
pass "users, tenants and keys made on one replica work on the other"

# 2. Isolation.
expect 200 "carol lists tenants" $R2 GET /api/tenants "$CAROL"
[ "$(ids)" = "acme-api,acme-web" ] || fail "acme viewer sees tenants $(ids)"
expect 200 "dave lists tenants" $R1 GET /api/tenants "$DAVE"
[ "$(ids)" = "globex-app" ] || fail "globex viewer sees tenants $(ids)"
expect 200 "bob lists orgs" $R2 GET /api/orgs "$BOB"
[ "$(ids)" = "globex" ] || fail "globex owner sees orgs $(ids)"
expect 404 "acme viewer reads globex" $R1 GET /api/orgs/globex "$CAROL"
expect 404 "acme owner lists globex members" $R2 GET /api/orgs/globex/members "$ALICE"
expect 404 "globex owner deletes an acme tenant" $R1 DELETE /api/tenants/acme-web "$BOB"
expect 404 "globex owner mints an acme key" $R2 POST /api/tenants/acme-api/keys "$BOB"
expect 404 "globex owner revokes an acme member" $R1 POST "/api/orgs/acme/members/$CAROL_ID/revoke" "$BOB"
expect 404 "globex owner creates a tenant in acme" $R1 POST /api/tenants "$BOB" '{"id":"sneaky","tier":"free","org":"acme"}'
expect 403 "acme viewer creates a tenant" $R2 POST /api/tenants "$CAROL" '{"id":"nope","tier":"free"}'
expect 403 "acme viewer sets the budget" $R1 PATCH /api/orgs/acme "$CAROL" '{"budget":0}'
expect 403 "acme owner bans a client" $R2 POST /api/bans "$ALICE" '{"client":"192.0.2.1","minutes":5}'
pass "cross-org reads and writes get 404, a viewer's writes 403, platform actions 403"

# 3. One budget, two tenants, two replicas.
for i in $(seq 25); do
  for t in acme-web:$R1 acme-api:$R2; do
    IFS=: read -r id port <<<"$t"
    curl -s -o "$tmp/r" -D "$tmp/h" -H "X-Api-Key: $(cat "$tmp/key.$id")" "http://127.0.0.1:$port/v1/ping" -w '%{http_code}\n' >>"$tmp/codes"
    grep -q '^HTTP/1.1 429' "$tmp/h" && { cp "$tmp/h" "$tmp/blocked.h"; cp "$tmp/r" "$tmp/blocked.json"; }
  done
done
ok=$(grep -c '^200$' "$tmp/codes" || true)
[ "$ok" = $BUDGET ] || fail "acme admitted $ok across both replicas, want its budget $BUDGET"
reason=$(jq -r .reason "$tmp/blocked.json")
limit=$(awk -F': ' 'tolower($1)=="ratelimit-limit"{print $2}' "$tmp/blocked.h" | tr -d '\r')
remaining=$(awk -F': ' 'tolower($1)=="ratelimit-remaining"{print $2}' "$tmp/blocked.h" | tr -d '\r')
retry=$(awk -F': ' 'tolower($1)=="retry-after"{print $2}' "$tmp/blocked.h" | tr -d '\r')
[ "$reason" = org_monthly ] && [ "$limit" = $BUDGET ] && [ "$remaining" = 0 ] && [ "${retry:-0}" -gt 0 ] ||
  fail "block: reason $reason, limit $limit, remaining $remaining, retry-after $retry"
echo "  a blocked request: 429 reason=$reason RateLimit-Limit=$limit RateLimit-Remaining=$remaining Retry-After=${retry}s"
echo "  $(jq -r .message "$tmp/blocked.json")"
for port in $R1 $R2; do
  expect 200 "acme's budget on :$port" $port GET /api/orgs/acme "$CAROL"
  [ "$(jq .used "$tmp/out")" = $BUDGET ] || fail "replica :$port reports acme used $(jq .used "$tmp/out")"
done
code=$(curl -s -o /dev/null -w '%{http_code}' -H "X-Api-Key: $(cat "$tmp/key.globex-app")" "http://127.0.0.1:$R2/v1/ping")
[ "$code" = 200 ] || fail "globex got $code after acme's budget ran out"
pass "acme-web and acme-api shared one budget of $BUDGET across both replicas; globex unaffected"

expect 200 "acme viewer reads audit" $R1 GET '/api/audit?limit=1000' "$CAROL"
[ "$(jq '[.[] | select(.tenant | startswith("acme") | not)] | length' "$tmp/out")" = 0 ] || fail "acme's audit shows other tenants"
pass "acme's audit holds only acme decisions"

expect 200 "carol explains acme-web" $R1 POST /api/ai/explain "$CAROL" '{"tenant":"acme-web"}'
[ "$(jq -r .reason "$tmp/out")" = org_monthly ] || fail "explain: $(cat "$tmp/out")"
echo "  $(jq -r .summary "$tmp/out")"
expect 404 "dave explains acme-web" $R1 POST /api/ai/explain "$DAVE" '{"tenant":"acme-web"}'
expect 200 "dave asks about acme" $R1 POST /api/ai/chat "$DAVE" '{"question":"what happened to acme-web?"}'
grep -q acme "$tmp/out" && fail "globex's answer mentions acme: $(cat "$tmp/out")"
pass "the explainer names acme's org budget to acme; globex gets 404 and an answer without acme"

# 4. Revocation.
expect 200 "carol's token on R2" $R2 GET /api/stats "$CAROL"
expect 204 "alice revokes carol on R1" $R1 POST "/api/orgs/acme/members/$CAROL_ID/revoke" "$ALICE"
ms() { perl -MTime::HiRes=time -e 'printf "%d\n", time * 1000'; }
start=$(ms)
for _ in $(seq 100); do
  [ "$(call $R2 GET /api/stats "$CAROL")" = 401 ] && break
  sleep 0.02
done
end=$(ms)
expect 401 "carol's revoked token on R2" $R2 GET /api/stats "$CAROL"
expect 401 "carol's revoked token on R1" $R1 GET /api/me "$CAROL"
CAROL=$(signin $R2 carol@acme.test)
expect 200 "carol signs in again" $R1 GET /api/me "$CAROL"
pass "a revoked token is rejected on the other replica (within $((end - start)) ms), a new sign-in works"

echo "all org checks passed"
