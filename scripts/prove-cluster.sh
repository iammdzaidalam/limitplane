#!/usr/bin/env bash
# Two gateways on a 3-master Redis Cluster (docker-compose.cluster.yml). Proves:
#   1. one shared limit across both gateways;
#   2. bans and unbans reach the other gateway at once (pub/sub, not the 2s sync);
#   3. stopping a master degrades only the tenants in its slots, a ban made meanwhile stays
#      local, and after restart it reaches the other gateway and limits are shared again.
set -euo pipefail
cd "$(dirname "$0")/.."
A=${A:-http://localhost:18091}
B=${B:-http://localhost:18092}
ADMIN_KEY=${ADMIN_KEY:-cluster-demo-key}
COMPOSE="docker compose -f docker-compose.cluster.yml"
LIVE=redis-1 # a node to ask about the cluster

fail() { echo "FAIL: $*"; exit 1; }
pass() { echo "PASS: $*"; }
rcli() { $COMPOSE exec -T "$1" redis-cli "${@:2}" | tr -d '\r'; }
slot() { rcli "$LIVE" cluster keyslot "$1"; }
# owner SLOT: the compose service (redis-N) serving it
owner() {
  rcli "$LIVE" cluster nodes | awk -v s="$1" '{
    for (i = 9; i <= NF; i++) {
      if ($i ~ /^\[/) continue
      n = split($i, r, "-"); lo = r[1]; hi = (n > 1 ? r[2] : r[1])
      if (s + 0 >= lo + 0 && s + 0 <= hi + 0) { split($2, a, "[:@]"); sub(/^10\.207\.7\.1/, "redis-", a[1]); print a[1] }
    }
  }'
}
# code URL IP: the status, plus the reason for a 429 ("429 banned", "429 burst")
code() {
  out=$(curl -s -w ' %{http_code}' -H "X-Forwarded-For: $2" "$1/v1/ping")
  c=${out##* }
  [ "$c" = 429 ] && c="$c $(echo "$out" | sed -nE 's/.*"reason":"([a-z_]+)".*/\1/p')"
  echo "$c"
}
remaining() { curl -s -D - -o /dev/null -H "X-Forwarded-For: $2" "$1/v1/ping" | awk 'tolower($1)=="ratelimit-remaining:"{print $2+0}'; }
api() { curl -s -o /dev/null -w '%{http_code}' -X "$1" -H "Authorization: Bearer $TOKEN" "${@:3}" "$2"; }
ban() { api POST "$1/api/bans" -d "{\"client\":\"$2\",\"minutes\":5,\"reason\":\"prove\"}"; }
# anon_on NODE [not]: a fresh public client IP whose anonymous limit key lives on NODE (or not on it)
anon_on() {
  for _ in $(seq 60); do
    ip="198.18.$((RANDOM % 256)).$((RANDOM % 254 + 1))"
    o=$(owner "$(slot "lp:{anon:$ip}:r")")
    if { [ "${2:-}" = not ] && [ "$o" != "$1" ]; } || { [ "${2:-}" != not ] && [ "$o" = "$1" ]; }; then echo "$ip"; return; fi
  done
  fail "no client ip found for $1"
}

TOKEN=$(curl -s -X POST -H "X-Forwarded-For: 198.19.$((RANDOM % 256)).1" "$A/api/login" -d "{\"key\":\"$ADMIN_KEY\"}" | sed -E 's/.*"token":"([^"]+)".*/\1/')
[ -n "$TOKEN" ] || fail "login"

echo "== 1. shared limit: acme (burst 10) alternating between $A and $B"
sleep 2 # let acme's bucket refill from earlier runs
ok=$(for i in $(seq 20); do [ $((i % 2)) = 0 ] && echo "$A" || echo "$B"; done |
  xargs -P 20 -I{} curl -s -o /dev/null -w '%{http_code}\n' -H 'X-Api-Key: demo-free-key' {}/v1/ping | grep -c 200 || true)
echo "200s: $ok of 20 (shared: 10 + refill; per-gateway limits would admit 20)"
[ "$ok" -ge 10 ] && [ "$ok" -le 13 ] && pass "limit shared across gateways" || fail "limit not shared"

echo "== 2. bans reach the other gateway at once (sync is every 2s; each check runs right after the ban returns)"
base=$((RANDOM % 200 + 1))
for i in 1 2 3 4 5; do
  ip="203.0.113.$((base + i))"
  [ "$(ban "$A" "$ip")" = 204 ] || fail "ban $ip on A"
  got=$(code "$B" "$ip")
  echo "ban $ip on A -> B answers $got"
  [ "$got" = "429 banned" ] || fail "ban not on B yet"
done
cidr="198.51.100.0/24"
[ "$(ban "$B" "$cidr")" = 204 ] || fail "cidr ban"
got=$(code "$A" 198.51.100.77)
echo "ban $cidr on B -> A answers $got for 198.51.100.77"
[ "$got" = "429 banned" ] || fail "cidr ban not on A"
api DELETE "$B/api/bans/$ip" >/dev/null
api DELETE "$A/api/bans/$cidr" >/dev/null
got=$(code "$A" "$ip")
echo "unban $ip on B -> A answers $got"
[ "$got" = 200 ] || fail "unban not on A"
pass "bans and unbans propagate instantly"
[ "${OUTAGE:-1}" = 1 ] || exit 0 # OUTAGE=0: steps 1-2 only (e.g. gateways on single-node Redis)

echo "== 3. stop the master holding the ban list"
down=$(owner "$(slot lp:bans)")
for n in redis-1 redis-2 redis-3; do [ "$n" != "$down" ] && LIVE=$n && break; done
hurt=$(anon_on "$down")
fine=$(anon_on "$down" not)
banned="203.0.113.$((base + 10))"
echo "stopping $down; client $hurt is limited there, $fine elsewhere"
$COMPOSE stop "$down" >/dev/null 2>&1
code "$A" "$hurt" >/dev/null # first touch finds the node dead
r_hurt=$(remaining "$A" "$hurt")
r_fine=$(remaining "$A" "$fine")
echo "remaining after one request: $hurt=$r_hurt (local, burst 10/2 replicas), $fine=$r_fine (shared)"
[ "$r_hurt" -le 4 ] && [ "$r_fine" -ge 8 ] && pass "only the dead master's tenants degrade" || fail "degradation not scoped"
[ "$(ban "$A" "$banned")" = 204 ] || fail "ban during outage"
echo "ban $banned on A while $down is down -> A answers $(code "$A" "$banned"), B answers $(code "$B" "$banned")"

$COMPOSE start "$down" >/dev/null 2>&1
for _ in $(seq 60); do rcli "$LIVE" cluster info | grep -q cluster_state:ok && rcli "$down" ping 2>/dev/null | grep -q PONG && break; sleep 0.5; done
echo "$down is back"
for _ in $(seq 40); do [ "$(code "$B" "$banned")" = "429 banned" ] && break; sleep 0.25; done
got=$(code "$B" "$banned")
echo "B answers $got for $banned (the ban A made during the outage)"
[ "$got" = "429 banned" ] || fail "outage ban lost"
for _ in $(seq 40); do r=$(remaining "$A" "$hurt"); [ "$r" -ge 5 ] && break; sleep 0.25; done
echo "remaining for $hurt: $r"
[ "$r" -ge 5 ] && pass "recovered: outage ban pushed, $hurt shared again" || fail "still degraded"
api DELETE "$A/api/bans/$banned" >/dev/null
