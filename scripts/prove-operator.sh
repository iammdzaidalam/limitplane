#!/usr/bin/env bash
# The operator on a real Kubernetes cluster (kind), installed with the Helm chart. Proves:
#   1. the chart's RBAC is enough: CRDs, Secrets, Leases and Events work as the pod's ServiceAccount;
#   2. a RateLimitPolicy and Tenant reach both replicas, and edits land on both without a restart;
#   3. an invalid policy is refused with status and an Event, and the last good one keeps serving;
#   4. a Tenant whose Secret is missing is marked not ready, then picked up when the Secret appears;
#   5. exactly one leader, and deleting its pod hands the Lease to the other replica;
#   6. monthly usage is shared through Redis and written to the Tenant's status.
# Needs docker, kind, kubectl and helm. KEEP=1 leaves the cluster up afterwards.
set -euo pipefail
cd "$(dirname "$0")/.."
CLUSTER=${CLUSTER:-lp-prove}
NS=limitplane
ADMIN_KEY=prove-admin-key
CTX=kind-$CLUSTER
k() { kubectl --context "$CTX" -n "$NS" "$@"; }

fail() { echo "FAIL: $*"; k get pods,rlp,tenants,leases 2>&1 | sed 's/^/  /'; exit 1; }
pass() { echo "PASS: $*"; }
# wait_for SECONDS DESCRIPTION CMD...: retry CMD until it succeeds
wait_for() {
  local t=$1 what=$2; shift 2
  for _ in $(seq "$t"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  fail "$what (waited ${t}s)"
}

PIDS=()
cleanup() {
  for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null; wait "$p" 2>/dev/null || true; done
  [ "${KEEP:-}" = 1 ] || kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  kind create cluster --name "$CLUSTER" --wait 120s
fi
docker build -q -t limitplane:prove . >/dev/null
kind load docker-image limitplane:prove --name "$CLUSTER" >/dev/null

kubectl --context "$CTX" create namespace "$NS" --dry-run=client -o yaml | kubectl --context "$CTX" apply -f - >/dev/null
helm --kube-context "$CTX" upgrade --install limitplane deploy/helm/limitplane -n "$NS" --wait --timeout 3m \
  --set image.repository=limitplane --set image.tag=prove --set image.pullPolicy=Never \
  --set autoscaling.enabled=false --set replicaCount=2 \
  --set operator.enabled=true --set adminKey="$ADMIN_KEY" \
  --set redis.persistence.enabled=false >/dev/null
k rollout status deploy/limitplane --timeout 2m >/dev/null
# Start from no CRs, in case a KEEP=1 run left some behind.
k delete rlp,tenants --all >/dev/null
k delete secret acme-key globex-key --ignore-not-found >/dev/null
k rollout restart deploy/limitplane >/dev/null # replicas keep a deleted policy, so start them fresh
k rollout status deploy/limitplane --timeout 2m >/dev/null
pass "chart installed: CRDs, RBAC, Redis and 2 replicas with --kube"

# One port-forward per pod, so each replica can be asked on its own. FWD holds "pod=port" pairs
# (macOS ships bash 3.2: no associative arrays).
FWD=()
BASE=18095
# live_pods: ready gateway pods not on their way out (a terminating pod still says Running)
live_pods() {
  k get pods -l app.kubernetes.io/component=gateway \
    -o jsonpath='{range .items[*]}{.metadata.name} {.metadata.deletionTimestamp} {.status.containerStatuses[0].ready}{"\n"}{end}' |
    awk 'NF == 2 && $2 == "true" { print $1 }'
}
two_live() { [ "$(live_pods | grep -c .)" -eq 2 ]; }
forward() {
  for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null; wait "$p" 2>/dev/null || true; done
  PIDS=(); FWD=()
  BASE=$((BASE + 10)) # fresh ports, so a dying forward can't answer for the new pod
  local i=0
  wait_for 90 "2 live gateway pods" two_live
  for pod in $(live_pods); do
    local port=$((BASE + i)); i=$((i + 1))
    k port-forward "pod/$pod" "$port:8080" >/dev/null 2>&1 &
    PIDS+=($!); FWD+=("$pod=$port")
    wait_for 15 "port-forward to $pod" curl -sf "localhost:$port/healthz"
  done
}
pods() { for f in ${FWD[@]+"${FWD[@]}"}; do echo "${f%%=*}"; done; }
port() { for f in ${FWD[@]+"${FWD[@]}"}; do [ "${f%%=*}" = "$1" ] && echo "${f#*=}"; done; }
# limit POD [KEY]: the RateLimit-Limit (the tier's burst) a request gets from that replica
limit() {
  local h=()
  [ -n "${2:-}" ] && h=(-H "X-Api-Key: $2")
  curl -s -D - -o /dev/null ${h[@]+"${h[@]}"} "localhost:$(port "$1")/v1/ping" |
    awk 'tolower($1)=="ratelimit-limit:"{print $2+0}'
}
# all_limit WANT [KEY]: every replica reports WANT
all_limit() { for p in $(pods); do [ "$(limit "$p" "${2:-}")" = "$1" ] || return 1; done; }
# stats POD: /api/stats from that replica. Logins are limited to 5 a minute per IP, so log in once:
# the token is signed with a key derived from the admin key, which every replica shares.
login() {
  TOKEN=$(curl -s -X POST "localhost:$(port "$1")/api/login" -d "{\"key\":\"$ADMIN_KEY\"}" |
    sed -nE 's/.*"token":"([^"]+)".*/\1/p')
  [ -n "$TOKEN" ] || fail "admin login on $1"
}
stats() { curl -s -H "Authorization: Bearer $TOKEN" "localhost:$(port "$1")/api/stats"; }
cond() { k get "$1" -o jsonpath="{.status.conditions[?(@.type==\"$2\")].$3}"; }
is() { [ "$("${@:2}")" = "$1" ]; }

forward
[ "$(pods | wc -w)" -eq 2 ] || fail "want 2 running replicas"
login "$(pods | head -1)"
for p in $(pods); do
  stats "$p" | grep -q '"kube":true' || fail "$p does not report kube mode"
done
# Before any RateLimitPolicy exists, the chart's bootstrap policy (free burst 20) serves.
all_limit 20 || fail "bootstrap policy not serving (want limit 20)"
pass "both replicas in kube mode, serving the bootstrap policy until a RateLimitPolicy exists"

k apply -f deploy/k8s/samples/ >/dev/null
wait_for 30 "sample policy on both replicas" all_limit 10
wait_for 30 "acme's pro tier on both replicas" all_limit 100 demo-pro-key
wait_for 30 "policy Applied=True" is True cond rlp/default Applied status
wait_for 30 "activeReplicas=2" is 2 k get rlp/default -o jsonpath='{.status.activeReplicas}'
wait_for 30 "tenant Ready=True" is True cond tenant/acme Ready status
pass "RateLimitPolicy and Tenant (key from a Secret) live on both replicas; Applied=True, activeReplicas=2"

k patch rlp default --type merge -p '{"spec":{"tiers":{"pro":{"rate":{"limit":50,"period":"1s","burst":200}}}}}' >/dev/null
wait_for 20 "edited burst on both replicas" all_limit 200 demo-pro-key
pass "editing the CR changes both replicas' limits without a restart"

# The CRD schema catches the simple mistakes at the API server, before any replica sees them.
out=$(k patch rlp default --type merge -p '{"spec":{"tiers":{"free":{"rate":{"limit":0,"period":"1s"}}}}}' 2>&1) &&
  fail "the API server accepted limit 0"
echo "$out" | grep -q "greater than or equal to 1" || fail "unexpected rejection: $out"
pass "the API server's CRD schema refuses limit 0 before it reaches the operator"

# A burst below a route's cost passes the schema; only the operator's validation can see it.
k patch rlp default --type merge -p '{"spec":{"tiers":{"free":{"rate":{"limit":5,"period":"1s","burst":3}}}}}' >/dev/null
wait_for 20 "invalid policy refused" is Invalid cond rlp/default Applied reason
wait_for 20 "PolicyInvalid event" sh -c "kubectl --context $CTX -n $NS get events --field-selector reason=PolicyInvalid -o name | grep -q ."
sleep 2
all_limit 200 demo-pro-key && all_limit 10 || fail "replicas stopped serving the last good policy"
echo "  message: $(cond rlp/default Applied message)"
pass "an invalid policy is refused (Applied=False Invalid, PolicyInvalid event) and the last good one keeps serving"
k patch rlp default --type merge -p '{"spec":{"tiers":{"free":{"rate":{"limit":5,"period":"1s","burst":10}}}}}' >/dev/null
wait_for 20 "policy valid again" is True cond rlp/default Applied status

cat <<'EOF' | k apply -f - >/dev/null
apiVersion: limitplane.dev/v1alpha1
kind: Tenant
metadata: {name: globex}
spec: {id: globex, tier: enterprise, keySecretRef: {name: globex-key, key: apiKey}}
EOF
wait_for 20 "globex SecretNotFound" is SecretNotFound cond tenant/globex Ready reason
all_limit 100 demo-pro-key || all_limit 200 demo-pro-key || fail "a bad Tenant broke the others"
k create secret generic globex-key --from-literal=apiKey=demo-ent-key >/dev/null
wait_for 20 "globex ready after its Secret appears" is True cond tenant/globex Ready status
wait_for 20 "globex's enterprise tier on both replicas" all_limit 1000 demo-ent-key
k delete tenant globex >/dev/null
wait_for 20 "deleted tenant's key falls back to anonymous" all_limit 10 demo-ent-key
pass "a Tenant without its Secret is not ready and harms no one; the Secret appearing makes it live; deleting it revokes the key"

leader() { k get lease limitplane-leader -o jsonpath='{.spec.holderIdentity}'; }
wait_for 20 "a leader" sh -c "[ -n \"\$(kubectl --context $CTX -n $NS get lease limitplane-leader -o jsonpath='{.spec.holderIdentity}')\" ]"
L=$(leader)
n=0
for p in $(pods); do
  if stats "$p" | grep -q '"leader":true'; then n=$((n + 1)); [ "$p" = "$L" ] || fail "$p thinks it leads, the Lease says $L"; fi
done
[ "$n" -eq 1 ] || fail "want exactly one leader, got $n"
pass "exactly one leader ($L), and the Lease agrees"

used() { k get tenant acme -o jsonpath='{.status.monthlyUsed}'; }
before=$(used); before=${before:-0}
for _ in $(seq 40); do curl -s -o /dev/null -H "X-Api-Key: demo-pro-key" "localhost:$(port "$L")/v1/ping"; done
for p in $(pods); do [ "$p" = "$L" ] || F=$p; done
for _ in $(seq 40); do curl -s -o /dev/null -H "X-Api-Key: demo-pro-key" "localhost:$(port "$F")/v1/ping"; done
grew() { [ "$(used)" -ge $((before + 80)) ]; }
wait_for 20 "monthlyUsed counts both replicas' traffic" grew
pass "monthly usage is shared: 40 requests on each replica moved the Tenant's monthlyUsed from $before to $(used)"

start=$(date +%s)
k delete pod "$L" --wait=false >/dev/null
# The old leader releases the Lease on SIGTERM; the survivor or the replacement pod, whichever
# tries first, takes it.
moved() { h=$(leader); [ -n "$h" ] && [ "$h" != "$L" ]; }
wait_for 30 "another replica takes the Lease" moved
took=$(($(date +%s) - start))
k rollout status deploy/limitplane --timeout 2m >/dev/null
forward
wait_for 30 "activeReplicas back to 2" is 2 k get rlp/default -o jsonpath='{.status.activeReplicas}'
all_limit 10 || fail "the replacement pod isn't serving the policy"
n=0
for p in $(pods); do stats "$p" | grep -q '"leader":true' && n=$((n + 1)); done
[ "$n" -eq 1 ] || fail "want exactly one leader after failover, got $n"
pass "deleting the leader's pod moved the Lease to $(leader) in ${took}s; still one leader, the replacement serves the policy"

k delete rlp default >/dev/null
sleep 3
all_limit 10 || fail "deleting the RateLimitPolicy dropped the live policy"
wait_for 20 "tenant PolicyNotFound" is PolicyNotFound cond tenant/acme Ready reason
pass "deleting the RateLimitPolicy keeps the current policy serving and marks Tenants PolicyNotFound"

k logs -l app.kubernetes.io/component=gateway --tail=-1 | grep -i forbidden && fail "RBAC errors in the logs"
pass "no RBAC errors in any replica's log"
echo "all operator checks passed"
