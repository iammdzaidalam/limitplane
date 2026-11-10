# Operator mode

With `--kube` (or `LIMITPLANE_KUBE=1`) LimitPlane reads its policy from Kubernetes instead of a file.
Every replica watches two CRDs and the Secrets they reference, and hot-swaps the same policy store that
file reload uses. One replica, picked by Lease leader election, writes status and Events.

No client-go: `internal/kube` is a small client built on `net/http` and `encoding/json`.

## Install

```bash
kubectl apply -f deploy/k8s/crds/
kubectl apply -n limitplane -f deploy/k8s/samples/   # a RateLimitPolicy, a Tenant and its key Secret
helm install limitplane deploy/helm/limitplane -n limitplane   # see docs/DEPLOY.md
```

| Flag / env | Default | Meaning |
|---|---|---|
| `--kube`, `LIMITPLANE_KUBE=1` | off | In-cluster mode. Token, CA and namespace come from `/var/run/secrets/kubernetes.io/serviceaccount`, the host from `KUBERNETES_SERVICE_HOST/PORT`. |
| `--kube-policy` | `default` | The RateLimitPolicy to apply. Others in the namespace get `Applied=False, reason=Ignored`. |
| `POD_NAME` | hostname | Identity for leader election (use the downward API). |
| `POD_UID` | unset | Optional. Lets the replica's heartbeat Lease be garbage collected with its pod. |

The pod's ServiceAccount needs this namespace Role:

| API group | Resources | Verbs |
|---|---|---|
| `limitplane.dev` | `ratelimitpolicies`, `tenants` | get, list, watch |
| `limitplane.dev` | `ratelimitpolicies/status`, `tenants/status` | get, update, patch |
| `""` | `secrets` | get, list, watch |
| `""` | `events` | create, patch |
| `coordination.k8s.io` | `leases` | get, list, watch, create, update |

## The resources

```yaml
apiVersion: limitplane.dev/v1alpha1
kind: RateLimitPolicy          # short name: rlp
metadata: {name: default}
spec:                          # the policy file format, minus keys
  tiers:
    free: {rate: {limit: 5,  period: 1s, burst: 10},  monthly: 10000}
    pro:  {rate: {limit: 50, period: 1s, burst: 100}, monthly: 1000000}
  routes:
    - {prefix: /v1/generate, cost: 5}
  anonymous: free
  autopilot: {stormBlocks: 20, stormWindow: 10s, banFor: 5m}   # optional; these are the defaults
---
apiVersion: limitplane.dev/v1alpha1
kind: Tenant
metadata: {name: acme}
spec:
  id: acme
  tier: pro
  org: acme                                     # optional: an org from the org directory (docs/ORGS.md)
  keySecretRef: {name: acme-key, key: apiKey}   # API keys live in Secrets, never in the CR
```

```
$ kubectl get rlp,tenants
NAME                                     APPLIED   REASON    REPLICAS   AGE
ratelimitpolicy.limitplane.dev/default   True      Valid     2          2m
ratelimitpolicy.limitplane.dev/staging   False     Ignored   0          1m

NAME                         ID     TIER   READY   REASON   USED   AGE
tenant.limitplane.dev/acme   acme   pro    True    Active   45     2m
```

| Status | Meaning |
|---|---|
| `Applied=True, Valid` | The policy is live. The message counts tiers, routes and tenants. |
| `Applied=False, Invalid` | The spec failed validation (same rules as the file). The message is the error. Replicas keep serving the last good policy. |
| `Applied=False, Ignored` | Not the policy named by `--kube-policy`. |
| `activeReplicas` | Replicas serving `observedGeneration`. It reads 0 while that generation is invalid. |
| `Ready=False` on a Tenant | `SecretNotFound`, `KeyNotFound`, `UnknownTier`, `DuplicateKey`, `InvalidSpec`, `PolicyInvalid` or `PolicyNotFound`. A bad Tenant is left out; it never blocks the policy. |
| `monthlyUsed` | Best effort, read by the leader. It is shared only with the Redis backend; in memory each replica counts its own traffic. |

Events, from the leader only: `PolicyApplied`, `PolicyInvalid` (on the policy), `QuotaAlert` at 80% of a
monthly cap (on the Tenant) and `TenantBanned` when a client is banned (on the policy, because bans
are per client address, not per Tenant).

`/api/stats` reports `kube` and `leader`.

## How it works

**Caches** (`watch.go`). For each resource: list, then watch from the list's `resourceVersion`. When the
stream ends (the server times watches out every few minutes) the watch resumes from the last version
seen, so nothing is missed and nothing is listed again. If that version has been compacted away the
server answers `410 Gone`, as an HTTP status or as an `ERROR` event in the stream; then the only safe
move is a fresh list, which replaces the cache wholesale, so deletes missed in the gap disappear.

**Reconcile** (`reconcile.go`). It is level-triggered: any change to any watched object rebuilds the
whole policy from the caches, merges each usable Tenant's key from its Secret, and runs it through
`policy.Parse`, the same decoder and validation as the file. A valid result is swapped in atomically,
and only when it differs from the live config. Because it compares with the live store, a
`PUT /api/policy` from the dashboard is undone on the next pass: in kube mode the CR is the source of
truth. A 5s resync refreshes status and the heartbeat.

Status is merge-patched only when it differs from what is stored, so the watch event our own write
causes ends in a no-op. Events go out only when a condition changes, so a new leader that finds status
up to date stays quiet.

**Leader election** (`lease.go`). Lease `limitplane-leader`: 15s duration, a try every 5s.

- No lease: create it. Two candidates racing to create: one gets `409 Conflict` and stays follower.
- We hold it: renew `renewTime`.
- Someone else holds it: take over only if the Lease has not changed for 15s **by our own clock**
  (we note when its `resourceVersion` last changed), so clock skew between nodes doesn't matter.
- Every write carries the `resourceVersion` we read, so two candidates can't both take over: the
  second PUT gets `409 Conflict`.
- The leader stops acting as leader 10s after its last successful renew (duration minus one retry),
  before anyone else may take over, so two replicas never both believe they lead.
- On SIGTERM the leader clears `holderIdentity`, so the next candidate takes over on its next try
  instead of waiting 15s.

**activeReplicas.** Each replica keeps its own Lease, `limitplane-replica-<pod>`, labelled
`limitplane.dev/replica=true` and annotated with the policy generation it serves, renewed every 5s.
The leader counts the fresh ones. With `POD_UID` set, the Lease is owned by the pod and is deleted with it.

**Fallback budget.** Every replica also counts the fresh heartbeat Leases (any generation) on each resync.
If Redis goes down, each replica limits locally on 1/n of every rate and burst, so n replicas together
still admit about one budget instead of n. The count is taken while Redis is still up, from the API
server, which doesn't depend on Redis.

## Behaviour to know

- At startup the server waits for the first sync (up to 20s) before listening, so the first requests
  already see the CRD policy. Until then, or if the named policy doesn't exist, it serves the startup
  policy (`--config`, or the built-in demo policy). File watching and SIGHUP are off in kube mode.
- Deleting the RateLimitPolicy keeps the last applied policy rather than dropping to defaults.
- `spec.autopilot` (`stormBlocks`, `stormWindow`, `banFor`) is applied to every replica's autopilot when
  it changes. Absent fields keep the defaults (20 blocks in 10s, ban for 5m); `stormBlocks: 0` turns
  storm bans off. A value autopilot can't use (a zero window or ban with blocks set) makes the policy
  `Applied=False, Invalid`, like any other spec error, and the last good rules stay.
- `spec.org` places the tenant in that org: its members see it in the dashboard, and it spends from
  the org's shared monthly budget. An invalid id is `InvalidSpec`, the same `spec.id` in two orgs is
  `OrgConflict`. Orgs themselves (members, budgets) live in the org directory, not in a CRD; see
  [ORGS.md](ORGS.md#kubernetes).
- Bans themselves are shared through Redis, so a ban decided on any replica holds on all of them. The
  `TenantBanned` and `QuotaAlert` Events come through `server.Config.OnBan`/`OnAlert` hooks on the
  replica that decided them, and only the leader sends Events, so a ban decided on a follower has no
  Event. They are best effort.

## Proof on a real cluster

`make prove-operator` (needs docker, kind, kubectl and helm) creates a kind cluster, installs the
Helm chart with `operator.enabled=true` and two replicas, and checks, through a port-forward to each
pod:

- both replicas run in kube mode as the chart's ServiceAccount, and no log line says `forbidden`;
- the sample RateLimitPolicy and Tenant reach both replicas (`Applied=True`, `activeReplicas=2`), and
  editing the CR changes both replicas' limits without a restart;
- the API server's CRD schema refuses `limit: 0` on its own; a burst below a route's cost passes the
  schema and is refused by the operator (`Applied=False, Invalid`, a `PolicyInvalid` Event) while the
  last good policy keeps serving;
- a Tenant whose Secret doesn't exist is `SecretNotFound` and harms no one, goes live when the Secret
  appears, and deleting it revokes the key;
- exactly one replica leads and the Lease agrees; deleting its pod moves the Lease (in about a second,
  since the old leader releases it on SIGTERM) and there is still one leader;
- 40 requests on each replica raise the Tenant's `monthlyUsed` by 80 (shared through Redis);
- deleting the RateLimitPolicy keeps the current policy and marks Tenants `PolicyNotFound`.

```
PASS: chart installed: CRDs, RBAC, Redis and 2 replicas with --kube
PASS: both replicas in kube mode, serving the bootstrap policy until a RateLimitPolicy exists
PASS: RateLimitPolicy and Tenant (key from a Secret) live on both replicas; Applied=True, activeReplicas=2
PASS: editing the CR changes both replicas' limits without a restart
PASS: the API server's CRD schema refuses limit 0 before it reaches the operator
  message: policy: tier "free": burst 3 < max route cost 5
PASS: an invalid policy is refused (Applied=False Invalid, PolicyInvalid event) and the last good one keeps serving
PASS: a Tenant without its Secret is not ready and harms no one; the Secret appearing makes it live; deleting it revokes the key
PASS: exactly one leader (limitplane-744556fd8d-s4f5h), and the Lease agrees
PASS: monthly usage is shared: 40 requests on each replica moved the Tenant's monthlyUsed from 9 to 89
PASS: deleting the leader's pod moved the Lease to limitplane-744556fd8d-vm2c7 in 1s; still one leader, the replacement serves the policy
PASS: deleting the RateLimitPolicy keeps the current policy serving and marks Tenants PolicyNotFound
PASS: no RBAC errors in any replica's log
all operator checks passed
```

It takes about 75s on a laptop once the kind node image is cached, and runs in CI on every push.
The unit tests in `internal/kube` use an in-memory API server instead, for the cases a real cluster
won't produce on demand: `410 Gone` mid-watch, update conflicts, two candidates racing for the Lease.
`KEEP=1` leaves the cluster up to poke at.

## Debugging

```bash
kubectl get lease limitplane-leader -o jsonpath='{.spec}'   # who leads, and how often it changed
kubectl get lease -l limitplane.dev/replica=true            # live replicas
kubectl describe rlp default                                 # conditions and Events
kubectl logs deploy/limitplane | grep kube:
```
