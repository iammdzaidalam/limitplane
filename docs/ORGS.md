# Organisations, users and roles

LimitPlane can be shared by several teams or customers. Each one gets an org, its members sign in
with an email and password, and they see only their own tenants. An org can also have a shared
monthly budget across all its tenants. The budget is checked in the same round trip as everything
else.

```
platform admin   the admin key (break glass), or users with the superadmin role
  └── org        "acme": optional shared monthly budget
        ├── members   email + password, role owner / admin / viewer
        └── tenants   each in at most one org; their own tier, keys and monthly quota as before
```

## Roles

| | viewer | admin | owner | superadmin |
|---|:-:|:-:|:-:|:-:|
| Read its org's tenants, decisions, audit, live events, clients, bans that affect them, dashboard totals | ✓ | ✓ | ✓ | every org |
| Read tiers and routes (`GET /api/policy` without API keys) | ✓ | ✓ | ✓ | with keys |
| Create and delete tenants, create and revoke API keys, in its org | | ✓ | ✓ | any org |
| Add, remove and re-role members, revoke their sessions, set the org budget | | | ✓ | any org |
| Create and delete orgs, move tenants between orgs, platform users | | | | ✓ |
| Ban and unban clients, edit the policy | | | | ✓ |

Bans and the policy are platform-wide on purpose. A ban is per client IP and holds for every tenant,
so an org admin who banned an address would also block it for every other org (a shared NAT, a
CDN). Tiers and routes price everyone's traffic. Org members see the bans that cover their own
clients, and they see tiers and routes.

The server enforces every rule. The dashboard hides what a role can't do, but that is only for
convenience. Requests about another org's resources get **404**, the same answer as for something
that doesn't exist, so ids don't leak between orgs. A member whose role is too low gets **403**, and
so does anyone but the superadmin on a platform-wide route. `TestAuthorizationMatrix`
(`internal/server/authz_test.go`) sends every admin endpoint as every role, from inside and outside
the org (38 routes × 9 callers). `TestScopedReads` checks what each role gets back.

## Signing in

- **Admin key.** `{"key": ...}`, as before. It is the break-glass superadmin and can't be locked
  out by the per-account limit. Its tokens stay valid until the key is rotated, because the signing
  secret is derived from it.
- **Email and password.** `{"email": ..., "password": ...}`.
- **Accounts are invite-only by default.** An owner adds members (`POST /api/orgs/{org}/members`),
  and the superadmin creates orgs and their first owner. If the inviter leaves the password out, a
  random one is generated and returned once. `--signup` (`LIMITPLANE_SIGNUP=1`, Helm
  `orgs.signup`) turns on `POST /api/signup`, which creates an org and makes the caller its owner.
  `GET /api/login` tells the dashboard whether sign-up is on.

### Passwords

- PBKDF2-HMAC-SHA256 from the standard library (`crypto/pbkdf2`, Go 1.24+), 600,000 iterations
  (OWASP's 2023 figure), a 16-byte random salt per user and a 32-byte key. That is about 0.1 to 0.2 s
  per check on one core.
- The record is `pbkdf2-sha256$<iterations>$<salt>$<key>`, so raising the count later doesn't break
  existing hashes.
- The comparison is constant time (`subtle.ConstantTimeCompare`).
- An unknown email is checked against a dummy hash, so it takes as long as a wrong password and the
  timing doesn't reveal which emails have accounts.
- Passwords must be 10 to 256 characters. The upper bound caps the hashing work one request can ask for.

PBKDF2 is not memory-hard. Argon2id or scrypt would make a GPU attack on a stolen directory
costlier, but neither is in the standard library, and the root module takes no dependencies. PBKDF2
is FIPS-approved, and at this iteration count it is the recommended stdlib-only choice.

### Login limits

Both limits run through LimitPlane's own limiter (`Limits.Allow`). With Redis they are shared, so
adding replicas doesn't add guesses.

| Bucket | Rate | Why |
|---|---|---|
| `login:<client ip>` | 5 per minute | as before: one address can't guess quickly |
| `login-account:<email>` | 10 per 10 minutes | a guesser spread over many addresses still gets about one try a minute per account |

The per-account bucket lets someone keep a known user locked out for a few minutes by spamming bad
passwords. That is the usual trade-off, and it is why this bucket is looser than the IP one. The
admin key isn't subject to it.

### Sessions and revocation

A token is an HS256 JWT carrying `sub` (the user id), `org`, `role` and `ver`, the user's session
version. On every request the auth middleware looks the user up in the in-memory directory: one
lock-free map read. It rejects the token if the user is gone, or if their version, org or role no
longer match.

Tokens are signed with a secret derived from the admin key, so replicas must share `--admin-key`
(the Helm chart does), and rotating the key signs everyone out.

These bump the version, which kills every token issued before:

- `POST /api/me/revoke`, which signs you out everywhere;
- `POST /api/orgs/{org}/members/{user}/revoke`, an owner ending a member's sessions;
- a role change, because the old tokens carry the old role;
- a password change, which returns a new token for the session that made it.

Deleting a user or their org kills their tokens too. Every replica holds the directory in memory, so
a revocation applies wherever the change has arrived: a pub/sub message, about 1 ms after the
commit, or the version check every 2 s if that message is lost. `scripts/prove-orgs.sh` measures
the time from a revoke on one replica to a 401 on the other; it was 16 ms, including curl. An open
SSE stream checks the session at every heartbeat (15 s) and closes when it is revoked.

## What each role sees

All reads are scoped by one function: `visible(r) func(tenant) bool` in `internal/server/scope.go`.
It is true for every tenant for the superadmin. For anyone else it is true only for tenants whose
org is the caller's.

| Endpoint | Scoped to |
|---|---|
| `GET /api/stats` | the org's tenants and quotas. Totals, the 120 s series and block reasons are counted per org (each decision carries its tenant's `org`). The org's budget and spend are under `org`. |
| `GET /api/audit`, `GET /api/events` (SSE) | decisions and alerts for the org's tenants. Ban events only when the ban covers one of the org's clients. |
| `GET /api/clients` | clients that sent the org's tenants traffic in the last 15 minutes |
| `GET /api/bans` | bans (IP or CIDR) that cover one of those clients |
| `GET /api/tenants`, `GET /api/orgs` | the org's own |

**Org switcher.** The superadmin adds `?org=<id>` to any of these and sees exactly what the org's
members see (it also works on the SSE URL). Members can't switch: the parameter is ignored for them.
The anonymous tenant belongs to no org, so only the unscoped superadmin view shows it.

`/metrics` is unchanged: it is for scrapers, guarded by `--metrics-key`, and not per role.

## API keys from the dashboard

An admin creates a tenant in their org (`POST /api/tenants {"id", "tier"}`), then keys for it
(`POST /api/tenants/{id}/keys`).

- A key is `lp_` plus 32 random base64url characters (24 bytes). The response holds it, and only that
  response does.
- The directory stores its SHA-256 (hex), a 9-character prefix to tell keys apart in the list, and
  the tenant. Listings show the prefix only.
- One fast hash is enough because a key has 192 bits of entropy: nobody can brute-force it. A slow
  hash would add its cost to every request.
- **Every replica resolves it.** The directory's change reaches each replica's policy store, which
  keeps `sha256 -> tenant` next to the plaintext policy keys. A request looks up the policy keys
  first, then the hash map (only when it isn't empty). The hash is computed into a stack buffer, so
  it allocates nothing.
- Revoking a key (`DELETE /api/tenants/{id}/keys/{key}`) takes effect wherever the change has
  arrived. The key then resolves as anonymous.

Tenants defined by the policy file or a Tenant CR keep their keys there. The API refuses (409) to add
keys to them or delete them. The superadmin can still place them in an org.

## The org budget

`PATCH /api/orgs/{org} {"budget": 50000}` (owner). 0 removes the budget.

- A request is allowed only if the tenant's monthly quota, the org's budget **and** the burst all
  pass. Nothing is spent otherwise.
- When several checks fail, the order is tenant monthly, then org budget, then burst, so the
  stickiest answer wins.
- A budget reject is `429` with `reason: "org_monthly"` and the same semantics as `monthly`:
  `RateLimit-Limit` is the budget, `RateLimit-Remaining` what is left of it, and `Retry-After` and
  `RateLimit-Reset` run to the 1st (UTC). The JSON body says which org.
- **An org's spend is counted whether or not it has a budget.** So a budget set on the 20th covers
  the whole month, and an owner can't grant a fresh allowance by removing the budget and setting it
  again.
- The spend of tenants from before they joined the org isn't billed to it.

### One round trip, one slot

On Redis the whole decision is one Lua script that touches one Cluster slot. That works because a
tenant in an org keeps its keys under the **org's** hash tag:

| Tenant | Burst | Monthly | Org budget |
|---|---|---|---|
| no org (unchanged) | `lp:{acme}:r` | `lp:{acme}:q:2026-11` | none |
| in org `corp` | `lp:{org:corp}:t:acme:r` | `lp:{org:corp}:t:acme:q:2026-11` | `lp:{org:corp}:budget:2026-11` |

The script reads Redis `TIME`, checks the monthly quota, then the org's spend against the budget,
then GCRA, and only if all pass writes the tat and `INCRBY`s both counters (35-day expiry). It is the
same round trip as before; an org tenant adds one `GET` and one `INCRBY` inside it. Different orgs
spread over the masters as tenants did, but all of one org's tenants share a slot. A very hot org is
therefore one hot slot, the price of checking its budget atomically. Tenants without an org don't
change at all.

The keys can't collide. A tenant's own keys end in `:r` or `:q:<month>` right after its tag, so
none of them can equal `...:budget:<month>` or `...:t:...`. Org ids are slugs (`[a-z0-9-]`, 1-40),
and a tenant in an org can't have `{` or `}` in its id (validated), so no id can shift a tag.

### Moving between orgs

Where a tenant's counters live depends on its org, so changing the org moves them. The policy
store notices any change of a tenant's org, from the dashboard, the policy file or a Tenant CR, and
calls `Limits.Move`:

1. On the old slot, one script takes the current month's spend (`GET`, then `DEL`).
2. On the new slot, a second script `INCRBY`s it.

These have to be two scripts, because the slots differ. Every replica runs the move when it hears of
the change. Since the take empties the old key, a second run only carries over what replicas that
hadn't heard yet spent there in the meantime, so the repeats are useful rather than double-counted.
The burst tat is left to expire (at worst one extra burst). The org's own counter doesn't change:
spend from before the tenant joined isn't billed to the new org. What can slip is a request that a
replica still on the old layout decides after every move has run. That window is the pub/sub delay,
or at most the 2 s sync if a message is lost.

### Memory and fallback

The in-process limiter does the same thing under one lock: a tenant in an org lives in the org's
shard, next to the org's spend (the in-memory version of a hash tag). It is zero-alloc with or
without an org (`TestCheckAllocs`).

While Redis is down, the fallback gives each replica 1/n of the burst, as before, and now also 1/n of
the monthly quota and of the org budget, never less than the request's cost. The local counters start
from zero, so an outage can admit about one extra month of each cap across the fleet, not n months.

## Where the directory lives

Every replica reads an immutable in-memory snapshot of the directory. Writes check their
invariants against it in Go: an email is unique, an org always keeps an owner, a tenant is in one org
at most. Then they commit with a version check (optimistic concurrency): if anyone committed since
the snapshot was read, the write reloads and tries again. Two replicas therefore can't both remove
the last two owners or both claim one email (`TestRedisReplicas`). One code path serves both
backends.

| Mode | Storage |
|---|---|
| `--redis` | Four hashes under one hash tag, plus a version: `lp:{dir}:orgs`, `lp:{dir}:users`, `lp:{dir}:tenants`, `lp:{dir}:keys` (id → JSON), `lp:{dir}:v`. A commit is one script: compare the version, `HSET`/`HDEL`, `INCR` the version, `PUBLISH lp:dir <version>`. Replicas reload on the message, and also check the version every 2 s and after every resubscribe (the same pattern as bans). |
| `--data-dir DIR`, no Redis | `DIR/orgs.json`, written whole on each change: temp file in the same directory, fsync, rename, fsync the directory. A crash leaves the old file or the new one, never half of one. The file is mode 0600, since it holds password hashes. A corrupt file stops startup instead of being silently replaced by an empty directory. One process only. |
| neither | in memory; a log line says so |

Writes are rare (people clicking in a dashboard), and reads happen on every admin request, so the
whole directory is reloaded on each change instead of patching it record by record. That is fine
for thousands of users. At millions it would want per-record invalidation.

A tenant's org can come from three places. If the policy file (`"keys": {"k": {"id": "acme", "tier": "pro", "org": "corp"}}`)
or a Tenant CR names one, that wins, and the API refuses to move the tenant (409). Otherwise the
directory places it.

## Kubernetes

`Tenant` has an optional `spec.org` (an org id, validated by the CRD pattern), shown in an `Org`
printer column. Readiness checks it too:

- an invalid org id is `InvalidSpec`;
- two Tenants with the same `spec.id` in different orgs: the second gets `OrgConflict`.

Neither blocks the rest of the policy.

There is **no `Org` CRD**. An org's members are users with password hashes, and those don't belong in
etcd, where anyone with read access to the namespace's custom resources could take them. Splitting an
org between a CR (its budget) and Redis (its members) would leave two sources of truth for one
thing. So orgs, users, budgets and dashboard keys stay in the directory (Redis) in `--kube` mode too.
Tenants declared as CRs join an org through `spec.org`, and those created in the dashboard live in
the directory like any others.

## API

| Method and path | Who |
|---|---|
| `GET /api/login`, `POST /api/login`, `POST /api/signup` | anyone (sign-up only with `--signup`) |
| `GET /api/me`, `PUT /api/me/password`, `POST /api/me/revoke` | any user |
| `GET /api/orgs`, `GET /api/orgs/{org}` | members (their org), superadmin |
| `POST /api/orgs`, `DELETE /api/orgs/{org}` | superadmin (delete refuses while the org has tenants) |
| `PATCH /api/orgs/{org}` `{"name", "budget"}` | owner |
| `GET/POST /api/orgs/{org}/members`, `PATCH/DELETE .../members/{user}`, `POST .../members/{user}/revoke` | owner (an org keeps at least one owner) |
| `GET/POST /api/users`, `DELETE /api/users/{user}` | superadmin (platform users) |
| `GET /api/tenants` | members (their org) |
| `POST /api/tenants`, `DELETE /api/tenants/{id}`, `POST /api/tenants/{id}/keys`, `DELETE /api/tenants/{id}/keys/{key}` | admin |
| `PUT /api/tenants/{id}/org` `{"org"}` | superadmin |

## Prove it

```bash
./scripts/prove-orgs.sh   # Redis + two replicas in Docker; tears down after
```

It creates two orgs, each with an owner and a viewer, and tenants with keys, all over the API and
spread across both replicas. Then it shows:

- cross-org isolation: scoped lists, 404 across orgs, 403 for a viewer's writes;
- one budget of 30 shared by two tenants and enforced across both replicas, with
  `reason: org_monthly`, `RateLimit-Limit: 30`, `RateLimit-Remaining: 0` and a Retry-After to the
  1st, while the other org is unaffected;
- a token revoked on one replica rejected by the other.

## Not covered

- SSO (OIDC, SAML), MFA, and password reset by email (there is no mail delivery). An owner sets a new
  password by removing the member and inviting them again.
- A user in more than one org. Each user has exactly one, which keeps the token and the scoping
  simple. Platform staff are superadmin users with no org.
- A log of admin actions (who changed what).
- Per-org Prometheus labels: `/metrics` stays per tenant.
