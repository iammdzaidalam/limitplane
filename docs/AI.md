# AI: explanations, incident memory and ops chat

Three things, all in `internal/ai`, all useful with no model at all:

- **Explain**: why was this decision, client or tenant blocked, and what to do about it.
- **Incident memory**: bans, block storms, quota alerts, degraded windows and policy reloads,
  kept as short documents and searched with BM25.
- **Ask**: "what happened to acme last night?" answered from that memory plus live state, with
  citations.

Rules write every answer. A model, when one is configured, only rewrites the rule-based answer
from a numbered list of facts, and its text is thrown away unless it passes the checks below. If
the model is slow, down, over budget or wrong, the dashboard shows the rule-based answer and a
one-line reason.

## Turning a model on

| Flag / env | Meaning |
|---|---|
| `--ai` / `LIMITPLANE_AI` | `auto` (default), `anthropic`, `openai` or `off`. |
| `ANTHROPIC_API_KEY` | With `auto`, uses the Anthropic Messages API. Default model `claude-haiku-5-5`, effort `low`. |
| `--ai-base-url` / `LIMITPLANE_AI_BASE_URL` | An OpenAI-compatible API. With `auto` this wins over the Anthropic key, since it is the more explicit choice. |
| `LIMITPLANE_AI_KEY` | Bearer key for that API. Leave it empty for a local Ollama. |
| `--ai-model` / `LIMITPLANE_AI_MODEL` | Model id. Required for `openai`. |
| `--ai-share-ips` | Send raw client IPs to the model. Off by default. |
| `--ai-calls-per-hour` / `LIMITPLANE_AI_CALLS_PER_HOUR` | Model calls allowed per hour, 60 by default, in bursts of up to 10. |

Keys are read from the environment only, never from flags, so they don't show up in `ps`.

```bash
ANTHROPIC_API_KEY=sk-ant-... limitplane
limitplane --ai-base-url https://api.groq.com/openai/v1 --ai-model llama-3.3-70b-versatile   # LIMITPLANE_AI_KEY=gsk_...
limitplane --ai-base-url http://localhost:11434/v1 --ai-model llama3.2                     # Ollama, no key
```

The Anthropic client is about 60 lines of `net/http` against `POST /v1/messages` with
`anthropic-version: 2026-10-21`. The root module is standard library only, so there's no SDK. It
reads `text` blocks by type, because a response can open with a `thinking` block. It sends no
`temperature`, which that API version rejects. A `refusal` or `max_tokens` stop counts as a
failure, because a cut-off answer can end mid-citation. `max_tokens` is 2048 although answers are a
few sentences: thinking counts toward it, and a tighter cap would cut answers off. The system prompt is far below the
minimum cacheable prefix, so it doesn't ask for prompt caching.

## What a model may see

The model gets the same facts the operator sees, as `F1: ...` lines, and nothing else:

- **Never sent**: API keys (only tenant ids are ever written into facts), request bodies and
  headers (the gateway never records them), query strings (decisions keep only the path).
- **IPs are hashed** unless `--ai-share-ips` is set. Every IP or CIDR in a fact or question becomes
  `ip-` plus 8 hex digits of HMAC-SHA256 under a random key made at process start. Within one
  prompt a client keeps one name, so the model can still say "the same client". Without the key
  the hash can't be reversed, not even by hashing all 2^32 IPv4 addresses. The answer's tokens are
  swapped back to real addresses before the dashboard sees them.
- **Paths are sent as they are.** If your paths carry identifiers you consider sensitive, run with
  `--ai off` or put a route prefix in front of them.

## Checking the model's answer

`grounded` in `ai.go` drops the model's text unless:

1. It cites at least one fact, like `[F2]` or `[M4, F1]`.
2. Every bracket holds only IDs that were in the prompt. `[F9]`, `[see above]` and `[]` all fail.
3. Every number of 10 or more appears in some fact. "480 requests" fails when no fact says 480.
   Single digits and `429` pass, since they turn up in ordinary phrasing.
4. It is under 1,200 characters.

A dropped answer counts as `limitplane_ai_fallbacks_total{reason="invalid"}`.

## Cost and load

- **Endpoint limit**: `/api/ai/explain`, `/api/ai/chat` and `/api/ai/incidents` share the
  gateway's own limiter at 120 a minute (bursts of 30, key `ai:api`). Past that they return 429
  with `Retry-After`. With Redis behind the gateway, the budget is fleet-wide.
- **Model budget**: every model call first spends one unit from the same limiter (key `ai:model`,
  `--ai-calls-per-hour`). When that is empty the answer is rules only (`reason="limited"`). On
  Claude Haiku 5.5 ($0.10 / $0.50 per million tokens) a call sends under 2,000 tokens and may
  produce at most 1,024 (thinking included), so the default 60 calls an hour cost at most about
  4¢ an hour.
- **In flight**: at most 4 model calls at once. Past that a call fails fast (`reason="busy"`)
  instead of queueing, because a queued call would only use up its timeout waiting.
- **Timeouts and size**: 10 s per call. Reading stops at 256 KiB, and a longer reply is refused.

`/metrics` adds:

```
limitplane_ai_tokens_total{dir="in"|"out"}
limitplane_ai_requests_total
limitplane_ai_errors_total
limitplane_ai_fallbacks_total{reason="limited"|"busy"|"timeout"|"error"|"invalid"}
limitplane_ai_memory_docs
```

Rules-only answers given while no model is configured are not counted as fallbacks.

## Explain

`POST /api/ai/explain` takes exactly one of `{"decision": {...}}`, `{"client": "203.0.113.7"}` or
`{"tenant": "acme"}`. A posted decision only says which one: the audit ring's copy is used when it
is still there. The explainer gathers facts from the audit ring, the policy (tier, rate, burst,
lanes, the route that priced the path), monthly usage, bans (exact or covering CIDR), the
autopilot's label for the client, whether the backend is degraded, and, for a tenant in an org
with a budget, the org's spend against it. It then reads the client's last minute of decisions for timing:

| Finding | Evidence |
|---|---|
| Retry loop | autopilot label `retry_bug`, or most of its last 429s answered before half the Retry-After |
| Scripted traffic | gaps between requests vary by under 30% |
| Crawler / human | autopilot label |
| Expensive route | one burst fits fewer than 4 calls of this route |
| Storm ban | ban reason `storm`, with the storm rule as a fact |
| Monthly quota | usage, reset date, and, for tenants, the projected run-out date at this month's pace |
| Org budget | a block with reason `org_monthly`: the org's spend and budget, and that every tenant in it waits for the 1st |
| Degraded | the decision came from the local fallback |

Each finding and action lists the fact IDs it rests on, so the dashboard can show where every
claim comes from.

## Incident memory

What gets remembered, each as a small document:

| Kind | When | Tenant |
|---|---|---|
| `ban` | any ban (autopilot storm or manual), with a note | the client's last tenant |
| `quota` | the autopilot's 80% alert, with run-out date | the tenant |
| `storm` | a tenant has 100+ blocked requests in one minute, at most once per 10 minutes | the tenant |
| `degraded` | a window of local-fallback decisions, written once it has been quiet for 15 s | fleet-wide |
| `policy` | tiers, routes or keys reloaded: one fleet-wide summary; and one per tenant added, removed or moved, in the policy or the org directory | as stated |

Memory keeps the newest 2,000 documents. With `--redis` they are also pushed to one list,
`lp:{ai}:memory`, trimmed to the same cap. Writes go through a buffered channel off the hub
goroutine and are dropped if Redis is slow. Each replica loads the list once at start, so after a
restart it remembers the fleet's history, while it runs it adds only what it saw itself. That keeps
persistence to two cheap commands per incident. A shared, live index would need a search service.

**Why BM25 and not TF-IDF cosine.** These documents are short and repetitive, and the questions
are a few words. BM25 caps how much a repeated word can add (k1 = 1.2), so a doc that says
"blocked" five times doesn't beat one that names the tenant you asked about. It also normalizes
for length (b = 0.75), so short incidents compete fairly with long ones. Cosine over TF-IDF has
neither control: it rewards whichever doc is mostly made of the query word. Since memory holds
only a few thousand docs, a query scans all of them, which takes microseconds and needs no posting
lists to keep consistent as old docs are evicted.

Tokens keep compounds whole and split them too: `203.0.113.7`, `acme-corp`, `/v1/generate` match
exactly and by their parts. A small stemmer treats `bans` / `banned` / `banning` as the same word,
and a few ops synonyms map onto the doc wording (`outage` → degraded, `cap` → quota).

**Time phrases** are read before searching, in the asker's time zone (the dashboard sends it):
`last night` (18:00 to 08:00), `yesterday`, `today`, `this morning`, `this afternoon`,
`this evening`, `last hour`, `last N minutes|hours|days`, `this week`, `last week`. A question that
is only a time phrase lists that window, newest first.

**Scope.** Every search takes `Visible func(tenant string) bool`. Docs the caller can't see are
removed before scoring, and term statistics are computed over the visible docs only, so even a
score can't show that another org had a similar incident. Fleet-wide docs have tenant `""`, and
the scoping function decides who sees them.

## Ask

`POST /api/ai/chat {"question": "...", "tz": "60"}` (`tz` is minutes east of UTC). The answer is:

- **Live state** for any tenant the question names that the caller can see, as a tenant
  explanation.
- **Matching incidents**, best first, each cited `[M12]`.
- Optionally the model's answer to the question, grounded on those incidents and live facts.

`GET /api/ai/incidents?q=` returns the raw hits; `GET /api/ai/status` says which model (if any)
is in use and whether IPs are shared.

## Who sees what

The AI endpoints are scoped like every other read (see [ORGS.md](ORGS.md)). The platform admin sees
everything, or one org with `?org=`. An org member:

- explains only decisions and tenants of its own org, and clients that sent its tenants traffic
  lately. Anything else is 404, the same as something that doesn't exist;
- gets explanations built from its own org's decisions and the bans that cover its clients, so
  another org's traffic never becomes a fact, and so never reaches a model either;
- searches and is told about only incidents that name one of its tenants. Fleet-wide incidents
  (degraded windows, policy summaries) are the platform admin's, and so is the fleet's incident
  count in `/api/ai/status`;
- receives `incident` and `note` SSE events only for its own tenants.

Each caller has its own allowance on the AI endpoints (120 a minute, bursts of 30), so one org's
dashboard can't use up another's. The model budget (`--ai-calls-per-hour`) is one for the fleet:
it caps what the operator pays.

## Autopilot notes

When the autopilot bans a client or raises a quota alert, the incident gets its rule-based note
at once. An `incident` SSE event, published next to `ban` or `alert`, carries it. It is a separate
event because a ban reaches every org whose clients it covers, while the note names one tenant,
so `incident` is scoped by that tenant. With a model, a worker pool rewrites the note off the
request path. When the rewrite passes the checks, it replaces the
note in memory and goes out as an SSE `note` event. Citation marks are removed first, because the
facts they point to aren't stored. The incident is persisted once its note is final, so the stored
copy has the better note.
