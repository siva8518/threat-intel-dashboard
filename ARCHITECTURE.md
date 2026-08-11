# Architecture

This document is a technical reference for reviewers (human or AI) who need to understand how the
platform is built without reading all ~300 source files first. For feature-by-feature narrative detail
and the reasoning behind specific decisions, see `README.md` — this file stays at the structural level.

## 1. Overall architecture

A single-page React frontend talks exclusively to one Express backend process over a small, versionless
JSON REST API (`/api/dashboard/*`, `/api/investigate*`, `/api/chat*`). The backend is a **stateful
aggregation service**, not a thin proxy: it owns scheduling, in-memory caching, retries, and
cross-source correlation for ~30 external threat-intelligence sources, so every browser tab reads
already-normalized, already-correlated data instead of each client independently hammering upstream
APIs.

```
Browser (React SPA)
   │  fetch, same-origin in prod / Vite proxy in dev
   ▼
Express backend (single Node process)
   ├── Scheduler — runs every "connector" once at boot, then on its own interval forever
   ├── In-memory cache — { [sourceId]: { data, updatedAt, error, isSyncing } }
   ├── On-demand lookups — live, per-query calls (not scheduled), used by the Triage/Investigation Console
   ├── Correlation layer — joins/dedupes across sources, computes derived metrics
   ├── Background extraction jobs — LLM-assisted entity extraction from ingested news text
   ├── AI layer — provider-failover router for cloud LLM calls + a separate local-only RAG chatbot
   └── Disk-backed JSON stores — server/.cache/*.json (see §4)
```

There is no reverse proxy, no API gateway, and no message queue. In production the same Express process
also serves the built frontend (`dist/`) as static files, so the whole application is one deployable
unit (see the `Dockerfile`).

## 2. Technology stack

| Layer | Choice | Notes |
|---|---|---|
| Frontend framework | React 18 + TypeScript, built with Vite | No SSR/meta-framework — plain SPA |
| Data fetching / cache | TanStack Query (`@tanstack/react-query`) | All server state; no separate Redux/Zustand store |
| Styling | Tailwind CSS + a small hand-rolled component set (`src/components/ui/`) | No component library (no MUI/Radix/shadcn dependency, though the style is shadcn-influenced) |
| Charts | Recharts | Bar/line/area charts throughout Overview and per-tab widgets |
| Maps | `react-simple-maps` + `world-atlas` topojson | World threat map (Overview) |
| Command palette | `cmdk` | Topbar search / jump-to |
| Backend runtime | Node.js (ESM, `"type": "module"`), Express 4 | No framework beyond Express itself |
| Scheduling | Custom (`server/scheduler.js`), no cron library | Interval-based, per-connector |
| Persistence | Flat JSON files on disk (`server/.cache/*.json`), no database | See §4 |
| AI (cloud) | Provider-failover router — Gemini `gemini-flash-latest`, Mistral `mistral-small-latest`, Groq `llama-3.3-70b-versatile`, Cohere `command-r-08-2024` | See §7 |
| AI (local) | Ollama (`llama3.1:8b` + `nomic-embed-text`), fully local | Powers the RAG chatbot only |
| MCP | `@modelcontextprotocol/sdk` | Exposes the same data as MCP tools for external MCP clients |
| Deployment targets | Docker image (any host), tested live on DigitalOcean App Platform; `fly.toml` present for Fly.io | No IaC/Terraform |

## 3. Frontend design

- **Shell**: `src/pages/DashboardPage.tsx` owns a flat list of ~17 tabs (`TABS` array) and renders exactly
  one tab's top-level component at a time based on local `useState` — no router library, no URL-based
  routing. Two global overlay components (`CveDetailDrawer`, `MalwareDetailDrawer`) are always mounted
  and driven by `SelectionContext` (React Context), so any tab can open a CVE/malware detail view without
  prop-drilling a callback through every layer.
- **Layout**: `src/components/layout/` — `Topbar.tsx` (brand, search, source-health dot, refresh),
  `DashboardLayout.tsx` (sidebar nav + content area).
- **Feature components**: `src/components/dashboard/`, one file per tab/widget (e.g.
  `MalwareIntelligence.tsx`, `AiSummarization.tsx`, `IntelligenceInvestigationConsole.tsx`). Shared
  presentational primitives (`Section`, `KeyValueBlock`, `FieldList`, `GroupedLists`) live in
  `reportPrimitives.tsx` and are reused across every AI-report-shaped view instead of each tab reinventing
  its own layout.
- **Data access**: `src/api/dashboardApi.ts` is the single typed HTTP client (thin `fetch` wrappers with
  timeout/error normalization via `src/lib/http.ts`); `src/hooks/*.ts` wrap each endpoint in a
  `useQuery`/`useMutation` hook. Components never call `fetch` directly.
- **Types**: `src/types/threat-intel.ts` is the single source of truth for every data shape the frontend
  consumes — one large file, deliberately not split, so a reviewer (human or AI) can see the entire data
  model in one place.
- **No global state manager**: server state lives in React Query's cache; the only client-only global
  state is `SelectionContext` (which CVE/malware drawer is open) and per-component `useState`.

## 4. Backend design

- **Entry point**: `server/index.js` — loads `.env`, builds the Express app, mounts
  `routes/dashboard.js` and `routes/chat.js` at `/api`, starts the connector scheduler, the RAG indexer,
  and three background extraction jobs, then serves `dist/` in production.
- **Connectors** (`server/connectors/*.js`, ~26 files) — one module per **bulk/scheduled** source
  (CISA KEV, NVD, EPSS, MITRE ATT&CK, abuse.ch feeds, ransomware trackers, news RSS, etc.). Each exports
  `{ id, label, intervalMs, fetch() }`; the scheduler calls `fetch()` once at boot and then every
  `intervalMs`, storing the result in the in-memory `cache.js` map. A handful of these files are
  **dual-duty**: they also export a `checkIndicator()` used for on-demand single-indicator lookups (e.g.
  `otx.js`, `abuseipdb.js`, `pulsedive.js`), so the same code backs both the bulk feed and the Triage
  Console.
- **Lookups** (`server/lookups/*.js`, 14 files) — **on-demand-only** single-indicator checks with no bulk
  feed at all (VirusTotal, GreyNoise, Shodan, Hybrid Analysis, LeakIX, crt.sh, RIPEstat, Team Cymru,
  Hudson Rock, SANS ISC, RDAP, urlscan.io, CIRCL). Wrapped in `server/lib/lookupLimiter.js` for a 10-minute
  per-indicator cache plus per-source rate spacing, since these are called live on every search.
- **Investigation orchestrator** (`server/investigation/`) — the backend for the Triage Console. `detect.js`
  classifies a pasted string into one of 16 indicator types; one module per type-family (`ipModule.js`,
  `domainModule.js`, `urlModule.js`, `hashModule.js`, `cveModule.js`, `entityModule.js`,
  `artifactModule.js`) gathers real data for that type; `crossReference.js` checks the value against this
  app's own already-ingested intelligence; `verdict.js` computes one shared severity/risk/priority so
  those fields can never contradict each other; `index.js` ties it all into one response.
- **Correlation layer** (`server/correlate.js`, `server/executiveSummary.js`, `server/threatTimeline.js`,
  `server/newsCorrelation.js`, etc.) — pure functions that join cache entries together (CVE+KEV+EPSS,
  IOC-to-ATT&CK-technique mapping, ransomware+OTX actor merging, threat-score computation). These run
  synchronously per-request from data already in memory — no separate batch/ETL step.
- **Entity extraction pipeline** (`server/combinedExtractionJob.js` + `*Extraction.js` files) — a
  background job that periodically reads newly-ingested news article text, uses the AI router to extract
  named malware families / threat actors / campaigns / dark-web findings, and merges results into four
  persistent entity stores (`malwareIntelligence.js`, `threatActorIntelligence.js`,
  `campaignIntelligence.js`, `darkWebIntelligence.js`). This is the one place raw LLM output is allowed to
  become persisted "fact" data, and even then every entity is seeded/cross-checked against MITRE ATT&CK's
  own catalog where possible (`verified` flag).
- **Persistence — no database**: every store the app writes across restarts is a flat JSON file under
  `server/.cache/` (malware/actor/campaign/dark-web intelligence, AI Summarization reports, watchlist,
  remediation tracker status, source-reliability history, threat-score history). Each store module
  (`malwareIntelligence.js` etc.) is a tiny hand-written repository: load-on-boot, mutate in memory,
  `fs.writeFileSync` on every write. There is no ORM, no migrations, and no schema enforcement beyond
  what each store's own JS functions do — see §5 for the shapes.
- **Routes** (`server/routes/dashboard.js`, ~56 endpoints + `chat.js`, 2 endpoints) — a single Express
  `Router`, all `GET`/`POST`/`PUT`/`DELETE` handlers in one file, grouped by feature with comment
  banners. No versioning, no OpenAPI spec.
- **MCP server** (`server/mcpServer.js`) — a separate optional process (`npm run mcp`) exposing the same
  underlying data as MCP tools (`lookup_cve`, `search_ioc`, `get_threat_feed`, etc.) for any MCP-compatible
  client, independent of the HTTP API.

## 5. "Database schema" (JSON store shapes)

There is no relational or document database. The closest equivalent is the set of persisted JSON stores
under `server/.cache/`. Representative shapes (TypeScript types for all of these live in
`src/types/threat-intel.ts`, shared conceptually between frontend and backend even though the backend
itself is untyped JS):

- **`malware-intelligence.json`** → `MalwareIntelligenceEntity[]`: `{ id, name, aliases[], description,
  attackId, verified, iocSightings, iocs[], articleIocs[], firstSeen, lastSeen, mentionCount, articles[] }`
- **`threat-actor-intelligence.json`** → `ThreatActorIntelligenceEntity[]`: adds `type` (APT/Ransomware/
  Cybercrime/...), `country`, `motivations[]`, `malwareUsed[]`, `targetedIndustries[]`, `techniqueIds[]`
- **`campaign-intelligence.json`** → `CampaignIntelligenceEntity[]`: `associatedActors[]`,
  `associatedMalware[]`, `targetedIndustries[]`, `cveExploited[]`
- **`darkweb-intelligence.json`** → `DarkWebIntelligenceEntity[]`: adds `type` (Data Leak/Credential Dump/
  .../Extortion Threat), `platform`, `victimOrg`
- **`ai-threat-summaries.json`** → `AiThreatSummaryReport[]`: the full structured SOC report shape (see
  §7) plus `processedArticleIds[]` and `lastCycleAt` for job-resumption bookkeeping
- **`watchlist.json`** → `{ keywords: WatchlistKeyword[] }`
- **`remediation-tracker.json`** → per-CVE `{ status, note, statusUpdatedAt }`
- **`source-reliability-history.json`** / **`threat-score-history.json`** / **`malware-trend-history.json`**
  / **`actor-trend-history.json`** → rolling daily snapshot arrays, capped at N days, used to compute
  trend deltas without needing time-series storage

None of these are queryable beyond "load the whole array into memory and `.filter()`/`.find()` it,"
which is adequate at current data volumes (each file is capped, e.g. 300 reports max) but is the first
thing that would need to change if this were pushed to significantly larger scale — see §11.

## 6. Authentication

**There is none.** Every HTTP endpoint under `/api/*` is unauthenticated and unauthorized — anyone who
can reach the process can read all data and trigger the on-demand lookups and AI-report generation. This
is acceptable for a personal/demo deployment behind an unlisted URL, but it is the single largest gap
before any shared or corporate deployment: there is no session/JWT/API-key middleware anywhere in
`server/routes/`, no user model, and no concept of a logged-in identity anywhere in the codebase. Adding
auth would mean introducing an identity layer (SSO/OIDC in front of the app, or middleware-level API keys)
that does not exist today, not just toggling a flag.

## 7. AI pipeline

Two entirely separate AI subsystems exist, deliberately not sharing infrastructure:

**A. Cloud provider-failover router** (`server/ai/aiRouter.js`) — used by every feature that needs a
cloud LLM call: AI Summarization report generation (`aiThreatSummary.js`), the on-demand Investigation
AI Report (`investigationAi.js`), detection-artifact drafting (`detectionRuleDraft.js`), and the combined
entity-extraction job. `aiRouter.summarize()` / `summarizeJson()` walk a fixed provider priority list,
retrying each once with backoff before failing over to the next, and normalizing whichever provider
actually answered into one result shape. A provider with no configured key is skipped (not counted as a
failure); if every configured provider fails, `AllProvidersFailedError` propagates up as a 503.

| Priority | Provider | Model (exact ID) | Notes |
|---|---|---|---|
| 1 | Google Gemini | `gemini-flash-latest` | Google's maintained alias, not a pinned snapshot — avoids breakage when a dated model is retired |
| 2 | Mistral | `mistral-small-latest` | Served through Mistral's own OpenAI-compatible chat completions endpoint |
| 3 | Groq | `llama-3.3-70b-versatile` | Same Groq account/key also used for structured report/extraction calls elsewhere |
| 4 | Cohere | `command-r-08-2024` | Last live dated snapshot of Command R (undated alias was retired) |

**B. Local RAG chatbot** (`server/rag/*.js`) — fully separate, runs entirely against a local Ollama
install (`llama3.1:8b` for generation, `nomic-embed-text` for embeddings), no cloud call, no API key, no
cost. `indexer.js` chunks and embeds this app's own already-extracted intelligence (CVEs, KEV, ransomware
campaigns, ATT&CK techniques, malware/actor/campaign/dark-web entities, news) into `vectorStore.js`;
`retriever.js` does similarity search at query time; `ragChat.js` grounds the answer strictly in
retrieved chunks and returns their provenance (`ChatSource[]`) alongside the answer, so every chatbot
answer is traceable to a specific piece of this app's own data rather than the model's open-ended recall.
This tab reports itself unavailable (with setup instructions) if Ollama isn't running or the two models
aren't pulled — it degrades independently of subsystem A.

**C. Campaign-aware AI Summarization (recent addition).** Reports now go beyond a single vulnerability/
malware writeup: `campaignName` is extracted only when the article explicitly names a campaign/operation;
`campaignEvolution` is populated only when this platform already has real prior coverage of that same
campaign (matched by name/alias against `CampaignIntelligenceEntity`) — grounded strictly in that real
history, with the actual prior articles code-attached (never model-authored) so the citation can never be
fabricated. A first-ever sighting of a campaign correctly shows no evolution rather than an invented
narrative. Alongside this, **Infrastructure Reuse** (`server/infrastructureReuse.js`) cross-references a
report's own IOCs against every tracked malware/actor/campaign and every other AI Summarization report —
reusing the Investigation Console's own correlation engine — computed fresh every time the report is
viewed rather than stored, so a reuse hit discovered later still surfaces. **Intelligence Gaps** is a
lightweight derived view (no new AI call) over the kill-chain fields the schema already leaves `null`
when unreported, showing what's genuinely unknown rather than requiring a manual scan for missing rows.

**Grounding discipline (applies to both, and to the extraction jobs):** the guiding rule throughout this
codebase is that any fact the backend can already verify (CVE IDs, KEV/EPSS status, severity, raw
IOCs pulled from article text via regex, ATT&CK technique IDs matched against the synced catalog) is
extracted with code, never trusted to model recall — this is what actually enforces "never invent an
IOC," not just a prompt instruction. The model is only asked for genuine synthesis (narrative analysis,
risk framing, detection/hunting guidance, its own confidence self-assessment), and every structured field
returned by a model is passed through a `safeString`/`safeArray`/type-specific validator before it's
trusted — an ungrounded or malformed field is dropped or replaced with an explicit "Not Reported" rather
than silently reaching the frontend.

**Prompts** live inline as large template-literal constants at the top of the file that owns that
feature — `aiThreatSummary.js` (`SYSTEM_PROMPT`, the SOC report schema), `investigationAi.js`
(`SYSTEM_PROMPT` for the on-demand Investigation Report), `detectionRuleDraft.js` (per-artifact-type
prompts for Sigma/YARA/KQL/SPL drafting), `ragChat.js` (the grounding/citation instruction). There is no
separate prompt-template file or prompt-management system; prompts are versioned as ordinary source code
alongside the logic that calls them.

## 8. Threat intelligence integrations

~30 external sources, split by integration pattern:

- **Bulk/scheduled, keyless**: CISA KEV, MITRE ATT&CK (STIX bundle), URLHaus, ThreatFox, MalwareBazaar,
  Feodo Tracker, OpenPhish, Spamhaus DROP, Exploit-DB, ransomware.live, RansomWatch, RansomLook, YARA-Rules
  + SigmaHQ (detection-rule index), ~200-source news RSS aggregator
- **Bulk/scheduled, key optional-or-required**: NVD (key optional, raises rate limit), FIRST EPSS, OTX,
  AbuseIPDB, Pulsedive, PhishTank, Emerging Threats/Proofpoint, Malpedia, VulnCheck KEV, CVE Project, MISP
  Warning Lists
- **On-demand only, keyless**: crt.sh, RIPEstat, Team Cymru (IP-to-ASN + Malware Hash Registry, via DNS
  TXT not REST), Hudson Rock Cavalier, SANS ISC/DShield, RDAP (WHOIS-equivalent), CIRCL (NVD fallback)
- **On-demand only, key required**: VirusTotal, GreyNoise, Shodan, Hybrid Analysis, LeakIX, urlscan.io

Every source degrades independently and visibly: a missing key surfaces as `notConfigured`, a rate limit
as `rateLimited`, an inapplicable lookup (e.g. Hybrid Analysis rejecting a non-SHA256 hash) as `skipped`
with a reason — never a silent gap. `GET /api/dashboard/health` reports every source's live status plus a
rolling reliability score.

## 9. Data flow

**Bulk path (most of the app):** `Scheduler` calls each connector's `fetch()` on its own interval →
raw result lands in `cache.js` (`{ [sourceId]: { data, updatedAt } }`) → a `routes/dashboard.js` handler
reads one or more cache entries synchronously, runs them through `correlate.js`/feature-specific
correlation, and returns JSON → a React Query hook polls that endpoint on its own interval (defaulting
to a 15-minute dashboard-wide auto-refresh) → the component renders. No data is pushed; everything is
client-polled.

**On-demand investigation path:** user submits a raw string → `POST`/`GET /api/investigate` →
`detect.js` classifies the type → the matching module fans out `Promise.allSettled` across every
relevant lookup/connector `checkIndicator()` call → `crossReference.js` checks it against the app's own
entity stores → `verdict.js` computes one shared verdict → the full result renders immediately. The AI
Investigation Report is a **second, separate** on-demand call (`POST /api/investigate/ai-report`),
triggered only by an explicit button click, never fired automatically alongside the search above.

**Extraction path:** the news connector ingests article text on its own schedule → once enough
Critical/High/Medium articles are queued, `aiThreatSummaryJob.js` runs a full AI Summarization pass per
article (grounded per §7) → in parallel, `combinedExtractionJob.js` runs entity extraction across the same
article pool → both write to their respective JSON stores → the RAG indexer picks up newly-written data
and re-embeds it for the local chatbot.

## 10. Component relationships

- **Frontend ↔ Backend**: exclusively HTTP/JSON through `src/api/dashboardApi.ts`; no shared code between
  the two (the shared "contract" is the TypeScript interfaces in `threat-intel.ts`, hand-kept in sync with
  the JS backend's actual response shapes — there is no codegen or runtime schema validation on the wire).
- **Within the backend**: routes are the only consumers of connectors/lookups/investigation
  modules/correlation functions — those lower layers never import from `routes/`, keeping dependencies
  one-directional (routes → domain logic → cache/store, never the reverse).
- **Cross-feature reuse**: the investigation orchestrator and the CVE detail drawer both call
  `server/cveProfile.js`'s correlation engine rather than duplicating it; the Triage Console's malware/actor
  pivot and the dedicated intelligence tabs both read the same four entity stores; `reportPrimitives.tsx`
  is shared between AI Summarization and the Investigation Console's AI report rendering.
- **Independent subsystems**: the MCP server (`mcpServer.js`) and the RAG chatbot are the two pieces that
  can run/fail without affecting the main dashboard — both are optional, separately health-checked,
  and read from the same underlying data rather than owning their own copy.

## 11. Future roadmap

The items below are gaps observed while building this platform, not commitments — listed in rough
priority order for whoever picks this up next:

1. **Authentication/authorization** — the largest gap for anything beyond a personal demo (§6). Needs an
   identity layer (SSO/OIDC) and likely role scoping (e.g. read-only vs. can-trigger-AI-reports) before
   any shared deployment.
2. **Real persistence at scale** — the flat-JSON-file stores (§5) work well under ~300-record caps but
   have no indexing, no concurrent-write safety beyond "last write wins," and no query capability beyond
   in-memory `.filter()`. A move to a real datastore (Postgres is the natural fit given the data is mostly
   relational entities with array fields) becomes necessary once data volume or write concurrency grows.
3. **Secrets management** — currently a flat `.env` file; a corporate/shared deployment should move keys
   into a real secrets manager (Vault/AWS Secrets Manager/Azure Key Vault) rather than an env file on disk.
4. **API contract enforcement** — no runtime schema validation between backend responses and frontend
   `threat-intel.ts` types today; a schema-first approach (e.g. Zod shared between both sides, or OpenAPI
   codegen) would catch drift automatically instead of relying on manual discipline.
5. **Rate-limit/quota resilience** — several bulk sources are free-tier and can silently degrade under
   load; a more robust backoff/circuit-breaker layer (beyond the current per-source `withRetry`) would
   help at higher traffic.
6. **Test coverage** — there is currently no automated test suite (no unit/integration tests found in the
   repo); verification has been manual (typecheck + live endpoint checks + browser click-through per
   change). Adding tests, especially around the correlation/verdict logic, would materially de-risk future
   changes.
7. **Observability** — logging is console-based (`server/lib/log.js`); no structured logging, metrics, or
   tracing integration exists. Worth adding before running this unattended at any real scale.
