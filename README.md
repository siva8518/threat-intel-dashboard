# Threat Intelligence Dashboard

A real-time threat intelligence platform: React/TypeScript/Vite/Tailwind frontend over a Node/Express
backend that continuously ingests, normalizes, and correlates data from free/community-tier public
threat-intel sources.

> **Verification status**: `npm install`, `tsc --noEmit`, and a live click-through of the dashboard
> in a real browser have all been done. All bulk sources have now been confirmed against live upstream
> APIs with real credentials, not just documented shapes: CISA KEV, NVD, EPSS, MITRE ATT&CK,
> ransomware.live, RSS feeds, and -- once a real key was configured for each -- OTX, AbuseIPDB,
> URLHaus, ThreatFox, and MalwareBazaar. That last round of testing caught (and fixed) real
> discrepancies between abuse.ch's documented behavior and what the live API actually does, see
> [Known limitations](#known-limitations). Pulsedive, Emerging Threats, Spamhaus DROP and the CVE
> Program's delta feed were all confirmed live (keyless, shapes verified against real responses).
> Pulsedive and Hybrid Analysis have now also been exercised end-to-end with real keys -- that pass
> caught a real discrepancy in Hybrid Analysis's endpoint (see Known limitations), fixed in
> `server/lookups/hybridAnalysis.js`. PhishTank was probed live without a real key far enough to
> confirm its current anonymous-access behavior (see Known limitations) but not exercised end-to-end
> with one. VirusTotal, GreyNoise and Shodan (IOC Search only) are still untested against live keys.

## Architecture

**The backend is a real aggregation service, not a reverse proxy.** Background sync jobs
(`server/scheduler.js`) run on their own schedule per source regardless of whether a browser is even
open, writing into an in-memory cache (`server/cache.js`) with retry-with-backoff
(`server/lib/retry.js`) and graceful degradation (a failing source keeps serving its last-known-good
data instead of going blank). The frontend polls the backend's own already-normalized, already-
correlated endpoints (`server/routes/dashboard.js`) -- it never talks to an upstream API directly.

This is a deliberate shift from an earlier version of this project, where the browser polled a thin
reverse-proxy directly. That model breaks down once you need shared caching, rate-limit respect
across multiple viewers, and cross-source correlation -- none of which mean anything if every browser
tab is independently hitting NVD/abuse.ch/etc.

```
server/
  lib/            retry.js (backoff), rss.js (regex RSS parser -- Node has no DOMParser),
                  cpe.js (NVD vendor extraction), http.js (fetch+timeout+ApiError), abuseCh.js, log.js,
                  lookupLimiter.js (per-source rate limit + 10-min cache for on-demand IOC Search lookups)
  cache.js        in-memory { [sourceId]: { data, updatedAt, error, isSyncing } }
  scheduler.js     runs every connector once at boot, then on its own intervalMs forever
  connectors/      one module per scheduled/bulk source (see table below); index.js registers them all
  lookups/         on-demand-only single-indicator lookups (VirusTotal, GreyNoise, Shodan,
                  Hybrid Analysis, LeakIX, crt.sh, RIPEstat, Team Cymru, Hudson Rock, SANS ISC,
                  CIRCL) -- never scheduled/cached in bulk, called live by IOC Search (CIRCL is
                  called from the single-CVE route instead, as an NVD fallback)
  data/
    malware-attack-map.json   curated malware-family -> ATT&CK technique-id seed list (see caveats below)
  correlate.js     CVE+KEV+EPSS join, cross-source IOC dedup, malware->ATT&CK mapping,
                  trending-malware aggregation, ransomware+OTX actor merge
  threatFeed.js    the deduped IOC feed builder, shared by routes/dashboard.js AND githubIntel/
                  (factored out so both read the exact same source list, see below)
  githubIntel/     GitHub repo discovery/classification/extraction/correlation/scoring -- own
                  two-connector cadence + disk-backed store, see "GitHub Intel" section below
  routes/dashboard.js   GET /api/dashboard/{summary,cves,cve-trend,cve-program-activity,kev,
                        vulncheck-kev,exploits,threat-feed,malware-trending,attack-techniques,
                        ransomware,threat-actors,threat-actor-profiles,github-intel,news,health},
                        GET /api/ioc-search
  index.js         mounts the router, starts the scheduler, serves dist/ in production
```

## Data sources

| Section | Source(s) | Auth | Bulk feed or lookup-only |
|---|---|---|---|
| Latest CVEs, trend chart, EPSS score | [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) + [FIRST EPSS](https://www.first.org/epss/) | NVD key optional | Bulk |
| Known Exploited Vulnerabilities | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | No | Bulk |
| ATT&CK technique index | [MITRE ATT&CK](https://attack.mitre.org/) (official STIX bundle) | No | Bulk (taxonomy only) |
| Threat feed (URLs/domains/hashes/IPs) | URLHaus, ThreatFox, MalwareBazaar, Feodo Tracker, OpenPhish, OTX, [Pulsedive](https://pulsedive.com/), [PhishTank](https://phishtank.org/), [Emerging Threats](https://rules.emergingthreats.net/) (Proofpoint), [Spamhaus DROP](https://www.spamhaus.org/drop/) | abuse.ch/OTX/PhishTank keys optional-to-required (see table below); Pulsedive/Emerging Threats/Spamhaus keyless | Bulk |
| Top malicious IPs | [AbuseIPDB](https://www.abuseipdb.com/) `/blacklist` | Key optional | Bulk |
| Ransomware campaigns + actor activity | [ransomware.live](https://ransomware.live/) + [RansomWatch](https://github.com/joshhighet/ransomwatch) + [RansomLook](https://www.ransomlook.io/) (merged/deduped, see `server/ransomwareCampaigns.js`) + OTX adversary tags | No (OTX optional) | Bulk |
| Malware family reference | [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/) (Fraunhofer FKIE) -- family/actor taxonomy synced daily; per-actor family attribution fetched live only when a Threat Actor Profile is viewed | No | Bulk (list) + live (per-actor detail) |
| Security news | 32 RSS feeds: CISA Advisories, CISA ICS Advisories, CISA Malware Analysis Reports, CISA Cybersecurity Advisories, UK NCSC, JPCERT/CC, The Hacker News, BleepingComputer, Krebs on Security, Dark Reading, SecurityWeek, Infosecurity Magazine, The Record, CyberScoop, Malwarebytes Labs, SANS ISC, Graham Cluley, The DFIR Report, Red Canary, Cisco Talos, CrowdStrike, Unit 42, Recorded Future, Google Threat Intelligence (covers Mandiant research), Microsoft Security, SentinelLabs, Rapid7, Check Point Research, ESET Research, Kaspersky Securelist, Elastic Security Labs, FortiGuard Labs | No | Bulk |
| CVE Program recent activity | [CVE Program](https://www.cve.org/) (`cve.org`/CVEProject) `delta.json` -- newly reserved/updated CVE IDs, distinct from NVD's enriched records | No | Bulk |
| Exploit intelligence | [Exploit-DB](https://gitlab.com/exploit-database/exploitdb) CSV mirror (CVE<->PoC correlation) + [VulnCheck KEV](https://vulncheck.com/kev) (larger, exploit-linked exploited-CVE catalog vs CISA's own) | Exploit-DB keyless; VulnCheck key optional | Bulk |
| Detection rule coverage | [YARA-Rules](https://github.com/Yara-Rules/rules) + [SigmaHQ](https://github.com/SigmaHQ/sigma) -- filename-based family/actor index, cross-referenced against Trending Malware (see Known limitations) | No | Bulk (periodic tree sync) |
| Single-CVE lookup fallback | [CIRCL CVE Search](https://cve.circl.lu/) -- used only when NVD doesn't have a record | No | Live, fallback only |
| IOC Search (on-demand) | OTX, AbuseIPDB, Pulsedive, VirusTotal, GreyNoise, Shodan, Hybrid Analysis, [LeakIX](https://leakix.net/), [crt.sh](https://crt.sh/) (domain/cert transparency), [RIPEstat](https://stat.ripe.net/) (IP/ASN), [Team Cymru](https://www.team-cymru.com/) (IP/hash, DNS-based), [Hudson Rock Cavalier](https://www.hudsonrock.com/) (domain/infostealer exposure), [SANS ISC/DShield](https://isc.sans.edu/api/) (IP reputation) | All keys optional; crt.sh/RIPEstat/Team Cymru/Hudson Rock/SANS ISC are fully keyless | **Lookup-only** -- these free tiers don't offer a bulk feed (or, for Hybrid Analysis, its old bulk feed no longer exists), so they only run when you search a specific indicator. Each is throttled server-side (`server/lib/lookupLimiter.js`) to its own free-tier rate limit and cached for 10 minutes per indicator. |
| GitHub Intel | [GitHub Search + REST API](https://docs.github.com/en/rest) -- repo discovery, README/rule-file content, correlated against every source above | `GITHUB_TOKEN` strongly recommended (works without one) | Bulk, two-tier cadence (see below) |

If a source is unreachable or its key isn't configured, its panel/contribution shows a clean
"unavailable"/"not configured" state instead of breaking the rest of the dashboard.

## GitHub Intel

Discovers public repos related to exploit PoCs, malware, Sigma/YARA rules, then classifies, content-scans,
and scores them -- see `server/githubIntel/`.

- **Discovery** (`discovery.js`, hourly): sweeps a curated set of GitHub Search queries per category
  (`categories.js`) and upserts repo metadata into a disk-backed store (`store.js`). Deliberately starts
  with 4 categories (Exploit PoC, Sigma Rules, YARA Rules, Malware), not the full ~18 originally
  considered -- cheaper to validate the whole pipeline against ~150 repos than ~2,000. Add more
  categories/queries once this set is confirmed working for your use case.
- **Enrichment** (`enrichment.js`, every 15 min, small batches): for each not-yet-enriched (or
  weekly-stale) repo, fetches the README + a recursive file tree + up to 10 files matching known
  rule/IOC/per-CVE filename patterns (`contentFetcher.js`) -- deliberately *not* a full git clone, since
  the content that actually carries extractable intel almost always lives in those files, not buried in
  general source.
- **Extraction** (`extractor.js`): regex-based CVE IDs, hashes, IPs, domains, URLs, emails, YARA rule
  names, Sigma rule IDs -- with automatic un-defanging (`hxxp://`, `[.]`, `(at)`). ATT&CK technique IDs
  and threat-actor names are cross-checked against this app's own already-cached MITRE ATT&CK data
  (`server/connectors/attack.js`) to filter out false-positive-shaped matches, not trusted as raw regex hits.
- **Classification** (`classifier.js`): weighted keyword/topic heuristic (GitHub topics strongest, README
  content weakest), same "documented, tunable, not a black box" style as the rest of this app -- not ML.
- **Correlation** (`enrich.js#correlateIndicators`): cross-references extracted indicators against the
  exact same deduped threat feed powering the Threat Feed tab (`server/threatFeed.js`, shared so the
  source list can't drift between the two).
- **CVE enrichment** (`enrich.js#enrichCve`): live single-CVE NVD lookup (cached process-wide) plus
  already-cached KEV/EPSS data.
- **Threat scoring** (`threatScoring.js`): the same transparent weighted-heuristic approach as the IOC
  Search's `correlatedVerdict` -- see the module's own comments for the exact weights and worked example.

**Two-tier cadence, not one**: GitHub's Search API is rate-limited to 10 req/min unauthenticated (30/min
with a free `GITHUB_TOKEN`) -- the scarce resource -- so discovery of new repos runs hourly. Content
fetches (README/tree/file) use the much larger REST ("core") pool (60/hr unauthenticated, 5000/hr with a
token), so enrichment works through the backlog every 15 min instead.

**Why a disk-backed store, unlike every other connector in this app**: every other source here is
in-memory only, cheap to rebuild on restart. A GitHub repo index is not cheap to rebuild given the
Search API's tight rate limit -- losing it on every dev-server restart would mean slowly re-earning it
back. `server/githubIntel/store.js` persists to a gitignored JSON file instead.

## Correlation

- **Executive Threat Summary** (`server/executiveSummary.js`, `GET /api/dashboard/executive-summary`):
  the dashboard's hero section, replacing the old static summary cards (and the old homepage geo map,
  named-actors preview, and US-scoped industry heat map widgets, which were removed -- the map had a
  live rendering bug, and both are superseded by this section's globally-computed industries/countries
  facts). Computes an overall 0-100 Threat Score and Low/Elevated/High/Critical level from five live
  signals -- critical CVE volume (30d), recent CISA KEV additions (7d), live threat-feed IOC volume,
  ransomware campaign volume, and malware-family sighting concentration. A transparent weighted
  heuristic (same philosophy as `server/githubIntel/threatScoring.js`'s per-repo score), not a claimed
  industry-standard metric -- the exact weights/caps and a live breakdown are documented in the module
  and exposed in the UI via a "How is this score calculated?" disclosure. Also surfaces the most active
  threat actor (from the existing ransomware/OTX actor merge), most active malware family (from the
  existing trending-malware computation), most exploited CVE (prefers a CVE that's both in CISA KEV
  *and* has GitHub PoC repos referencing it -- the strongest combined signal this app can derive for
  free), industries targeted and countries under attack (computed globally via
  `correlate.js#computeActorIndustryHeatmap`/`computeGeoTargeting` called with no country filter), and
  total active campaigns. Clicking the malware/CVE facts opens the same detail drawers described below;
  clicking a country or industry jumps to Threat Actors & Tools filtered to it (ransomware campaigns
  are tagged with their industry bucket server-side in `/api/dashboard/ransomware` for this).
- **Threat Correlation Engine** (`server/correlationEngine.js`, `GET /api/dashboard/correlation-engine`,
  "Correlation Engine" tab): automatically links *live* records -- the deduped threat feed,
  ransomware.live campaigns, and enriched GitHub Intel repos -- whenever they share a CVE, malware
  family, threat actor, or IP/domain/URL/hash indicator, via a union-find over normalized key tokens.
  Each connected cluster renders as one "Unified Intelligence Card" instead of the same activity
  sitting scattered across separate, isolated feed rows. MITRE ATT&CK (techniques, plus any CVEs a
  matched actor/malware's ATT&CK entry cites) is layered on top as read-only enrichment of an
  already-formed cluster, never used to merge clusters. That distinction came from three real
  supercluster bugs hit and fixed live while building this (all documented in the module itself):
  ATT&CK technique IDs are shared by hundreds of unrelated malware families; common dual-use tools
  (Mimikatz, Cobalt Strike, PsExec...) are used by dozens of otherwise-unrelated ATT&CK groups, and
  MITRE's own group↔software graph turned out to be a genuinely dense small-world network no threshold
  could tame; and GitHub "aggregator" repos (PoC/signature indexes covering dozens of unrelated
  campaigns) and a handful of individually-common malware names (e.g. "Conti," a defunct brand still
  name-dropped in countless unrelated repos' generic "detects: ..." blurbs) bridged the same way. Each
  was fixed by excluding the specific hub source from *merging* records rather than lowering a
  threshold, since lower thresholds still left enough short chains to re-collapse into one blob.
- **Security Newsroom** (`server/newsCorrelation.js`, tagging done server-side in the existing
  `GET /api/dashboard/news`, "Security News" tab): every headline is tagged with the CVE IDs, threat
  actors, malware families, industries, and countries it mentions (regex for CVE IDs; word-boundary
  substring matching for the rest, against the same ATT&CK group/software names, live threat-feed
  malware families, and ransomware group names used elsewhere in this app -- plus a new
  `server/data/country-names.json` for country mentions), a derived severity (critical if a mentioned
  CVE is in CISA KEV or has EPSS ≥ 0.5; high for urgent-language headlines like "zero-day"/"actively
  exploited"; medium if it mentions any tracked entity; low otherwise), and an `isBreaking` flag
  (published in the last 6 hours). The UI groups by any of the five tag dimensions, with a pulsing
  "Breaking" strip for recent critical/high-severity stories, and CVE/malware chips open the same
  detail drawers as the rest of the app. Two real bugs found and fixed live while building this: plain
  substring matching (not word-boundary) tagged headlines with tools they never mentioned (the ATT&CK
  software "Ping" matched inside "Wiping"/"Mapping", "Disco" inside "discovered"); and generic
  living-off-the-land tool names (Ping, Net, Tasklist, certutil...) are common enough as plain English
  words to falsely tag unrelated headlines, so `correlationEngine.js#getCommonAttackToolNames` (a tool
  used by more than 5 different ATT&CK groups) is reused here to exclude them. Known limitation, same
  as elsewhere in this app: a handful of actor/country names are also common words or given names (the
  "Play" ransomware group vs. the word "play", "Jordan" the country vs. the name) and can occasionally
  over-match -- accepted for the same reason as the other name-collision cases already documented here,
  since there's no free NLP entity extractor to do meaningfully better.
- **Merged Overview tile**: the Executive Threat Summary, Top Security Events Today, and Daily Summary
  (below) all render inside one `<Card>` (`ExecutiveThreatSummary.tsx` hosts all three, each of the
  latter two exported without its own Card wrapper) instead of three separate cards -- one scannable
  tile instead of three, per explicit request. (An earlier "Live Threat Feed" widget -- a continuously-
  updating activity timeline in a right-hand sidebar column -- was later removed entirely once its most
  load-bearing signal, new ransomware activity, was already covered by the Daily Summary below; removing
  it also freed the sidebar column for the Top Threat Actors Today panel below.) The CVE/KEV story is
  told exactly once across the merged tile: "Most Exploited CVE" (a specific CVE ID) stays in the
  fact-card row, and the KEV *count* lives only in the Daily Summary's first line -- there's no separate
  "Critical KEV" stat tile duplicating that count.
- **Top Security Events Today** (`server/todaySecurityEvents.js`, `GET /api/dashboard/today-events`): a
  same-calendar-day rollup -- active exploit campaigns (distinct OTX pulses reported today), new
  ransomware victims, new MalwareBazaar samples, new GitHub exploits/PoCs, and new IOCs -- each just a
  same-day filter over the exact sources already used elsewhere in this app, not a separate rollup
  mechanism. Every tile is clickable, jumping to the most relevant tab (Active Exploit Campaigns →
  Correlation Engine, New Ransomware Victims → Threat Actors & Tools, New Malware Samples/IOCs → Threat
  Feed, GitHub Exploits → GitHub Intel).
- **Daily Summary** (`server/dailySummary.js`, `GET /api/dashboard/daily-summary`; originally named "AI
  Daily Brief" -- renamed since it does no LLM/AI summarization at all, just rule-based counts and
  comparisons over this app's own live data, and the old name implied otherwise): a short, skimmable
  "Today's Summary" -- new KEVs, distinct ransomware groups active today (not the raw victim-post count
  already shown in the stat tile above -- a different, complementary cut of the same data), new ThreatFox
  IOCs specifically (a named source's share of the aggregate "New IOCs" tile, not a duplicate of it),
  today's most active malware family, and a news highlight -- plus an estimated reading time computed
  from the actual word count (~200 wpm), not a fixed label. Every bullet is clickable: each carries a
  typed `action` alongside its text (a tab jump, a malware family that opens the same detail drawer used
  everywhere else in this app, or a news source that deep-links into Security Newsroom's existing source
  filter) rather than the frontend re-parsing the sentence to guess where it should go. The malware-family
  line is the one place in this app that needs a real day-over-day comparison, so it's the one place that
  persists a small rolling history to disk: `server/malwareTrendHistory.js` records one snapshot per
  calendar day (same pattern as `server/githubIntel/store.js`) and reports "family activity
  increased/decreased N%" once a prior day's snapshot exists. On a fresh deploy (no history yet), it
  honestly reports the day's leading family and its sighting count instead of inventing a percentage --
  the same "state what's real, don't guess" principle used everywhere else in this app. The news-highlight
  line originally always picked whichever source published the most articles today, which in practice was
  almost always SANS ISC's frequent daily podcast posts -- real, but not a particularly newsworthy
  highlight. Now prefers a real report from a major security vendor (`MAJOR_VENDOR_SOURCES` in
  `server/connectors/newsFeeds.js`) whenever one exists today, and only falls back to the plain
  highest-volume source when no major vendor published anything that day (confirmed live: this fallback
  is the honest, common case, since these free vendor blogs don't all publish daily).
- **Security Newsroom "Major Vendors" filter**: the source dropdown includes a grouped "Major Vendors
  (grouped)" option covering the commercial threat-research vendor feeds among this app's 31 news
  sources (Cisco Talos, CrowdStrike, Unit 42, Recorded Future, Google Threat Intelligence, Microsoft
  Security, SentinelLabs, Rapid7, Check Point Research, ESET Research, Kaspersky Securelist, Elastic
  Security Labs, FortiGuard Labs) as one bucket, distinct from journalism/aggregator outlets and
  government/CERT advisories. Defined twice -- `MAJOR_VENDOR_SOURCES` in
  `server/connectors/newsFeeds.js` (used by the Daily Summary's vendor-preference logic above) and again
  in `src/components/dashboard/SecurityNews.tsx` (used by this filter) -- kept in sync manually, since
  this app has no shared client/server code layer. `SecurityNews` also accepts an `initialSourceFilter`
  prop so the Daily Summary's news bullet can deep-link straight into a specific source's headlines,
  reusing this same dropdown rather than a separate mechanism.
- **Top Threat Actors Today** (`server/topThreatActorsToday.js`, `GET /api/dashboard/top-threat-actors-today`,
  right-hand panel on the Overview tab, in the space freed up by removing Live Threat Feed): a ranked,
  same-calendar-day activity leaderboard -- distinct from `correlate.js#mergeThreatActors` (an all-time,
  not "today," ransomware.live + OTX merge that only ever surfaces one name for the Executive Summary's
  "Most Active Threat Actor"). Surveyed every existing threat-actor data source in this app before
  building this (the Threat Actors & Tools tab's ransomware.live+OTX merge, the Threat Actor Profiles
  tab's 174 MITRE ATT&CK groups, and Security Newsroom's actor tagging) and combined three of them --
  ransomware.live victim posts, OTX pulse adversary tags, and news actor mentions (the exact tagging
  already computed in `newsCorrelation.js`, not re-derived) -- into one score per actor, each filtered to
  today's date. Every raw name is canonicalized through MITRE ATT&CK's own alias lists first (e.g. a
  group's `G0016`/"APT29" entry lists 14 known aliases including "Cozy Bear" and "Midnight Blizzard"), so
  a ransomware.live group and a news mention referring to the same real actor under different spellings
  count as one entry, not two; a raw name with no ATT&CK match (e.g. a pure ransomware brand like "the
  gentlemen") is kept as-is. Confirmed live: on a quiet day ransomware.live's dozens-of-victims/day volume
  dominates the list, since there's no free source that reports daily APT activity volume the way
  ransomware.live does for ransomware -- an honest reflection of what these free sources actually cover
  in bulk, not a bug. Shows however many distinct actors were genuinely active today (up to 5), not padded
  to a fixed count. Each row shows a real trend arrow (↑/↓/→) from a real day-over-day comparison, powered
  by `server/actorTrendHistory.js` (a rolling daily snapshot of every actor's score, same pattern as
  `server/malwareTrendHistory.js`) -- a brand-new entrant with no prior-day score is correctly shown as ↑
  (a real increase from a real baseline of zero), not fabricated.
- **Clickability fix** (confirmed live, a pre-existing bug surfaced while wiring up the widgets above):
  "Industries Targeted" and "Countries Under Attack" in the Executive Threat Summary were entirely
  unclickable -- `FactCard` rendered as a native `<button>`, but those two facts nest their own per-item
  `<button>`s inside it, and a `<button>` can't validly contain another one; the browser's HTML parser
  broke the inner clicks (React's own `validateDOMNesting` warning matched exactly this component).
  Fixed by rendering `FactCard` as a `<div role="button">` with keyboard handling instead, reserved for
  the FactCards that click as a single unit. Separately, ransomware campaign rows across this app
  (Threat Actors & Tools, Threat Actor Profiles) were often missing a usable link at all -- confirmed
  live: RansomLook's own `link` field is relative to the leak site's own domain, not a standalone URL.
  Added `server/connectors/ransomwareGroups.js` (ransomware.live's own group directory, a real per-group
  profile page URL) as a fallback `sourceUrl` in `server/ransomwareCampaigns.js` when no victim-specific
  link exists yet -- a real link, just less specific than a per-victim page. That connector's endpoint is
  rate-limited to 1 request/minute, so its sync interval is kept short (30 min, not hours) purely so a
  transient 429 (e.g. from `node --watch` restarting on every server file edit during dev, each restart
  re-running every connector once) self-heals on the next tick instead of leaving the fallback empty for
  hours.
- **CVE ↔ KEV ↔ EPSS**: every CVE record is cross-referenced against the KEV catalog
  (`knownExploited`) and given an EPSS score/percentile, computed once server-side
  (`correlate.js#correlateCves`) instead of by every client.
- **IOC dedup**: the same indicator often appears in more than one feed (e.g. a URL in both URLHaus
  and OpenPhish). `correlate.js#dedupeIocs` merges these into one row with a combined `sources` list.
- **Malware ↔ ATT&CK**: there is no free live feed mapping arbitrary malware to ATT&CK techniques, so
  `server/data/malware-attack-map.json` is a small, manually curated seed list (~28 well-known
  families, sourced from MITRE's own Software pages). "Trending Malware" and "ATT&CK Techniques
  Observed" are both derived by matching malware-family names seen in the live threat feed against
  this map -- a best-effort approximation, stated as such in the UI, not live telemetry.
- **Threat actors**: ransomware.live (group name, victim, sector) is merged with OTX pulses' informal
  `adversary` tag into one list. Ransomware-group attribution is real; OTX adversary tags are
  community-submitted and not verified. Neither covers APT/nation-state actors -- there's no free
  bulk-attribution source for that.
- **Threat Actor Profile "Related CVEs"**: MITRE ATT&CK Groups/Campaigns/Software often cite the
  specific CVE they exploited right in their own citation text (confirmed live, e.g. Velvet Ant's own
  citation reads "... Exploits Cisco Zero-Day (CVE-2024-20399)") -- `server/connectors/attack.js`
  extracts these IDs and `server/actorProfile.js` enriches each with a live single-CVE NVD lookup
  (falling back to a bare ID+link if NVD is unreachable for that ID). This is real, actor-specific data,
  not a guess -- but confirmed live it only covers **16 of 174 ATT&CK groups** (~9%), since most
  write-ups don't cite a specific CVE. A generic NVD keyword search on the actor's own name is kept as
  a free last-resort topper-upper, but confirmed live that this almost never matches anything (CVE
  descriptions describe the vulnerability, not who exploited it -- e.g. searching NVD for the exact
  phrase "Lazarus Group" returns zero results). For most actors, an empty "Related CVEs" section is
  the honest answer, not a bug.
- **Threat Actor Profile "Related Malware"**: matches live threat-feed IOCs against both the actor's
  own name/aliases *and* the names of its ATT&CK-documented malware/tools (e.g. an IOC tagged
  "Zebrocy" now correctly surfaces under APT28). Still frequently empty for a given actor at any given
  moment, since the live threat feed's rolling window is dominated by generic commodity
  malware/ransomware, not APT-specific implants -- this reflects what's actually circulating right
  now, not a broken correlation.
- **Threat Actor Profile "Related Campaigns" (OTX)**: a live full-text pulse search
  (`server/connectors/otx.js#searchPulses`) for the actor's name, re-verified against each hit's own
  name/description (`actorProfile.js#buildOtxCampaigns`) since OTX's search is a loose/fuzzy match, not
  an exact phrase search -- confirmed live that querying "Velvet Ant" returns zero pulses that
  genuinely mention it, while "APT28"/"Lazarus Group" return pages of real ones (9 real campaigns for
  APT28, up from 1 before this was added).
  - **Confirmed live this search is genuinely slow** (~16s for a broad query), which surfaced a real
    bug: the frontend's `src/lib/http.ts` has its own client-side fetch timeout (12s, independent of
    the backend's), so it was silently aborting the profile fetch before the slower backend response
    ever arrived -- the profile view would render just the actor's name and nothing else, with no
    error message (React Query's `isLoading`/`isError` were both technically correct, there was just
    never a settled result to show). Fixed by giving `fetchThreatActorProfile` its own longer
    `timeoutMs` (35s) in `src/api/dashboardApi.ts`.
- **IOC Search correlation**: searching one indicator fans out live to whichever of
  OTX/AbuseIPDB/Pulsedive/VirusTotal/GreyNoise/Shodan/Hybrid Analysis are configured and support that
  indicator type, and reduces their individual verdicts to one `correlatedVerdict` (malicious if ≥2
  sources agree, suspicious if 1 flags it, else clean/unknown) -- a simple, documented heuristic, not a
  proprietary scoring model. Each lookup is wrapped in `server/lib/lookupLimiter.js`, which enforces a
  minimum spacing between live calls per source (matching that source's free-tier rate limit) and
  caches each indicator's result for 10 minutes, so repeat searches are free and rapid-fire searches
  can't blow through e.g. VirusTotal's 4-req/min quota. A source that's rate-limited surfaces in the
  response's `rateLimited` list rather than silently disappearing.

## Getting started

Requires **Node.js 18+**.

```bash
npm install
cp .env.example .env   # optional: add any of the keys described in .env.example
npm run dev              # runs Vite (5173) AND the backend (8080) together via `concurrently`
```

The backend now does continuous background work (scheduled sync jobs), so it has to run as a real
process in dev, not just live inside Vite's proxy. `npm run dev` starts both; `npm run dev:api` runs
just the backend alone if you need to debug it in isolation.

### Production build

```bash
npm run build   # tsc --noEmit && vite build -> dist/
npm start        # node server/index.js -- serves dist/ AND runs the same scheduler/routes
```

### Docker

```bash
docker build -t threat-intel-dashboard .
docker run -p 8080:8080 \
  -e ABUSECH_AUTH_KEY=... -e OTX_API_KEY=... -e ABUSEIPDB_API_KEY=... \
  -e PULSEDIVE_API_KEY=... -e PHISHTANK_API_KEY=... \
  -e VIRUSTOTAL_API_KEY=... -e GREYNOISE_API_KEY=... -e SHODAN_API_KEY=... -e HYBRID_ANALYSIS_API_KEY=... \
  threat-intel-dashboard
```

## MCP server

`server/mcpServer.js` exposes the dashboard's already-aggregated data as [MCP](https://modelcontextprotocol.io)
tools, so an MCP-capable client (Claude Desktop, Claude Code, etc.) can query this project's threat
intel directly instead of you copy-pasting from the browser. It's a thin stdio-based client: it makes
no upstream calls itself, it just calls the already-running backend's own `/api/dashboard/*` routes.
**The backend (`npm run dev` or `npm start`) must already be running** for tool calls to return data —
starting the MCP server alone does not start the scheduler/cache.

Tools exposed: `lookup_cve`, `search_threat_actor`, `get_threat_actor_profile`, `search_ioc`,
`get_threat_feed`, `get_ransomware_campaigns`, `get_github_repo_intel`, `get_source_health`,
`get_malware_trending`, `get_attack_techniques`, `get_kev_catalog`.

Run it standalone with:

```bash
npm run mcp   # node server/mcpServer.js
```

To register it with **Claude Desktop**, add to `claude_desktop_config.json`
(Windows: `%APPDATA%\Claude\claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "threat-intel-dashboard": {
      "command": "node",
      "args": ["C:/Users/sivak/OneDrive/Desktop/threat-intel-dashboard/server/mcpServer.js"]
    }
  }
}
```

To register it with **Claude Code**, run from this project directory:

```bash
claude mcp add threat-intel-dashboard -- node server/mcpServer.js
```

Either way, restart the client after registering, and make sure the dashboard backend is already
running on the same machine (default `http://localhost:8080`) before asking it to use these tools.

## AI Assistant (local RAG chatbot)

The **AI Assistant** tab is a chatbot that answers questions using only this platform's own synced
intelligence — no paid API, no API key, no data ever leaves your machine. It's Retrieval-Augmented
Generation (RAG) built entirely on free, open-source, locally-run models via [Ollama](https://ollama.com):

- `server/rag/chunkBuilder.js` turns the already-synced CVEs, KEV entries, ransomware campaigns,
  MITRE ATT&CK actors/techniques, trending malware and news into small text chunks — nothing new is
  fetched, this is the same data every other tab shows.
- `server/rag/indexer.js` embeds each chunk (Ollama's `nomic-embed-text` model) and stores the
  vectors in a local, in-memory + JSON-file-backed index (`server/rag/vectorStore.js`) — re-embedding
  only chunks that changed since the last cycle, on the same 15-minute cadence as every connector.
- On each question, `server/rag/retriever.js` embeds it and finds the most similar chunks; if nothing
  clears a similarity threshold, the chatbot says so instead of guessing — this is what actually
  enforces "only answer from platform data," not just a prompt instruction.
- `server/rag/llmClient.js` streams a grounded answer from a local instruct model (`llama3.1:8b` by
  default) via Ollama's `/api/chat`, given only the retrieved chunks as context.

**Setup** (one-time, free): install [Ollama](https://ollama.com/download), then pull both models:

```bash
ollama pull llama3.1:8b
ollama pull nomic-embed-text
```

That's it — no `.env` changes needed unless you want different models (see `.env.example`). Start the
dashboard as usual (`npm run dev` / `npm start`); the AI Assistant tab detects Ollama automatically and
shows exact setup instructions if it isn't running yet or a model hasn't been pulled.

## AI Summarization

The **AI Summarization** tab turns major vendor threat-research and CISA advisories (Cisco Talos,
Unit 42, CrowdStrike, Microsoft Security, Google Threat Intelligence, Rapid7, CISA, etc. — see
`MAJOR_VENDOR_SOURCES` in `server/connectors/newsFeeds.js`) into full enterprise-grade SOC threat
intelligence reports, written for a Tier 1/2/3 analyst, incident responder, threat hunter, detection
engineer, threat intel analyst, security architect, and leadership all at once. It's deliberately not
a news recap: an AI Technical Summary (Threat/Attack Vector/Root Cause/Exploitation Details/Technical
Findings/Security Implications/Detection Opportunities/Hunting Opportunities/Immediate Actions),
executive summary, business impact, a full attack-chain threat overview, affected products, vendor
severity assessment, MITRE ATT&CK mapping, threat actors, malware, IOCs, detection opportunities,
threat hunting queries for eight named platforms (Microsoft Defender XDR, Microsoft Sentinel, Splunk,
Elastic, Sigma, YARA, CrowdStrike Falcon, Carbon Black), detection engineering opportunities, incident
response guidance, priority-bucketed immediate recommendations, patch information, confidence/risk
scoring, and five role-specific takeaways (SOC analyst, detection engineer, threat hunter, threat
intel, executive leadership).

- `server/aiThreatSummary.js` builds the prompt and calls Groq's free hosted API (`llama-3.3-70b-versatile`
  by default) — unlike the RAG Assistant above, this does **not** run on local Ollama. It's this app's
  single heaviest LLM call (a 25+ section structured report per article), and moving just this one call
  to a hosted free tier avoids the local model's own memory/reliability limits under sustained load. Get
  a free key (no card required) at [console.groq.com/keys](https://console.groq.com/keys) and set
  `GROQ_API_KEY` in `.env` — without it, AI Summarization reports itself unavailable, same "quiet
  not-configured" pattern as every other optional keyed source in this app.
- The AI Technical Summary is explicitly a technical-extraction task, not an executive summary --
  the prompt instructs the model to preserve named vulnerability classes, exact configuration/trigger
  names, and precise exploitation mechanisms verbatim rather than abstracting them into generic
  statements (e.g. naming a specific attack pattern and the exact trigger/config involved, not just
  "attackers abused X").
- Facts the platform can already verify — CVE IDs, KEV/EPSS status, severity, raw IOCs
  (hashes/IPs/domains/URLs), and MITRE ATT&CK technique IDs — are extracted or validated with this
  app's own proven regex/lookup/catalog logic, never trusted to the model's own recall. Any
  model-supplied ATT&CK technique ID is checked against this app's synced technique catalog and
  stripped if it doesn't match a real entry (with a same-catalog name-match recovery step for cases
  where the model swapped which field held the name vs. the ID). The model is only asked for the
  parts that genuinely require synthesis. Exotic IOC types with no reliable extraction path (mutexes,
  registry keys, scheduled tasks, certificates, etc.) are always reported empty rather than asking the
  model to invent them.
- Covers **all four severities**, including Low (widened from Critical/High/Medium-only -- Low was
  deliberately deferred at first, not dropped, precisely so it could be turned on later with no
  backfill step: unmatched Low articles were never marked processed, so the entire backlog picked up
  automatically the moment `ELIGIBLE_SEVERITIES` in `aiThreatSummaryJob.js` was widened). Within the
  eligible pool, candidates are processed Critical-first, then High, Medium, Low, newest-first within
  each tier -- so a high-priority article can't get stuck behind a large backlog of lower-priority ones.
- `server/aiThreatSummaryJob.js` runs once every 24h (not continuously), processing up to 20 vendor/CISA
  articles per run. The 24h cadence is persisted (`lastCycleAt` in the report store) so a backend
  restart mid-day doesn't reset the clock and trigger an extra run early. Reports persist to
  `server/.cache/ai-threat-summaries.json`, are never regenerated once produced, and are pruned once
  they're more than 24h old -- the tab is a rolling "today" view, not a growing archive.
- Generation speed is Groq's hosted inference (typically seconds per report, not minutes) rather than
  whatever this machine's own CPU/GPU can do locally.

## Environment variables

See [.env.example](.env.example) for the full list with links to get each free key. All of them are
read server-side only and never reach the browser bundle -- none are `VITE_`-prefixed.

## Behavior notes

- **Background sync, not client polling**: each connector refreshes on its own interval
  (`intervalMs` in its file) independent of any browser tab -- 5 min for NVD, 10-15 min for most IOC
  feeds (including every new source added in this round: Pulsedive, PhishTank, Emerging Threats,
  Spamhaus DROP and the CVE Program feed all sync every 15 min), hourly for AbuseIPDB (small daily
  quota), daily for EPSS (updates once/day), weekly for ATT&CK (a taxonomy, not telemetry). The
  frontend still polls every ~15 min for freshness, but that just reads the shared cache -- it
  doesn't trigger new upstream calls.
- **Retry/backoff**: every connector call goes through `withRetry` (exponential backoff, 2 retries)
  before being marked failed; a 401 (not configured) or 404 skips retries since those won't resolve
  by retrying.
- **Graceful degradation**: a failing source keeps its last-known-good cached data and reports the
  error via `/api/dashboard/health` -- it doesn't blank out or crash other sections.
- **CVE list cold-start fallback**: the above covers an already-synced source going down mid-session,
  but a server restart during an NVD outage has no cache to fall back on. For that specific case,
  `/api/dashboard/cves`'s default view falls back to CVE Program's (cve.org) own recently-reserved CVE
  ID list, enriched per-ID via CIRCL (see `server/lookups/cveFallback.js`) -- confirmed live this
  produces real, if less complete, records (no numeric CVSS score, since CIRCL doesn't expose one) until
  NVD's own sync succeeds, at which point the route switches back automatically. The response includes
  a `fallbackSource` field when this path is active, surfaced in the UI as a banner rather than silently
  passed off as normal NVD data.
- **EPSS lag**: confirmed live -- EPSS's daily snapshot lags NVD's newest publications by roughly a
  day, so CVEs published in the last ~24h will show `epssScore: null` until the next day's snapshot;
  this is normal (verified the join itself works correctly against older CVEs, e.g. Log4Shell/
  CVE-2021-44228 correctly returns a 0.99999 score), not a correlation bug.
- **CVE table**: search/severity/pagination for the *default* (unfiltered, first-page) view are
  served from cache; anything else is answered live from NVD (still through the same
  reverse-pagination fix as before -- NVD's date-range queries return oldest-first with no
  descending option, so "latest" means paging backward from the end of the range and reversing).

## Known limitations

- **Real bugs found by testing with live keys, not just reading docs** (same discipline that earlier
  caught the CVE vendor-extraction bug, the stale-pagination bug, and the search rate-limiting bug):
  - `.env` was never actually loaded by the backend -- Node has no built-in `.env` support, and only
    the old Vite dev-proxy (since removed) had env loading wired up. Every key silently did nothing
    until `dotenv` was added. Fixed in `server/index.js`.
  - URLHaus's recent-URLs endpoint now requires **GET**, not POST (POST returns
    `405 { query_status: "http_get_expected" }`) -- confirmed live once a real Auth-Key was
    configured to test against. Fixed in `server/connectors/urlhaus.js`.
  - ThreatFox's IOC timestamp field is `first_seen`, not `first_seen_utc` -- the wrong field name
    was `undefined` on every entry and crashed the connector. Fixed in `server/connectors/threatfox.js`.
  - AbuseIPDB's connector synced successfully but was never actually wired into the Threat Feed
    merge (`THREAT_FEED_IDS` in `server/routes/dashboard.js` was missing `"abuseipdb"`).
  - OpenPhish has no real per-item timestamp (everything is stamped "now" at sync time), so once
    OTX added 1500+ genuinely-timestamped IOCs, OpenPhish's fake-recent entries still crowded out
    every other source in a pure recency sort. Fixed by capping each source to its own most-recent
    N entries before merging (`PER_SOURCE_CAP` in `server/routes/dashboard.js`).
  - VirusTotal, GreyNoise and Shodan (IOC Search only) are still untested against live keys.
  - **PhishTank's anonymous bulk download is effectively broken**: confirmed live it now redirects to
    a signed CDN URL that 404s (returning a placeholder image, not JSON) for unregistered requests,
    and even key-holders are capped at 75 requests/3 days -- this source reports "not configured"
    until `PHISHTANK_API_KEY` is set, unlike OpenPhish/Feodo Tracker which really are keyless.
  - **Hybrid Analysis's old bulk `/api/v2/feed/latest` endpoint no longer exists** (confirmed live:
    404 "Requested URI - Not Found" even with a dummy key), so this source is a hash-only IOC Search
    lookup, not a bulk feed, unlike what the older public docs describe.
  - **Hybrid Analysis's `/api/v2/search/hash` endpoint is also gone, but only found out once a real
    key was configured**: a dummy key returned a merely-generic 403 ("incompatible with API v2"),
    which looked like "exists, just needs a real key" -- but a real, currently-issued key gets 410
    Gone ("deprecated in API version 2.35.0. Your API key is newer than the deprecation date"). The
    live replacement, confirmed with a real key, is `GET /api/v2/overview/{sha256}` -- but it only
    accepts SHA256 (the old endpoint took any hash type), so MD5/SHA1 searches now get a clear
    "unsupported" error instead of a raw upstream validation failure. Fixed in
    `server/lookups/hybridAnalysis.js`. This is exactly why dummy-key testing isn't a substitute for
    testing with a real one -- a generic auth error and a real deprecation error look identical from
    the outside.
  - **Pulsedive's `explore.php`/`info.php` endpoints work with no API key at all** (confirmed live
    against the real API) -- a free key only raises the anonymous rate limit, it's never required.
  - **Spamhaus's EDROP list was merged into DROP** (confirmed live: `edrop.txt` is now just a
    redirect note) -- only `drop.txt` is fetched.
  - **RSS titles with numeric HTML entities rendered literally** (e.g. Microsoft Security's `&#038;`
    for `&`) -- `server/lib/rss.js`'s entity decoder only handled the 5 named entities, not numeric
    (`&#38;`) or hex (`&#x26;`) character references. Fixed generically in the shared decoder, found
    while confirming the Microsoft Security feed live.
  - **Mandiant no longer has its own separate blog/feed** -- its research now publishes under Google
    Cloud's blog as "Google Threat Intelligence" (confirmed live: `mandiant.com/resources/blog`
    redirects into `cloud.google.com/security/mandiant`), so that's a single merged RSS source
    (`https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/`), not two.
  - **No feed exists scoped to just "Microsoft Threat Intelligence"/MSTIC** -- only the general
    Microsoft Security blog has a public RSS feed, so that source also carries non-threat-intel
    posts (product/compliance content mixed in with actual research).
- **GitHub Intel's content scan is bounded, not exhaustive**: confirmed live against
  `nomi-sec/PoC-in-GitHub` (a large PoC-aggregator repo) that its top-level README alone doesn't surface
  its per-CVE content, since that repo organizes detail as one file/dir per CVE rather than listing
  every CVE in the README. Added a path-based `CVE-\d{4}-\d+` filename pattern to catch that specific
  layout, but this remains a documented tradeoff, not a guarantee: only README + up to 10 files matching
  known rule/IOC/per-CVE filename patterns are fetched per repo (see `contentFetcher.js`), never a full
  clone -- so content organized in an unanticipated way can still be missed. This is a deliberate
  boundedness-over-completeness choice given GitHub's free-tier rate limits, not an oversight.
- **GitHub Intel's classification/extraction is regex/keyword-heuristic, not ML** -- same "best-effort,
  documented" caveat as the rest of this app's classification logic (country/motivation keyword lists in
  `attack.js`, malware-family matching in `correlate.js`). Confidence scores are weighted keyword-hit
  ratios, not calibrated probabilities.
- **GitHub Intel starts with 4 of the ~18 originally-considered categories** (Exploit PoC, Sigma Rules,
  YARA Rules, Malware) -- deliberately scoped down to validate the full discovery -> extraction ->
  correlation -> scoring pipeline against a small corpus (~150 repos) before fanning out query variety.
  Add more to `server/githubIntel/categories.js` once this set is confirmed working for your use case.
- **RansomWatch's underlying data has stopped updating** -- confirmed live: `posts.json`'s own commit
  history shows its last real data update was 2025-06-16 (the automated "cronbot" scraper appears to
  have died), despite the GitHub repo itself still existing and receiving unrelated commits since. Kept
  in this app anyway (it's free and still serves valid historical data that corroborates against the two
  actively-updating trackers), synced daily instead of every 30 min, and its label says so directly in
  Source Health rather than silently looking "online" with fresh-looking data.
- **vx-underground has no accessible free API**: confirmed live every path returns 403 Forbidden
  (Cloudflare/bot-protected) -- it's a browse-only sample/paper archive, not something with a
  programmatic interface, free or otherwise. Not integrated.
- **Social intelligence (Reddit, Mastodon, Pastebin) -- none feasible for free, keyless ingestion**,
  confirmed live:
  - **Reddit** (r/threatintel, r/netsec, r/blueteamsec): its feeds are **Atom**, not RSS 2.0 --
    `server/lib/rss.js` only understands `<item>`, the same reason Schneier on Security and The
    Register were excluded. Separately, 2 of the 3 subreddits returned `429 Too Many Requests` on
    the very first unauthenticated request, so it would be unreliable for scheduled polling even
    with an Atom parser.
  - **Mastodon (infosec.exchange)**: its tag RSS feeds (`/tags/malware.rss` etc.) return a valid
    but always-empty channel -- confirmed live across 8 different tags (`malware`, `cve`,
    `threatintel`, `phishing`, `dfir`, `infosec`, `exploit`, `apt`), all 0 items. Root cause:
    calling the equivalent public REST API directly (`/api/v1/timelines/tag/malware`) returns
    `{"error":"This method requires an authenticated user"}` -- this specific instance requires a
    registered account + access token even for public tag timelines, so it isn't truly keyless.
  - **Pastebin**: its scraping API returns `403 Forbidden ... VISIT pastebin.com/doc_scraping_api
    TO GET ACCESS!` -- a paid Pro-tier feature requiring IP whitelisting, not free. The public
    `/archive` page is a browsable HTML listing, not a feed meant to be scraped.
  
  None integrated. Revisit if a Mastodon access token or an Atom parser becomes worth the effort.
- **4 more security-vendor blogs checked, not added**, confirmed live:
  - **Secureworks CTU**: Secureworks was acquired by Sophos in 2025 -- every Secureworks blog/RSS
    URL now redirects straight into `sophos.com`, it's no longer a separate entity.
  - **Sophos X-Ops**: every `sophos.com`/`news.sophos.com` URL refused the connection outright
    (no HTTP response at all) from this environment -- looks like a WAF blocking the whole IP
    range rather than a missing feed, so this may work fine from a different network.
  - **Trend Micro Research**: no discoverable RSS feed -- its old FeedBurner URL
    (`feeds.trendmicro.com/Anti-MalwareBlog`) is dead, and its current research pages have no
    RSS auto-discovery link tag.
  - **Proofpoint Threat Insight**: no dedicated feed exists. The only public RSS
    (`proofpoint.com/us/rss.xml`) is a general newsroom/press-release feed -- confirmed live it's
    roughly half PR announcements (product launches, partnerships) mixed with real threat research,
    which would dilute signal rather than add it.
- **LeakIX** (`server/lookups/leakix.js`, IOC Search only -- IP/domain, no url/hash) requires a
  registered API key (confirmed live: 401 without one). Two live-confirmed quirks it's built around:
  - `/host/{ip}` can return **hundreds of service records for a busy/shared IP** (600 for 8.8.8.8
    alone, a 1.4MB response) -- summarized to counts + a few samples rather than returned raw.
  - A query with zero results returns **`204 No Content`**, not `200` with an empty array/object --
    `fetchJson()` (`server/lib/http.js`) previously had no 204 handling at all and would have thrown
    trying to parse the empty body; fixed there since it's a generically-useful fix, not LeakIX-specific.
- **Malpedia actor-slug matching is a guess, not a lookup**: `server/actorProfile.js#buildMalpediaMalware`
  guesses an actor's Malpedia slug by lowercasing its ATT&CK name/aliases and replacing spaces with
  underscores (confirmed live this matches Malpedia's real convention for "APT28" -> `apt28` and
  "Lazarus Group" -> `lazarus_group`), then checks that guess against Malpedia's own cached actor list.
  An actor whose Malpedia slug doesn't follow this convention will simply show no Malpedia data, not an
  error.
- **"ATT&CK Techniques Observed" and the technique tags on "Trending Malware"** come from a small
  curated static map (`server/data/malware-attack-map.json`), not a live feed -- there is no free
  source that tracks which techniques are trending in real time.
- **Threat actor / ransomware campaign coverage is ransomware groups only** -- no free bulk source
  covers APT/nation-state attribution.
- **GreyNoise, VirusTotal and Shodan** only ever answer IOC Search queries (their free tiers are
  single-indicator lookups) -- they never appear as bulk dashboard sections.
- **In-memory cache**: resets on process restart (an immediate resync follows). Not shared across
  multiple instances -- fine for a single-process deployment, would need Redis for horizontal scaling.
- **Detection rule coverage (`detectionRules` on Trending Malware) is a filename-based signal, not
  parsed rule content**: `server/connectors/detectionRules.js` indexes YARA-Rules/SigmaHQ file *paths*
  (e.g. `malware/RANSOM_Lockbit.yar`), then `server/correlate.js#detectionRulesFor` substring-matches
  a malware family name against those path segments. A rule whose filename doesn't mention the family
  by name (generic/behavioral rules, differently-spelled families) won't be found even if it would
  actually detect that malware -- this is "a rule that looks related exists", not a guarantee of
  coverage or a false-negative-free check.
- **CIRCL CVE Search (`server/lookups/circl.js`) is an NVD fallback only**, used solely when NVD
  doesn't have a record. Confirmed live its CVE Record v5 payload has no structured CVSS score --
  its `metrics` field is free-text (e.g. `{"content":{"other":"critical"}}`), not a numeric vector --
  so `cvssScore` stays `null` for CIRCL-sourced records rather than guessing a number, and `severity`
  is only set when that free text unambiguously names one of NVD's own bands.
- **Team Cymru (`server/lookups/teamCymru.js`) is DNS-based, not REST** -- IP-to-ASN and the Malware
  Hash Registry are both DNS TXT record zones (confirmed live via direct `nslookup`), queried with
  Node's `dns.resolveTxt`. A non-existent-domain DNS response means "not in the registry", not an
  error, and is treated as such rather than surfaced as a failure.
- **SANS ISC/DShield (`server/lookups/isc.js`) has no API-key mechanism for its query API at all** --
  confirmed live against the real endpoint and ISC's own docs ("Currently, we do not require
  authentication"). A registered account's API key on isc.sans.edu is for *submitting* honeypot/
  firewall logs, a different feature this dashboard doesn't use -- so this lookup is fully keyless,
  just sends a descriptive `User-Agent` per ISC's request. Also confirmed live that its `count`/
  `attacks` fields (recent honeypot-reported activity) are null for most IPs, including ones ISC's
  own "top attackers" list ranks highly -- `threatfeeds` (cross-referenced third-party blocklists)
  is the more reliably populated signal and drives the verdict.
- **3 national CERT RSS feeds evaluated, only 1 added**: JPCERT/CC's English feed is confirmed live
  (RSS 1.0/RDF using `<dc:date>` instead of `<pubDate>` -- `server/lib/rss.js` now falls back to it).
  ACSC (Australia)'s RSS endpoints connection-refused outright from this environment, the same
  WAF/IP-range-block signature as Sophos above. FBI/IC3's cyber-alerts RSS returned a Cloudflare
  bot-check challenge page (HTTP 403) instead of XML. Neither was added.
- **VulnCheck KEV, Exploit-DB and the detection-rule sync are untested against live keys/data beyond
  endpoint-shape verification** -- VulnCheck specifically returned `{"error":true,"errors":["unauthorized"]}`
  during verification (no real Community key was available), confirming the endpoint/auth-header shape
  but not a full authenticated response.
