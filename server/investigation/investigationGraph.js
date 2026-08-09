// Investigation Graph -- analyst-grade replacement for the old linear Pivot
// Chain (Threat Actor -> Campaign -> Malware -> ... one hop at a time).
// Every node type below can be the center of a query, and every edge is
// backed by a field this app already computes somewhere (entity stores,
// crossReference.js, cveProfile.js, correlate.js) -- same "no new
// correlation invented" discipline the old pivotChain.js (now deleted)
// established, just reshaped into a flat, per-edge-metadata graph instead of
// a nested per-type neighbor map, and extended to cover every entity type
// this app can meaningfully reason about.
//
// Email / fileName / processName / registryKey / userAgent have NO external
// reputation source anywhere in this app (see server/investigation/
// artifactModule.js) -- the only real signal for those types is "does this
// literal string already appear in this app's own ingested IOC/report data"
// via crossReferenceIndicator. url/hash get the same treatment (no
// urlModule/hashModule live-lookup integration here -- that's the Triage
// Console's job, not this graph's). ASN has no bulk "list all IPs on this
// ASN" data source anywhere (confirmed absent from every free API this app
// integrates) so it is exposed only as a leaf off an IP node showing the
// already-computed sibling-IP set, never as an independently-expandable
// node. Detection rules / hunting queries / AI reports / source articles are
// real but are attached as node metadata (for a detail panel), not modeled
// as separate graph nodes -- turning every citation into a canvas node would
// flood the graph with dozens of low-value nodes per entity.
import { getAllEntities as getActorEntities } from "../threatActorIntelligence.js";
import { getAllEntities as getCampaignEntities } from "../campaignIntelligence.js";
import { getAllEntities as getMalwareEntities } from "../malwareIntelligence.js";
import { getAllEntities as getDarkWebEntities } from "../darkWebIntelligence.js";
import { ransomwareCampaigns as getRansomwareCampaigns } from "../ransomwareCampaigns.js";
import { getAllReports as getAiReports, getReportById } from "../aiThreatSummaryStore.js";
import { buildCveProfile } from "../cveProfile.js";
import { matchVendorProductIndustries, classifyIndustryRelevance, INDUSTRY_TIER, INDUSTRY_TIER_RANK } from "../industryClassification.js";
import { getAllGithubRepos } from "../githubIntel/index.js";
import { crossReferenceIndicator } from "./crossReference.js";
import { resolveDnsRecords, reverseDns } from "../lib/dnsRecords.js";
import { getPassiveDns } from "../connectors/otx.js";
import { checkRipestatThrottled } from "./ipModule.js";
import { checkIndicator as checkCrtsh } from "../lookups/crtsh.js";
import { checkIndicator as checkRdap } from "../lookups/rdap.js";
import { detectionRulesFor, detectionRulesForCve, techniqueIdsForFamily, ATTACK_TACTICS_ORDER } from "../correlate.js";
import { buildEntityHuntingQueries } from "../huntingLibrary.js";
import { norm, findByNameOrAlias } from "./entityLookup.js";
import { resolveCanonicalAlias } from "./knownAliasGroups.js";
import * as cache from "../cache.js";

export const GRAPH_NODE_TYPES = [
  "actor", "campaign", "malware", "cve", "victim", "ip", "domain", "url", "hash",
  "email", "fileName", "processName", "registryKey", "userAgent", "attackTechnique", "country", "report", "industry",
];

// Entity-shaped node types eligible for the auto-expand orchestrator below
// (getExpandedGraph) -- deliberately excludes IOC/leaf types (ip, domain,
// url, hash, email, fileName, processName, registryKey, userAgent, asn,
// report, attackTechnique): several of those trigger live network calls
// (gatherIpOrDomain's DNS/RIPEstat/crt.sh/RDAP) that shouldn't fan out
// automatically, and the rest are cheap, already-rich leaves better left to
// deliberate click-to-expand than auto-fetched on every entity search.
const AUTO_EXPAND_TYPES = new Set(["actor", "campaign", "malware", "cve", "victim", "country", "industry"]);

const CROSS_REF_ONLY_TYPES = new Set(["url", "hash", "email", "fileName", "processName", "registryKey", "userAgent"]);

// Same-target edges with a DIFFERENT relationship string are conflicting
// claims about the same entity (e.g. one path says "attributed actor", a
// separate path says a different actor "breached by" the same victim) --
// these used to be silently dropped, keeping only whichever happened to be
// found first. Now the first one found is kept and every later conflicting
// claim is preserved on its `conflictsWith[]` instead of discarded. True
// duplicates (identical relationship string to the same target) still
// collapse silently, since those aren't a disagreement.
function dedupeEdges(edges) {
  const kept = new Map(); // `${targetType}:${targetKey}` -> kept edge
  const out = [];
  for (const e of edges) {
    const k = `${e.targetType}:${norm(e.targetKey)}`;
    const existing = kept.get(k);
    if (!existing) {
      kept.set(k, e);
      out.push(e);
      continue;
    }
    if (existing.relationship === e.relationship) continue;
    existing.conflictsWith.push({ relationship: e.relationship, why: e.why, source: e.sources[0] ?? "Unknown" });
  }
  return out;
}

// Claim-strength classification for a relationship TYPE, independent of
// which code path produced it -- distinct from classifyConfidence()/
// scoreConfidence() above, which classify HOW a fact was obtained
// (explicit field vs. live lookup vs. cross-reference join). This instead
// classifies WHAT KIND of claim it semantically is, so e.g. "shares ASN
// with" (infrastructure co-location) can never be read the same way as
// "attributed actor" (an attribution claim) just because both happen to be
// backed by a live lookup or a cross-reference join. `impliesColocationOnly`
// is the guardrail that stops shared hosting/ASN evidence -- including
// major cloud/CDN providers -- from ever being treated as attribution or
// malicious association on its own.
function semantics(claimStrength, opts = {}) {
  return { claimStrength, impliesAttribution: opts.impliesAttribution ?? false, impliesColocationOnly: opts.impliesColocationOnly ?? false, guardrailNote: opts.guardrailNote ?? null };
}
const DEFAULT_SEMANTICS = semantics("cross-reference");
const RELATIONSHIP_SEMANTICS = {
  "uses malware": semantics("explicit-record", { impliesAttribution: true }),
  "used by": semantics("explicit-record", { impliesAttribution: true }),
  exploits: semantics("explicit-record", { impliesAttribution: true }),
  "exploits this CVE": semantics("explicit-record", { impliesAttribution: true }),
  "originates from": semantics("explicit-record", { impliesAttribution: true }),
  "originates from this country": semantics("explicit-record", { impliesAttribution: true }),
  "uses technique": semantics("explicit-record", { impliesAttribution: true }),
  "implements technique": semantics("explicit-record"),
  "runs campaign": semantics("explicit-record", { impliesAttribution: true }),
  "run by": semantics("explicit-record", { impliesAttribution: true }),
  "deploys malware": semantics("explicit-record", { impliesAttribution: true }),
  "deployed in": semantics("explicit-record", { impliesAttribution: true }),
  "hosts infrastructure": semantics("explicit-record", { guardrailNote: "Recorded as hosting infrastructure for this malware family -- does not by itself establish that the malware's operators control or own this IP (hosts ≠ controls)." }),
  "resolves to": semantics("reverse-lookup"),
  "distributes via": semantics("explicit-record", { guardrailNote: "Recorded as a distribution URL for this malware family -- does not by itself establish attacker control of the underlying hosting infrastructure." }),
  sample: semantics("explicit-record"),
  "breached victim": semantics("explicit-record", { impliesAttribution: true }),
  "breached by": semantics("explicit-record", { impliesAttribution: true }),
  "linked actor": semantics("explicit-record", { impliesAttribution: true }),
  "linked to victim": semantics("cross-reference", { impliesAttribution: true }),
  "malware used": semantics("explicit-record"),
  "exploited via": semantics("explicit-record"),
  "covers CVE": semantics("explicit-record"),
  "mentions indicator": semantics("explicit-record"),
  "covered in report": semantics("explicit-record"),
  "covers actor": semantics("cross-reference", { impliesAttribution: true, guardrailNote: "May be a direct citation or an unresolved name mention not yet matched to a canonical entity -- see this edge's own reasoning/confidence for which." }),
  "covers malware": semantics("cross-reference", { guardrailNote: "May be a direct citation or an unresolved name mention not yet matched to a canonical entity -- see this edge's own reasoning/confidence for which." }),
  "covers campaign": semantics("cross-reference", { guardrailNote: "May be a direct citation or an unresolved name mention not yet matched to a canonical entity -- see this edge's own reasoning/confidence for which." }),
  "linked malware family": semantics("cross-reference", { guardrailNote: "Inferred by matching a shared indicator against this platform's own malware-family records -- not a first-party citation." }),
  "classified as malware family": semantics("attribution", { impliesAttribution: true, guardrailNote: "A live sandbox/multi-engine detection classified this exact file into this family -- a real, first-party classification, but the family-name match itself is a best-effort text match against this platform's own tracked entity names, not a guaranteed-exact vendor taxonomy alignment." }),
  "attributed actor": semantics("attribution", { impliesAttribution: true, guardrailNote: "Inferred transitively (indicator → malware family → actor known to use that family) -- does not by itself confirm this specific actor controls this specific indicator." }),
  "seen in campaign": semantics("cross-reference", { impliesAttribution: true, guardrailNote: "Inferred transitively via a shared malware family -- not a first-party citation of this specific indicator." }),
  "seen exploiting this CVE": semantics("cross-reference", { guardrailNote: "Inferred transitively via a shared malware family, not a first-party CVE-to-indicator citation." }),
  "related URL": semantics("cross-reference"),
  "related sample": semantics("cross-reference"),
  "reverse DNS resolves to": semantics("reverse-lookup"),
  "passive DNS resolution": semantics("reverse-lookup"),
  "shares ASN with": semantics("infrastructure-colocation", {
    impliesAttribution: false,
    impliesColocationOnly: true,
    guardrailNote: "Shared ASN/hosting provider does not establish attribution or malicious association on its own -- shared hosting, including major cloud/CDN providers (Cloudflare, AWS, Azure, GCP, Akamai, Fastly, DigitalOcean, Oracle Cloud), is common among entirely unrelated tenants.",
  }),
  "shares SSL/TLS certificate with": semantics("reverse-lookup", { guardrailNote: "A shared certificate indicates shared infrastructure configuration, not confirmed common ownership or attacker control." }),
  "targets victims in": semantics("algorithmic-guess"),
  "targets victims here": semantics("algorithmic-guess"),
  "targets industry": semantics("algorithmic-guess"),
  "targeted by": semantics("algorithmic-guess"),
  "technology relevant to industry": semantics("algorithmic-guess", {
    guardrailNote: "This CVE's affected vendor/product is commonly used in this industry -- does not by itself establish that this specific industry was targeted or exploited.",
  }),
  "potentially exposes industry": semantics("algorithmic-guess", {
    guardrailNote: "This CVE's affected vendor/product is broadly used across many sectors, including this one -- a much weaker signal than targeting, shown only as possible exposure.",
  }),
  "technology relevant to": semantics("algorithmic-guess", {
    guardrailNote: "This entity's own coverage mentions a product/vendor commonly used in this industry -- does not by itself establish that this industry was targeted.",
  }),
  "potentially exposes": semantics("algorithmic-guess", {
    guardrailNote: "This entity's own coverage mentions a product/vendor broadly used across many sectors, including this one -- a much weaker signal than targeting.",
  }),
};
function semanticsFor(relationship) {
  return RELATIONSHIP_SEMANTICS[relationship] ?? DEFAULT_SEMANTICS;
}

// Confidence is derived entirely from provenance this app already records in
// `linkBasis` strings -- an explicit stored field on either side of a
// relationship ("Direct"/"Reverse") is highest, something inferred via a
// shared value or a live external source ("Cross-reference"/"Indirect"/
// "Live") is mid-tier, and an algorithmic guess or a not-yet-canonicalized
// name match ("Heuristic"/"Report-only") is lowest. The third element of
// each rule is that tier's numeric base score (see scoreConfidence below) --
// nothing here is a new judgment call, it's a fixed mapping over labels the
// underlying gather functions already produce.
const CONFIDENCE_RULES = [
  [/^Direct:/, "High", 72],
  [/^Reverse:/, "High", 72],
  [/^Cross-reference:/, "Medium", 52],
  [/^Indirect:/, "Medium", 50],
  [/^Live:/, "Medium", 55],
  [/^Heuristic:/, "Low", 30],
  [/^Report-only:/, "Low", 25],
];
const DEFAULT_CONFIDENCE_RULE = [null, "Low", 25];
function confidenceRule(linkBasis) {
  return CONFIDENCE_RULES.find(([re]) => re.test(linkBasis)) ?? DEFAULT_CONFIDENCE_RULE;
}
function classifyConfidence(linkBasis) {
  return confidenceRule(linkBasis)[1];
}

/**
 * Numeric 0-100 confidence underneath the High/Medium/Low badge above --
 * still purely derived from real facts already on the edge, never a new
 * judgment call. Base score comes from the same provenance tier
 * classifyConfidence() maps; a real (not fabricated) supportingReportCount
 * and a real distinct source count each add a small, capped bonus; a
 * relationship confirmed recently (lastSeen within the last 90 days) gets a
 * small recency bonus over a stale or unknown one.
 */
function scoreConfidence(linkBasis, extra = {}) {
  const [, , base] = confidenceRule(linkBasis);
  let score = base;
  if (typeof extra.supportingReportCount === "number") score += Math.min(20, extra.supportingReportCount * 4);
  if (Array.isArray(extra.sources)) score += Math.min(10, Math.max(0, extra.sources.length - 1) * 5);
  if (extra.lastSeen) {
    const days = (Date.now() - new Date(extra.lastSeen).getTime()) / (24 * 60 * 60 * 1000);
    if (days <= 30) score += 6;
    else if (days <= 90) score += 3;
  }
  return Math.max(0, Math.min(100, Math.round(score)));
}

const SOURCE_PATTERNS = [
  [/ATT&CK/i, "MITRE ATT&CK"],
  [/malware\.iocs|articleIocs/i, "Malware Intelligence store"],
  [/actor\.(malwareUsed|cveExploited|country|techniqueIds|targetedCountries)/i, "Threat Actor Intelligence store"],
  [/campaign\.\w|campaignIds/i, "Campaign Intelligence store"],
  [/dark-web finding targetedCountries/i, "Dark Web Intelligence store"],
  [/AbuseIPDB/i, "AbuseIPDB"],
  [/crt\.sh/i, "crt.sh certificate transparency"],
  [/RDAP/i, "RDAP (WHOIS)"],
  [/passive DNS/i, "OTX Passive DNS"],
  [/reverse DNS/i, "Reverse DNS (PTR)"],
  [/DNS A\/AAAA/i, "DNS resolution"],
  [/report\./i, "AI Summarization report"],
  [/ransomware/i, "Ransomware leak-site tracker"],
  [/dark-web/i, "Dark Web Intelligence store"],
  [/RIPEstat/i, "RIPEstat"],
  [/own (?:prior )?ioc/i, "This app's own ingested IOC data"],
];
/** `overlapSources` (real distinct article-source names from articleOverlapDetail) are folded in alongside the technical source label, deduped -- so an edge backed by both a store field AND independently corroborating reports shows every real source, not just one. */
function sourcesFor(linkBasis, extra = {}) {
  const hit = SOURCE_PATTERNS.find(([re]) => re.test(linkBasis));
  const base = hit ? hit[1] : "This app's own correlation";
  const overlap = Array.isArray(extra.overlapSources) ? extra.overlapSources : [];
  return Array.from(new Set([base, ...overlap]));
}

// Plain-English rendering of the same provenance categories classifyConfidence()
// already classifies -- the analyst-facing counterpart to the technical
// linkBasis label (kept as `why`, now a tooltip rather than the primary text).
const REASONING_TEMPLATES = [
  [/^Direct:/, "Directly recorded in this platform's own tracked data"],
  [/^Reverse:/, "Directly recorded in this platform's own tracked data (reverse lookup)"],
  [/^Cross-reference:/, "Discovered by cross-referencing a shared indicator across this platform's own tracked malware data"],
  [/^Indirect:/, "Inferred from a shared value in this platform's own tracked data"],
  [/^Live:/, "Confirmed via a live external lookup at investigation time"],
  [/^Heuristic:/, "An algorithmic best-guess match, not an explicit citation"],
  [/^Report-only:/, "Named in a report but not yet matched to a canonical entity in this app"],
];
function baseReasoning(linkBasis) {
  return REASONING_TEMPLATES.find(([re]) => re.test(linkBasis))?.[1] ?? "Derived from this platform's own correlation";
}
/**
 * Analyst-readable sentence for the edge -- e.g. "Directly recorded in this
 * platform's own tracked data. Observed together in 14 independent
 * intelligence reports including Microsoft, Mandiant, CISA." Every number
 * and name here comes straight from articleOverlapDetail()'s real,
 * pre-computed overlap -- never estimated or invented.
 */
function buildReasoning(linkBasis, extra = {}) {
  const parts = [baseReasoning(linkBasis)];
  if (typeof extra.supportingReportCount === "number" && extra.supportingReportCount > 0) {
    const names = Array.isArray(extra.overlapSources) && extra.overlapSources.length > 0 ? ` including ${extra.overlapSources.join(", ")}` : "";
    parts.push(`Observed together in ${extra.supportingReportCount} independent intelligence report${extra.supportingReportCount === 1 ? "" : "s"}${names}`);
  }
  return `${parts.join(". ")}.`;
}

/** Real, computable per-edge "supporting reports" -- the intersection of two entities' own article lists by link, plus up to 3 real distinct article-source names from that overlap (never invented). Returns {count: null, sources: []} (not 0) when not meaningfully computable, so the UI can render "not tracked" instead of implying zero evidence. */
function articleOverlapDetail(a, b) {
  if (!a?.articles?.length || !b?.articles?.length) return { count: null, sources: [] };
  const links = new Set(b.articles.map((x) => x.link));
  const overlapping = a.articles.filter((x) => links.has(x.link));
  const sources = Array.from(new Set(overlapping.map((x) => x.source).filter(Boolean))).slice(0, 3);
  return { count: overlapping.length, sources };
}
/** Spreads an articleOverlapDetail() result into the {supportingReportCount, overlapSources} shape edge()'s `extra` expects. */
function overlapExtra(detail) {
  return { supportingReportCount: detail.count, overlapSources: detail.sources };
}

function edge(targetType, targetKey, targetLabel, relationship, linkBasis, extra = {}) {
  const supportingReportCount = extra.supportingReportCount ?? null;
  const overlapSources = extra.overlapSources ?? [];
  const sources = sourcesFor(linkBasis, { overlapSources });
  return {
    targetType,
    targetKey,
    targetLabel,
    relationship,
    why: linkBasis,
    reasoning: buildReasoning(linkBasis, { supportingReportCount, overlapSources }),
    confidence: classifyConfidence(linkBasis),
    confidenceScore: scoreConfidence(linkBasis, { supportingReportCount, sources, lastSeen: extra.lastSeen ?? null }),
    firstSeen: extra.firstSeen ?? null,
    lastSeen: extra.lastSeen ?? null,
    supportingReportCount,
    sources,
    semantics: semanticsFor(relationship),
    conflictsWith: [],
  };
}

/** Detection rules + hunting queries + source articles for one canonical entity -- real citations, attached as node metadata for the detail panel rather than as separate graph nodes (see file header). */
function enrichmentFor(entity, kind) {
  const ruleIndex = cache.getEntry("detection-rules").data?.index ?? [];
  const huntingItems = buildEntityHuntingQueries(getMalwareEntities(), getActorEntities(), ruleIndex).filter((item) => item.reportId === `entity::${kind}::${entity.id}`);
  return {
    detectionRules: detectionRulesFor(entity.name, ruleIndex),
    huntingQueries: huntingItems.map((i) => ({ platform: i.platformLabel, query: i.query, source: i.articleSource, sourceUrl: i.articleLink })),
    sourceArticles: (entity.articles ?? []).slice(0, 10),
  };
}

/**
 * Same real citations as enrichmentFor above, but for a raw IOC (ip/domain/
 * url/hash/artifact) rather than a canonical entity -- keyed off the
 * malware family(ies) crossReferenceIndicator() already matched this value
 * to, since a Sigma/YARA rule or hunting query is never written against a
 * literal indicator value, only against the family it belongs to. Without
 * this, "what should Detection Engineering deploy" had no answer for any
 * IOC search, even when the matched family has real public rules.
 */
function detectionAndHuntingForFamilies(familyNames) {
  if (!familyNames.length) return { detectionRules: [], huntingQueries: [] };
  const ruleIndex = cache.getEntry("detection-rules").data?.index ?? [];

  const seenRules = new Set();
  const detectionRules = [];
  for (const name of familyNames) {
    for (const rule of detectionRulesFor(name, ruleIndex)) {
      const k = `${rule.label}:${rule.path}`;
      if (seenRules.has(k)) continue;
      seenRules.add(k);
      detectionRules.push(rule);
    }
  }

  const matchedEntities = getMalwareEntities().filter((m) => familyNames.some((n) => norm(n) === norm(m.name)));
  const matchedIds = new Set(matchedEntities.map((m) => `entity::malware::${m.id}`));
  const huntingItems = buildEntityHuntingQueries(matchedEntities, [], ruleIndex).filter((item) => matchedIds.has(item.reportId));
  const huntingQueries = huntingItems.map((i) => ({ platform: i.platformLabel, query: i.query, source: i.articleSource, sourceUrl: i.articleLink }));

  return { detectionRules, huntingQueries };
}

// --- ATT&CK technique summaries (metadata, not graph edges) ---------------
//
// MITRE ATT&CK techniques are real, sourced intelligence -- but they answer
// "HOW does this threat operate" (behavioral/analytical context), not "WHAT
// is this threat connected to" (the primary graph's own job). A single actor
// or malware family can carry 30-50+ technique IDs, which used to be pushed
// into the SAME edge list as campaigns/malware/victims/infrastructure --
// completely dominating the canvas by node count and pushing the actual
// operational relationships (campaigns, victims, infrastructure) out of
// view. Techniques are now attached as structured node metadata instead
// (tactic-grouped, same data, just not graph nodes/edges), rendered in a
// dedicated "MITRE ATT&CK Activity" panel by the frontend detail view
// instead of cluttering the canvas. See entityCorrelation.js#buildAttackTechniques
// for the equivalent, independently-computed dossier-level rollup used by
// EntitySections.tsx's own ATT&CK section for entity searches.
function attackTechniqueSummaries(techniqueIds, attackIndex) {
  const tacticRank = new Map(ATTACK_TACTICS_ORDER.map((t, i) => [t, i]));
  return (techniqueIds ?? [])
    .map((id) => {
      const t = attackIndex.find((x) => x.id === id);
      return { id, name: t?.name ?? id, tactic: t?.tactic ?? null };
    })
    .sort((a, b) => (tacticRank.get(a.tactic ?? "") ?? 99) - (tacticRank.get(b.tactic ?? "") ?? 99));
}

// Per-value "when was this most recently confirmed" for an entity's own
// targetedIndustries/targetedCountries -- scans the SAME per-article
// industries/countries annotations entityCorrelation.js#buildRecentActivity
// reads (see threatActorIntelligence.js/campaignIntelligence.js's
// upsertMention), so a "targets industry"/"targets victims in" edge carries
// a real lastSeen instead of none at all. Without this, these two edge
// types were the only ones in this whole file with no recency signal --
// scoreConfidence()'s existing lastSeen<=30/90-day bonus (and the UI's own
// first/last-seen display) silently never applied to them, so a value
// confirmed yesterday and one confirmed three years ago looked identical.
function valueRecencyMap(articles, field) {
  const map = new Map();
  for (const a of articles ?? []) {
    for (const v of a[field] ?? []) {
      const existing = map.get(v);
      if (!existing || new Date(a.publishedDate) > new Date(existing)) map.set(v, a.publishedDate);
    }
  }
  return map;
}

// Per-industry strongest tier across an entity's whole article history --
// entity.targetedIndustries itself is stored as a flat, tier-less name list
// (see threatActorIntelligence.js/campaignIntelligence.js's upsertMention),
// so this re-derives DIRECT vs TECHNOLOGY_RELEVANT vs POTENTIALLY_EXPOSED
// per value the same way valueRecencyMap re-derives lastSeen: by scanning
// each contributing article's own title through the classification engine
// again and keeping the strongest tier seen. This is what makes a "targets
// industry" edge (explicit text) visibly different from a "technology
// relevant to industry" edge (a product/vendor mention only) instead of
// both collapsing into one flat relationship label.
function industryTierMap(articles) {
  const map = new Map();
  for (const a of articles ?? []) {
    for (const hit of classifyIndustryRelevance(a.title)) {
      const existing = map.get(hit.industry);
      if (!existing || INDUSTRY_TIER_RANK[hit.tier] > INDUSTRY_TIER_RANK[existing]) map.set(hit.industry, hit.tier);
    }
  }
  return map;
}

function industryEdgeRelationship(tier) {
  if (tier === INDUSTRY_TIER.DIRECT) return "targets industry";
  if (tier === INDUSTRY_TIER.TECHNOLOGY_RELEVANT) return "technology relevant to industry";
  return "potentially exposes industry";
}

// --- Actor ---------------------------------------------------------------

function gatherActor(key) {
  const canonical = resolveCanonicalAlias(key);
  const entity = findByNameOrAlias(getActorEntities(), canonical ?? key);
  const edges = [];
  let attackTechniques = [];
  if (entity) {
    const names = new Set([norm(entity.name), ...entity.aliases.map(norm)]);

    for (const name of entity.malwareUsed) {
      const target = findByNameOrAlias(getMalwareEntities(), name);
      edges.push(edge("malware", name, name, "uses malware", "Direct: actor.malwareUsed", overlapExtra(articleOverlapDetail(entity, target))));
    }
    for (const id of entity.cveExploited) edges.push(edge("cve", id, id, "exploits", "Direct: actor.cveExploited"));
    if (entity.country) edges.push(edge("country", entity.country, entity.country, "originates from", "Direct: actor.country (ATT&CK)"));
    const industryRecency = valueRecencyMap(entity.articles, "industries");
    const countryRecency = valueRecencyMap(entity.articles, "countries");
    const industryTiers = industryTierMap(entity.articles);
    for (const c of entity.targetedCountries) edges.push(edge("country", c, c, "targets victims in", "Indirect: actor.targetedCountries (news text match)", { lastSeen: countryRecency.get(c) ?? null }));
    for (const i of entity.targetedIndustries ?? []) {
      const tier = industryTiers.get(i) ?? INDUSTRY_TIER.DIRECT;
      const basis = tier === INDUSTRY_TIER.DIRECT ? "Indirect: actor.targetedIndustries (explicit news text match)" : "Indirect: actor.targetedIndustries (technology/vendor signal, not an explicit sector claim)";
      edges.push(edge("industry", i, i, industryEdgeRelationship(tier), basis, { lastSeen: industryRecency.get(i) ?? null }));
    }
    attackTechniques = attackTechniqueSummaries(entity.techniqueIds, cache.getEntry("attack").data?.techniques ?? []);

    for (const c of getCampaignEntities()) {
      if ((c.associatedActors ?? []).some((a) => names.has(norm(a)))) {
        edges.push(edge("campaign", c.name, c.name, "runs campaign", "Reverse: campaign.associatedActors", overlapExtra(articleOverlapDetail(entity, c))));
      }
    }
    for (const r of getRansomwareCampaigns()) {
      if (names.has(norm(r.group))) edges.push(edge("victim", r.victim, r.victim, "breached victim", "Direct: ransomware disclosure group match", { firstSeen: r.discoveredDate, lastSeen: r.discoveredDate }));
    }
    for (const d of getDarkWebEntities()) {
      if ((d.associatedActors ?? []).some((a) => names.has(norm(a)))) {
        edges.push(edge("victim", d.victimOrg ?? d.name, d.victimOrg ?? d.name, "linked to victim", "Reverse: dark-web finding associatedActors"));
      }
    }
  }

  return {
    node: {
      type: "actor",
      id: entity?.id ?? key,
      label: entity?.name ?? key,
      summary: entity?.description ?? null,
      found: Boolean(entity),
      metadata: entity
        ? { aliases: entity.aliases, actorType: entity.type, country: entity.country, activeSince: entity.activeSince, verified: entity.verified, mentionCount: entity.mentionCount, attackTechniques, ...enrichmentFor(entity, "actor") }
        : null,
    },
    edges: dedupeEdges(edges),
    unavailableRelationships: [
      { relationshipType: "ip", reason: "No source links a threat actor directly to specific IP infrastructure -- pivot via a malware family or campaign instead." },
      { relationshipType: "domain", reason: "No source links a threat actor directly to specific domain infrastructure -- pivot via a malware family or campaign instead." },
    ],
  };
}

// --- Campaign --------------------------------------------------------------

function gatherCampaign(key) {
  const canonical = resolveCanonicalAlias(key);
  const entity = findByNameOrAlias(getCampaignEntities(), canonical ?? key);
  const edges = [];
  if (entity) {
    const actorNames = new Set(entity.associatedActors.map(norm));
    for (const name of entity.associatedActors) {
      const target = findByNameOrAlias(getActorEntities(), name);
      edges.push(edge("actor", name, name, "run by", "Direct: campaign.associatedActors", overlapExtra(articleOverlapDetail(entity, target))));
    }
    for (const name of entity.associatedMalware) {
      const target = findByNameOrAlias(getMalwareEntities(), name);
      edges.push(edge("malware", name, name, "deploys malware", "Direct: campaign.associatedMalware", overlapExtra(articleOverlapDetail(entity, target))));
    }
    for (const id of entity.cveExploited) edges.push(edge("cve", id, id, "exploits", "Direct: campaign.cveExploited"));
    const industryRecency = valueRecencyMap(entity.articles, "industries");
    const countryRecency = valueRecencyMap(entity.articles, "countries");
    const industryTiers = industryTierMap(entity.articles);
    for (const c of entity.targetedCountries) edges.push(edge("country", c, c, "targets victims in", "Indirect: campaign.targetedCountries (news text match)", { lastSeen: countryRecency.get(c) ?? null }));
    for (const i of entity.targetedIndustries ?? []) {
      const tier = industryTiers.get(i) ?? INDUSTRY_TIER.DIRECT;
      const basis = tier === INDUSTRY_TIER.DIRECT ? "Indirect: campaign.targetedIndustries (explicit news text match)" : "Indirect: campaign.targetedIndustries (technology/vendor signal, not an explicit sector claim)";
      edges.push(edge("industry", i, i, industryEdgeRelationship(tier), basis, { lastSeen: industryRecency.get(i) ?? null }));
    }

    for (const r of getRansomwareCampaigns()) {
      if (actorNames.has(norm(r.group))) edges.push(edge("victim", r.victim, r.victim, "breached victim", "Indirect: via a shared actor in campaign.associatedActors", { firstSeen: r.discoveredDate, lastSeen: r.discoveredDate }));
    }
    for (const d of getDarkWebEntities()) {
      if ((d.associatedActors ?? []).some((a) => actorNames.has(norm(a))) || (d.associatedMalware ?? []).some((m) => entity.associatedMalware.map(norm).includes(norm(m)))) {
        edges.push(edge("victim", d.victimOrg ?? d.name, d.victimOrg ?? d.name, "linked to victim", "Indirect: via a shared actor or malware family"));
      }
    }
  }

  return {
    node: {
      type: "campaign",
      id: entity?.id ?? key,
      label: entity?.name ?? key,
      summary: entity?.description ?? null,
      found: Boolean(entity),
      metadata: entity ? { aliases: entity.aliases, verified: entity.verified, mentionCount: entity.mentionCount, targetedIndustries: entity.targetedIndustries, sourceArticles: (entity.articles ?? []).slice(0, 10) } : null,
    },
    edges: dedupeEdges(edges),
    unavailableRelationships: [{ relationshipType: "attackTechnique", reason: "Campaign entities in this app carry no ATT&CK technique field -- no source links a campaign directly to a specific technique. Pivot via an associated actor or malware family instead." }],
  };
}

// --- Malware ---------------------------------------------------------------

function malwareIndicatorEdges(entity) {
  const edges = [];
  for (const ioc of [...(entity.iocs ?? []), ...(entity.articleIocs ?? [])]) {
    if (ioc.indicatorType === "ip") edges.push(edge("ip", ioc.indicator, ioc.indicator, "hosts infrastructure", "Direct: malware.iocs / articleIocs", { firstSeen: ioc.firstSeen ?? null }));
    else if (ioc.indicatorType === "domain") edges.push(edge("domain", ioc.indicator, ioc.indicator, "resolves to", "Direct: malware.iocs / articleIocs", { firstSeen: ioc.firstSeen ?? null }));
    else if (ioc.indicatorType === "url") edges.push(edge("url", ioc.indicator, ioc.indicator, "distributes via", "Direct: malware.iocs / articleIocs", { firstSeen: ioc.firstSeen ?? null }));
    else if (ioc.indicatorType === "hash") edges.push(edge("hash", ioc.indicator, ioc.indicator, "sample", "Direct: malware.iocs / articleIocs", { firstSeen: ioc.firstSeen ?? null }));
  }
  return edges;
}

function gatherMalware(key) {
  const canonical = resolveCanonicalAlias(key);
  const entity = findByNameOrAlias(getMalwareEntities(), canonical ?? key);
  const edges = [];
  let attackTechniques = [];
  if (entity) {
    edges.push(...malwareIndicatorEdges(entity));
    const names = new Set([norm(entity.name), ...entity.aliases.map(norm)]);
    for (const a of getActorEntities()) {
      if ((a.malwareUsed ?? []).some((m) => names.has(norm(m)))) edges.push(edge("actor", a.name, a.name, "used by", "Reverse: actor.malwareUsed", overlapExtra(articleOverlapDetail(entity, a))));
    }
    for (const c of getCampaignEntities()) {
      if ((c.associatedMalware ?? []).some((m) => names.has(norm(m)))) edges.push(edge("campaign", c.name, c.name, "deployed in", "Reverse: campaign.associatedMalware", overlapExtra(articleOverlapDetail(entity, c))));
    }
    const attackData = cache.getEntry("attack").data;
    attackTechniques = attackTechniqueSummaries(techniqueIdsForFamily(entity.name, attackData?.software ?? []), attackData?.techniques ?? []);

    // Victims -- dark-web findings can name a malware family directly;
    // ransomware disclosure records only ever carry the actor group, never a
    // malware family, so that path goes through the actor(s) already found
    // above to use this family.
    const usingActorNames = new Set(getActorEntities().filter((a) => (a.malwareUsed ?? []).some((m) => names.has(norm(m)))).map((a) => norm(a.name)));
    for (const r of getRansomwareCampaigns()) {
      if (usingActorNames.has(norm(r.group))) edges.push(edge("victim", r.victim, r.victim, "breached victim", "Indirect: via an actor known to use this malware family", { firstSeen: r.discoveredDate, lastSeen: r.discoveredDate }));
    }
    for (const d of getDarkWebEntities()) {
      if ((d.associatedMalware ?? []).some((m) => names.has(norm(m)))) edges.push(edge("victim", d.victimOrg ?? d.name, d.victimOrg ?? d.name, "linked to victim", "Direct: dark-web finding associatedMalware"));
    }
  }

  return {
    node: {
      type: "malware",
      id: entity?.id ?? key,
      label: entity?.name ?? key,
      summary: entity?.description ?? null,
      found: Boolean(entity),
      metadata: entity ? { aliases: entity.aliases, verified: entity.verified, iocSightings: entity.iocSightings, mentionCount: entity.mentionCount, attackTechniques, ...enrichmentFor(entity, "malware") } : null,
    },
    edges: dedupeEdges(edges),
    unavailableRelationships: [{ relationshipType: "cve", reason: "Malware entities in this app carry no CVE field -- no source links a malware family directly to a CVE." }],
  };
}

// --- CVE ---------------------------------------------------------------

function gatherCve(key) {
  const cveId = key.trim().toUpperCase();
  const profile = buildCveProfile(cveId, {
    attackData: cache.getEntry("attack").data,
    newsItems: cache.getEntry("news").data?.items ?? [],
    githubRepos: getAllGithubRepos(),
    exploitIndex: cache.getEntry("exploitdb").data?.cveIndex,
  });

  // AFFECTED TECHNOLOGY -> INDUSTRY signal (see server/industryClassification.js):
  // this CVE's own vendor/product (already parsed by the NVD connector, see
  // server/lib/cpe.js) mapped through the same technology-category engine
  // every other industry-facing feature uses -- this is what lets a CVE
  // surface industry relevance without any source ever naming a sector
  // explicitly (the literal "Atlassian Rovo" gap this engine was built to
  // close). Looked up from the cached last-30-days NVD pool only (no live
  // fetch inside graph gathering) -- a CVE outside that window simply gets
  // no technology-derived industry edge, same "don't fabricate what isn't
  // cached" discipline as the rest of this function.
  const nvdRecord = (cache.getEntry("nvd").data?.latestCves?.records ?? []).find((r) => norm(r.id) === norm(cveId));
  const industryHits =
    nvdRecord && nvdRecord.vendor !== "Unknown" ? matchVendorProductIndustries(nvdRecord.vendor, nvdRecord.product) : [];

  const edges = [
    ...profile.relatedActors.map((a) => edge("actor", a.name, a.name, "exploits this CVE", "Reverse: ATT&CK citation (group.cveIds / citing campaign / citing software)")),
    ...profile.relatedMalware.map((name) => edge("malware", name, name, "exploits this CVE", "Reverse: ATT&CK citation (software.cveIds)")),
    ...profile.relatedCampaigns.map((c) => edge("campaign", c.name, c.name, "exploits this CVE", "Reverse: ATT&CK citation (campaign.cveIds)")),
    ...industryHits.map((hit) =>
      edge(
        "industry",
        hit.industry,
        hit.industry,
        hit.tier === INDUSTRY_TIER.TECHNOLOGY_RELEVANT ? "technology relevant to industry" : "potentially exposes industry",
        `Indirect: ${nvdRecord.vendor} ${nvdRecord.product} (${hit.category}) -- affected technology, not a source-confirmed sector target`,
      ),
    ),
  ];
  for (const ioc of profile.relatedIocs) {
    if (ioc.indicatorType === "ip" || ioc.indicatorType === "domain") {
      edges.push(edge(ioc.indicatorType, ioc.indicator, ioc.indicator, "seen exploiting this CVE", "Indirect: via a shared malware family (one hop, not a direct CVE-IOC tag)"));
    }
  }
  for (const r of getAiReports()) {
    if ((r.cves ?? []).some((c) => norm(c.id) === norm(cveId))) edges.push(edge("report", r.id, r.articleTitle, "covered in report", "Direct: report.cves", { firstSeen: r.publishedDate, lastSeen: r.publishedDate }));
  }

  const ruleIndex = cache.getEntry("detection-rules").data?.index ?? [];
  return {
    node: {
      type: "cve",
      id: cveId,
      label: cveId,
      summary: null,
      found: profile.relatedActors.length + profile.relatedMalware.length + profile.relatedCampaigns.length + edges.length > 0,
      metadata: { relatedTechniques: profile.relatedTechniques ?? [], detectionRules: detectionRulesForCve(cveId, ruleIndex) },
    },
    edges: dedupeEdges(edges),
    unavailableRelationships: [{ relationshipType: "victim", reason: "No CVE-to-victim linkage exists anywhere in this app's data model." }],
  };
}

// --- Victim / Organization ---------------------------------------------------------------

function gatherVictim(key) {
  const target = norm(key);
  const ransomwareHits = getRansomwareCampaigns().filter((r) => norm(r.victim) === target);
  const darkWebHits = getDarkWebEntities().filter((d) => norm(d.victimOrg) === target || norm(d.name) === target);
  const found = ransomwareHits.length > 0 || darkWebHits.length > 0;

  const edges = [
    ...ransomwareHits.map((r) => edge("actor", r.group, r.group, "breached by", "Direct: ransomware disclosure record", { firstSeen: r.discoveredDate, lastSeen: r.discoveredDate })),
    ...darkWebHits.flatMap((d) => (d.associatedActors ?? []).map((a) => edge("actor", a, a, "linked actor", "Direct: dark-web finding associatedActors"))),
    ...darkWebHits.flatMap((d) => (d.associatedMalware ?? []).map((m) => edge("malware", m, m, "malware used", "Direct: dark-web finding associatedMalware"))),
    ...darkWebHits.flatMap((d) => (d.cveExploited ?? []).map((id) => edge("cve", id, id, "exploited via", "Direct: dark-web finding cveExploited"))),
  ];

  const summaryParts = [];
  const sector = ransomwareHits.find((r) => r.sector && r.sector !== "Unknown")?.sector;
  if (sector) summaryParts.push(sector);
  const dwType = darkWebHits.find((d) => d.type)?.type;
  if (dwType) summaryParts.push(dwType);

  return {
    node: { type: "victim", id: key, label: key, summary: summaryParts.length ? summaryParts.join(" • ") : null, found, metadata: { sector: sector ?? null } },
    edges: dedupeEdges(edges),
    unavailableRelationships: [
      { relationshipType: "ip", reason: "No indicator-level data links this victim to specific IP infrastructure." },
      { relationshipType: "domain", reason: "No indicator-level data links this victim to specific domain infrastructure." },
    ],
  };
}

// --- IP / Domain ---------------------------------------------------------------

async function gatherIpOrDomain(type, key) {
  const value = key.trim();
  const crossRef = crossReferenceIndicator(value);
  const edges = [
    ...crossRef.matchedMalwareFamilies.map((name) => edge("malware", name, name, "linked malware family", "Cross-reference: shared indicator in malware.iocs / articleIocs")),
    ...crossRef.associatedThreatActors.map((name) => edge("actor", name, name, "attributed actor", "Cross-reference: actor.malwareUsed includes matched family")),
    ...crossRef.activeCampaigns.map((name) => edge("campaign", name, name, "seen in campaign", "Cross-reference: campaign.associatedMalware includes matched family")),
    ...crossRef.matchingAiReports.map((r) => edge("report", r.id, r.articleTitle, "covered in report", "Direct: indicator present in report.iocs", { firstSeen: r.publishedDate, lastSeen: r.publishedDate })),
  ];
  for (const ioc of crossRef.relatedIocs) {
    if (ioc.indicatorType === "url") edges.push(edge("url", ioc.indicator, ioc.indicator, "related URL", "Cross-reference: shared malware family", { firstSeen: ioc.firstSeen }));
    else if (ioc.indicatorType === "hash") edges.push(edge("hash", ioc.indicator, ioc.indicator, "related sample", "Cross-reference: shared malware family", { firstSeen: ioc.firstSeen }));
  }

  let dnsAsn = null;
  const domainMetadata = {};
  try {
    if (type === "ip") {
      const [hostname, passive] = await Promise.allSettled([reverseDns(value), getPassiveDns("ip", value)]);
      if (hostname.status === "fulfilled" && hostname.value) edges.push(edge("domain", hostname.value, hostname.value, "reverse DNS resolves to", "Live: reverse DNS (PTR)"));
      if (passive.status === "fulfilled") for (const rec of passive.value) if (rec.hostname) edges.push(edge("domain", rec.hostname, rec.hostname, "passive DNS resolution", "Live: OTX passive DNS"));

      const ripestat = await checkRipestatThrottled("ip", value).catch(() => null);
      dnsAsn = ripestat?.asn ?? null;
      if (dnsAsn) {
        const siblingIps = crossRef.siblingIndicators.filter((s) => s.indicatorType === "ip").slice(0, 5);
        const asnResults = await Promise.allSettled(siblingIps.map((s) => checkRipestatThrottled("ip", s.indicator)));
        const sameAsn = [];
        asnResults.forEach((outcome, i) => {
          if (outcome.status === "fulfilled" && outcome.value.asn && String(outcome.value.asn) === String(dnsAsn)) sameAsn.push(siblingIps[i].indicator);
        });
        edges.push(edge("asn", dnsAsn, `AS${dnsAsn}${ripestat.holder ? ` (${ripestat.holder})` : ""}`, "shares ASN with", `Live: RIPEstat (${sameAsn.length} sibling IP(s) from this app's own IOC data confirmed on the same ASN)`));
      }
    } else {
      // crt.sh (certificate transparency) and RDAP (WHOIS-equivalent) are the
      // exact same lookups server/investigation/domainModule.js already uses
      // for the Triage Console's domain module -- reused here as real edges/
      // metadata instead of duplicating the correlation logic. No bulk
      // registrant-to-registrant index exists anywhere in this app, so RDAP
      // only ever enriches this one node's metadata, never a new cross-domain
      // edge (see file header discipline on not inventing correlation).
      const [records, passive, certificate, registration] = await Promise.allSettled([
        resolveDnsRecords(value),
        getPassiveDns("domain", value),
        checkCrtsh("domain", value),
        checkRdap("domain", value),
      ]);
      if (records.status === "fulfilled") for (const ip of [...records.value.a, ...records.value.aaaa]) edges.push(edge("ip", ip, ip, "resolves to", "Live: DNS A/AAAA record"));
      if (passive.status === "fulfilled") {
        for (const rec of passive.value) if (rec.address && (rec.recordType === "A" || rec.recordType === "AAAA")) edges.push(edge("ip", rec.address, rec.address, "passive DNS resolution", "Live: OTX passive DNS"));
      }
      if (certificate.status === "fulfilled") {
        const subdomains = (certificate.value.subdomains ?? []).filter((s) => s && s !== value).slice(0, 10);
        for (const sub of subdomains) edges.push(edge("domain", sub, sub, "shares SSL/TLS certificate with", "Live: crt.sh certificate transparency (same certificate covers this subdomain)"));
        if (certificate.value.certificateCount > 0) {
          domainMetadata.certificate = {
            certificateCount: certificate.value.certificateCount,
            subdomainCount: certificate.value.subdomainCount,
            latestIssuer: certificate.value.latestIssuer,
            latestNotBefore: certificate.value.latestNotBefore,
          };
        }
      }
      if (registration.status === "fulfilled" && registration.value.registered) {
        domainMetadata.registration = {
          registrar: registration.value.registrar,
          createdDate: registration.value.createdDate,
          updatedDate: registration.value.updatedDate,
          expiresDate: registration.value.expiresDate,
          nameservers: registration.value.nameservers,
          registrant: registration.value.registrant,
        };
      }
    }
  } catch {
    // live DNS/passive-DNS/RIPEstat/crt.sh/RDAP lookup failed entirely -- leave that side empty rather than guess
  }

  const unavailable = [
    { relationshipType: "cve", reason: "No direct indicator-to-CVE linkage exists in this app's data model (the only related path -- via a shared malware family -- is CVE-centric, not indicator-centric, and isn't surfaced here to avoid a misleading direct-looking link)." },
    { relationshipType: "victim", reason: `No data source links specific ${type === "ip" ? "IP" : "domain"} infrastructure to a named victim.` },
  ];
  if (type === "ip" && !dnsAsn) unavailable.push({ relationshipType: "asn", reason: "No configured live lookup (RIPEstat/Team Cymru/SANS ISC) returned an ASN for this IP." });

  return {
    node: { type, id: value, label: value, summary: null, found: true, metadata: { ...detectionAndHuntingForFamilies(crossRef.matchedMalwareFamilies), ...domainMetadata } },
    edges: dedupeEdges(edges),
    unavailableRelationships: unavailable,
  };
}

// --- ASN (leaf only -- see file header) -------------------------------------------------

function gatherAsn(key) {
  return {
    node: { type: "asn", id: key, label: `AS${key}`, summary: null, found: true, metadata: null },
    edges: [],
    unavailableRelationships: [
      {
        relationshipType: "ip",
        reason: "No free source this app integrates supports \"list all IPs on this ASN\" as a bulk query -- ASN is only checked against the small sibling-IP set already found for a specific IP you pivoted from, not expandable further on its own.",
      },
    ],
  };
}

// --- Cross-reference-only types: url, hash, email, fileName, processName, registryKey, userAgent ---

// Noise tokens a raw AV/sandbox threat label routinely carries around the
// actual family name (e.g. "trojan.mirai/gafgyt", "Ransom:Win32/LockBit!MTB")
// -- stripped before attempting to match a token against this platform's own
// tracked malware entity names/aliases. Deliberately conservative: this never
// invents a family, it only tries harder to recognize a REAL tracked family
// name buried inside a compound label the file-hash lookup already returned.
const THREAT_LABEL_NOISE_TOKENS = new Set([
  "trojan", "worm", "virus", "ransom", "ransomware", "backdoor", "downloader", "dropper", "generic", "malware",
  "win32", "win64", "msil", "linux", "android", "macos", "elf", "agent", "gen", "variant", "heur", "heuristic",
  "suspicious", "unwanted", "adware", "pua", "pup", "riskware", "hacktool", "exploit", "a", "b", "c", "gen2",
]);

/**
 * Best-effort match from a raw, often-compound AV/sandbox threat label (e.g.
 * VirusTotal's threatLabel or Hybrid Analysis's malwareFamily field) to a
 * REAL malware entity this platform already tracks -- splits the label into
 * candidate tokens, drops generic noise tokens, and tries each remaining
 * token (longest first, so a more specific token wins over a shorter
 * coincidental substring) for an EXACT name/alias match via
 * findByNameOrAlias. Returns null (never a fabricated/fuzzy guess) when
 * nothing exact matches.
 */
function matchMalwareFamilyFromLabel(label) {
  if (!label) return null;
  const tokens = label
    .split(/[^a-z0-9]+/i)
    .map((t) => t.toLowerCase())
    .filter((t) => t.length >= 3 && !THREAT_LABEL_NOISE_TOKENS.has(t))
    .sort((a, b) => b.length - a.length);
  for (const token of tokens) {
    const match = findByNameOrAlias(getMalwareEntities(), token);
    if (match) return match;
  }
  return null;
}

function gatherCrossReferenceOnly(type, key, context = {}) {
  const value = key.trim();
  const crossRef = crossReferenceIndicator(value);

  const edges = [
    ...crossRef.matchedMalwareFamilies.map((name) => edge("malware", name, name, "linked malware family", "Cross-reference: shared indicator in malware.iocs / articleIocs")),
    ...crossRef.associatedThreatActors.map((name) => edge("actor", name, name, "attributed actor", "Cross-reference: actor.malwareUsed includes matched family")),
    ...crossRef.activeCampaigns.map((name) => edge("campaign", name, name, "seen in campaign", "Cross-reference: campaign.associatedMalware includes matched family")),
    ...crossRef.matchingAiReports.map((r) => edge("report", r.id, r.articleTitle, "covered in report", "Direct: indicator present in report.iocs", { firstSeen: r.publishedDate, lastSeen: r.publishedDate })),
  ];

  // File hashes only: VirusTotal/Hybrid Analysis often classify a hash into
  // a NAMED malware family via a live sandbox/multi-engine detection even
  // when this exact hash was never previously ingested into this platform's
  // own IOC data (crossReferenceIndicator above only ever matches a LITERAL
  // string already in malware.iocs/articleIocs, so a never-before-seen hash
  // silently reported zero relationships even when its own live lookup had
  // JUST classified it). When a real, exact-matching tracked entity is
  // found for the classified family, that family's FULL tracked profile
  // (actors that use it, campaigns it's deployed in, other IOCs/samples,
  // victims, ATT&CK techniques) is pulled in via gatherMalware() and merged
  // -- the concrete fix for "the platform says the malware family is known
  // but never investigates it further."
  let matchedFamilyEntity = null;
  let liveFamilyLabelUnmatched = null;
  if (type === "hash" && context.malwareFamily) {
    matchedFamilyEntity = matchMalwareFamilyFromLabel(context.malwareFamily);
    if (matchedFamilyEntity) {
      if (!crossRef.matchedMalwareFamilies.some((n) => norm(n) === norm(matchedFamilyEntity.name))) {
        edges.push(
          edge(
            "malware",
            matchedFamilyEntity.name,
            matchedFamilyEntity.name,
            "classified as malware family",
            `Live: ${context.malwareFamilySource ?? "file-hash lookup"} classified this file as "${context.malwareFamily}", matched to this platform's tracked "${matchedFamilyEntity.name}" family`,
          ),
        );
      }
      // Reuses gatherMalware()'s own edge-building rather than duplicating
      // it -- these edges describe what the FAMILY connects to (actors,
      // campaigns, other samples/infrastructure, victims), which is exactly
      // what "investigate this hash's malware family" means for one sample
      // of it.
      const familyResult = gatherMalware(matchedFamilyEntity.name);
      edges.push(...familyResult.edges);
    } else {
      // A real classification exists, but no exact-matching tracked entity
      // -- disclosed as metadata (never silently dropped) so the analyst
      // sees the platform genuinely tried this pivot and what it found.
      liveFamilyLabelUnmatched = { label: context.malwareFamily, source: context.malwareFamilySource ?? "file-hash lookup" };
    }
  }

  const found = crossRef.matchedMalwareFamilies.length > 0 || crossRef.matchingAiReports.length > 0 || Boolean(matchedFamilyEntity);
  const allFamilyNames = [...crossRef.matchedMalwareFamilies, ...(matchedFamilyEntity ? [matchedFamilyEntity.name] : [])];

  return {
    node: {
      type,
      id: value,
      label: value,
      summary: null,
      found,
      metadata: { ...detectionAndHuntingForFamilies(allFamilyNames), liveMalwareFamilyLabel: context.malwareFamily ?? null, liveFamilyLabelUnmatched },
    },
    edges: dedupeEdges(edges),
    unavailableRelationships: [
      {
        relationshipType: "reputation",
        reason: `No external reputation or correlation source treats a ${type} as a globally-queryable indicator (confirmed: this app's Triage Console has the same gap). The only real signal here is whether this exact value already appears in this app's own ingested IOC/report data${type === "hash" ? ", plus (for file hashes only) whether a live sandbox/multi-engine classification matches a tracked malware family" : ""}.`,
      },
    ],
  };
}

// --- ATT&CK Technique ---------------------------------------------------------------

function gatherAttackTechnique(key) {
  const attackData = cache.getEntry("attack").data;
  const attackIndex = attackData?.techniques ?? [];
  const softwareIndex = attackData?.software ?? [];
  const techniqueId = key.trim().toUpperCase();
  const technique = attackIndex.find((t) => t.id === techniqueId) ?? null;

  const edges = [];
  for (const actor of getActorEntities()) {
    if ((actor.techniqueIds ?? []).includes(techniqueId)) edges.push(edge("actor", actor.name, actor.name, "uses technique", "Reverse: actor.techniqueIds (ATT&CK)"));
  }
  for (const malware of getMalwareEntities()) {
    if (techniqueIdsForFamily(malware.name, softwareIndex).includes(techniqueId)) edges.push(edge("malware", malware.name, malware.name, "implements technique", "Reverse: ATT&CK software techniqueIds / curated map"));
  }

  return {
    node: { type: "attackTechnique", id: techniqueId, label: technique ? `${techniqueId} ${technique.name}` : techniqueId, summary: technique?.tactic ?? null, found: Boolean(technique), metadata: technique ? { tactic: technique.tactic, url: technique.url } : null },
    edges: dedupeEdges(edges),
    unavailableRelationships: [
      { relationshipType: "campaign", reason: "Campaign entities in this app carry no ATT&CK technique field -- no source links a campaign directly to a specific technique." },
      { relationshipType: "cve", reason: "No source links an ATT&CK technique directly to a specific CVE in this app's data model." },
    ],
  };
}

// --- Country ---------------------------------------------------------------

function gatherCountry(key) {
  const target = norm(key);
  const edges = [];
  for (const a of getActorEntities()) {
    if (norm(a.country) === target) edges.push(edge("actor", a.name, a.name, "originates from this country", "Direct: actor.country (ATT&CK)"));
    if ((a.targetedCountries ?? []).some((c) => norm(c) === target)) edges.push(edge("actor", a.name, a.name, "targets victims here", "Indirect: actor.targetedCountries (news text match)"));
  }
  for (const c of getCampaignEntities()) {
    if ((c.targetedCountries ?? []).some((tc) => norm(tc) === target)) edges.push(edge("campaign", c.name, c.name, "targets victims here", "Indirect: campaign.targetedCountries (news text match)"));
  }
  for (const d of getDarkWebEntities()) {
    if ((d.targetedCountries ?? []).some((tc) => norm(tc) === target)) edges.push(edge("victim", d.victimOrg ?? d.name, d.victimOrg ?? d.name, "victim located here", "Indirect: dark-web finding targetedCountries (news text match)"));
  }

  return {
    node: { type: "country", id: key, label: key, summary: null, found: edges.length > 0, metadata: null },
    edges: dedupeEdges(edges),
    unavailableRelationships: [
      {
        relationshipType: "ip",
        reason: "Ransomware/geo-targeting data (Overview's World Threat Map) keys country by ISO alpha-2 code, a different representation than the free-text country names actor/campaign/dark-web records use -- not merged here to avoid an incorrect join. No IP/ASN-to-country bulk index exists either.",
      },
    ],
  };
}

// --- Industry ---------------------------------------------------------------
// Near-copy of gatherCountry's reverse-scan pattern -- entity.targetedIndustries
// exists on both actor and campaign entities but, before this, never became a
// real edge anywhere (only sat in campaign node metadata, dead for actor
// nodes). Same "Indirect: news text match" provenance as targetedCountries.

function industryReverseRelationship(tier) {
  if (tier === INDUSTRY_TIER.DIRECT) return "targeted by";
  if (tier === INDUSTRY_TIER.TECHNOLOGY_RELEVANT) return "technology relevant to";
  return "potentially exposes";
}

function gatherIndustry(key) {
  const target = norm(key);
  const edges = [];
  for (const a of getActorEntities()) {
    const matched = (a.targetedIndustries ?? []).find((i) => norm(i) === target);
    if (!matched) continue;
    const tier = industryTierMap(a.articles).get(matched) ?? INDUSTRY_TIER.DIRECT;
    edges.push(edge("actor", a.name, a.name, industryReverseRelationship(tier), "Indirect: actor.targetedIndustries (news text match)"));
  }
  for (const c of getCampaignEntities()) {
    const matched = (c.targetedIndustries ?? []).find((i) => norm(i) === target);
    if (!matched) continue;
    const tier = industryTierMap(c.articles).get(matched) ?? INDUSTRY_TIER.DIRECT;
    edges.push(edge("campaign", c.name, c.name, industryReverseRelationship(tier), "Indirect: campaign.targetedIndustries (news text match)"));
  }

  return {
    node: { type: "industry", id: key, label: key, summary: null, found: edges.length > 0, metadata: null },
    edges: dedupeEdges(edges),
    unavailableRelationships: [{ relationshipType: "victim", reason: "No source links a targeted-industry classification directly to a specific victim organization -- pivot via an actor or campaign instead." }],
  };
}

// --- Report ---------------------------------------------------------------

function gatherReport(key) {
  const report = getReportById(key);
  if (!report) {
    return { node: { type: "report", id: key, label: key, summary: null, found: false, metadata: null }, edges: [], unavailableRelationships: [{ relationshipType: "victim", reason: "AI Summarization reports carry no victim-organization field." }] };
  }

  const edges = [
    ...(report.cves ?? []).map((c) => edge("cve", c.id, c.id, "covers CVE", "Direct: report.cves")),
    ...(report.iocs?.ipAddresses ?? []).map((v) => edge("ip", v, v, "mentions indicator", "Direct: report.iocs.ipAddresses")),
    ...(report.iocs?.domains ?? []).map((v) => edge("domain", v, v, "mentions indicator", "Direct: report.iocs.domains")),
  ];

  const actorEntities = getActorEntities();
  for (const a of report.threatActors ?? []) {
    const match = findByNameOrAlias(actorEntities, a.group);
    edges.push(edge("actor", match?.name ?? a.group, a.group, "covers actor", match ? "Direct: report.threatActors (matched to canonical actor entity)" : "Report-only: no canonical actor entity matches this name yet"));
  }

  const malwareEntities = getMalwareEntities();
  for (const m of report.malware ?? []) {
    const match = findByNameOrAlias(malwareEntities, m.family);
    edges.push(edge("malware", match?.name ?? m.family, m.family, "covers malware", match ? "Direct: report.malware (matched to canonical malware entity)" : "Report-only: no canonical malware entity matches this name yet"));
  }

  if (report.campaignName) {
    const match = findByNameOrAlias(getCampaignEntities(), report.campaignName);
    edges.push(edge("campaign", match?.name ?? report.campaignName, report.campaignName, "covers campaign", match ? "Direct: report.campaignName (matched to canonical campaign entity)" : "Report-only: no canonical campaign entity matches this name yet"));
  }

  return {
    node: { type: "report", id: report.id, label: report.articleTitle, summary: `${report.articleSource} • ${report.publishedDate}`, found: true, metadata: { severity: report.severity, articleLink: report.articleLink, publishedDate: report.publishedDate } },
    edges: dedupeEdges(edges),
    unavailableRelationships: [{ relationshipType: "victim", reason: "AI Summarization reports carry no victim-organization field." }],
  };
}

// --- Orchestrator ---------------------------------------------------------------

/**
 * `context` carries per-search live-lookup facts the graph itself has no
 * other way to know (currently just a hash search's own VirusTotal/Hybrid
 * Analysis malware-family classification, see gatherCrossReferenceOnly) --
 * ignored by every node type that doesn't use it.
 */
export async function getGraphNode(nodeType, key, context = {}) {
  if (!GRAPH_NODE_TYPES.includes(nodeType) && nodeType !== "asn") throw new Error(`Unknown graph node type "${nodeType}"`);
  if (!key || !key.trim()) throw new Error("key is required");

  switch (nodeType) {
    case "actor":
      return gatherActor(key);
    case "campaign":
      return gatherCampaign(key);
    case "malware":
      return gatherMalware(key);
    case "cve":
      return gatherCve(key);
    case "victim":
      return gatherVictim(key);
    case "ip":
      return gatherIpOrDomain("ip", key);
    case "domain":
      return gatherIpOrDomain("domain", key);
    case "asn":
      return gatherAsn(key);
    case "attackTechnique":
      return gatherAttackTechnique(key);
    case "country":
      return gatherCountry(key);
    case "industry":
      return gatherIndustry(key);
    case "report":
      return gatherReport(key);
    default:
      if (CROSS_REF_ONLY_TYPES.has(nodeType)) return gatherCrossReferenceOnly(nodeType, key, context);
      throw new Error(`Unknown graph node type "${nodeType}"`);
  }
}

/**
 * Bounded, one-level auto-expand for entity-type searches (name/
 * ransomwareGroup) -- "make the graph the center of the experience" without
 * requiring the analyst to click every hop manually. Fetches the seed node
 * (hop 0, unchanged `getGraphNode`), then the top `maxNodesPerHop`
 * entity-shaped targets (by the SAME confidenceScore every edge already
 * carries -- no new ranking logic) from the seed's own edges, in parallel.
 * Purely additive to `GraphNodeResult`'s existing `{node, edges,
 * unavailableRelationships}` shape (via `additionalNodes`) -- every existing
 * consumer of a single node's own `.node`/`.edges` (coverage.js,
 * correlationSummary.js, shouldICare.js, rankResults.js) reads the SEED's
 * own fields unchanged; only the graph canvas (useInvestigationGraph.ts)
 * needs to know about the extra hop. IOC-type searches never call this --
 * they keep today's single-hop-per-click `getGraphNode` behavior unchanged.
 */
export async function getExpandedGraph(seedType, seedKey, { depth = 2, maxNodesPerHop = 8 } = {}) {
  const seed = await getGraphNode(seedType, seedKey);
  if (depth <= 1) return { ...seed, additionalNodes: [] };

  const candidates = seed.edges
    .filter((e) => AUTO_EXPAND_TYPES.has(e.targetType))
    .sort((a, b) => b.confidenceScore - a.confidenceScore)
    .slice(0, maxNodesPerHop);

  const results = await Promise.allSettled(candidates.map((e) => getGraphNode(e.targetType, e.targetKey)));
  const additionalNodes = results
    .map((result, i) => (result.status === "fulfilled" ? { seedType: candidates[i].targetType, seedKey: candidates[i].targetKey, ...result.value } : null))
    .filter(Boolean);

  return { ...seed, additionalNodes };
}
