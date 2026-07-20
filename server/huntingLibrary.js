// Flattens every AI Summarization report's threatHuntingOpportunities (see
// server/aiThreatSummary.js) into one searchable, per-platform library.
// Each report already generates real hunting logic grounded in that
// specific article's content (not generic boilerplate -- the prompt
// explicitly rejects that, see SYSTEM_PROMPT), but it's locked inside that
// one report with no way to browse across reports by platform. This is pure
// aggregation, not a new data source or a persisted store: re-derived from
// the report store on every request, since the underlying reports are
// already immutable once generated.
//
// Confirmed live this was the *only* thing feeding the Hunting Query
// Library -- with AI Summarization stuck at ~9 reports (nearly all CVE
// vendor advisories), the library looked CVE-only even though it's not a
// hardcoded filter. buildEntityHuntingQueries() below adds a second,
// deterministic (no LLM) source: Malware Intelligence and Threat Actor
// Intelligence entities (server/malwareIntelligence.js,
// server/threatActorIntelligence.js) already carry live indicators
// (`iocs`) and confirmed ATT&CK techniques (`techniqueIds`) that never flow
// through an AI Summarization report at all. Same substring-match helper
// (`detectionRulesFor`, server/correlate.js) the AI report path already uses
// to ground Sigma/YARA hits against the real synced rule index -- just run
// across every active entity instead of only the handful of names one
// article happened to name.
import { detectionRulesFor } from "./correlate.js";

const PLATFORM_LABELS = {
  defenderXdrKql: "Microsoft Defender XDR (KQL)",
  sentinelKql: "Microsoft Sentinel (KQL)",
  splunkSpl: "Splunk (SPL)",
  elastic: "Elastic",
  sigma: "Sigma",
  yara: "YARA",
  crowdstrikeFalcon: "CrowdStrike Falcon",
  carbonBlack: "Carbon Black",
};

export const HUNTING_PLATFORMS = Object.keys(PLATFORM_LABELS);

const MAX_INDICATORS_PER_QUERY = 5;
// Keeps entity-derived volume proportionate to how much real signal an
// entity actually has, same "hide, don't zero-fill" convention used
// elsewhere in this app -- an entity with a huge mentionCount doesn't need
// unbounded rows, just the most relevant ones.
const MAX_ENTITIES_PER_KIND = 40;

// Some articles genuinely use a generic phrase ("unknown malware") in place
// of a real family name -- confirmed live this extracts as if it were an
// actual name. Same spirit as the "Not Reported" filtering just below.
const GENERIC_ENTITY_NAMES = new Set(["unknown", "unknown malware", "unnamed malware", "unknown actor", "not reported", "n/a"]);
function isRealName(name) {
  return Boolean(name) && !GENERIC_ENTITY_NAMES.has(name.trim().toLowerCase());
}

function reportHuntingItems(reports) {
  const items = [];
  for (const report of reports) {
    const opportunities = report.threatHuntingOpportunities;
    if (!opportunities) continue;
    for (const platform of HUNTING_PLATFORMS) {
      const queries = opportunities[platform] ?? [];
      queries.forEach((query, index) => {
        items.push({
          id: `${report.id}::${platform}::${index}`,
          platform,
          platformLabel: PLATFORM_LABELS[platform],
          query,
          source: "ai-report",
          reportId: report.id,
          articleTitle: report.articleTitle,
          articleLink: report.articleLink,
          articleSource: report.articleSource,
          generatedAt: report.generatedAt,
          severity: report.severity,
          cveIds: (report.cves ?? []).map((c) => c.id),
          // "Not Reported" is a real, valid value for this field elsewhere in
          // this app (aiThreatSummary.js's own "never invent facts" grounding
          // uses it as an explicit placeholder when the article names
          // nothing) -- confirmed live it was leaking through here as if it
          // were a real malware family, right next to a genuine one like
          // "Dragonforce Ransomware" on the same badge row.
          malware: (report.malware ?? []).map((m) => m.family).filter((f) => f && f !== "Not Reported"),
          threatActors: (report.threatActors ?? []).map((a) => a.group).filter((g) => g && g !== "Not Reported"),
        });
      });
    }
  }
  return items;
}

/** Real public YARA/SigmaHQ rule citations for one malware/actor entity -- identical grounding mechanism to aiThreatSummary.js#groundHuntingRules, just applied to every active entity instead of only names one article mentioned. */
function ruleCitationItems(entity, kind, ruleIndex, generatedAt) {
  const items = [];
  for (const hit of detectionRulesFor(entity.name, ruleIndex)) {
    const platform = hit.label === "SigmaHQ" ? "sigma" : "yara";
    items.push({
      id: `entity::${kind}::${entity.id}::${platform}::${hit.path}`,
      platform,
      platformLabel: PLATFORM_LABELS[platform],
      query: `Existing public rule (${hit.label}): ${hit.path}\n${hit.url}`,
      source: "entity",
      reportId: `entity::${kind}::${entity.id}`,
      articleTitle: `Existing public detection rule for ${entity.name}`,
      articleLink: hit.url,
      articleSource: hit.label,
      generatedAt,
      severity: "UNKNOWN",
      cveIds: [],
      malware: kind === "malware" ? [entity.name] : [],
      threatActors: kind === "actor" ? [entity.name] : [],
    });
  }
  return items;
}

/** Generic, platform-native "hunt for these known-live indicators" queries built from a malware entity's own real, currently-tracked `iocs` (server/malwareIntelligence.js) -- not invented, not from an LLM. */
function indicatorHuntItems(entity, generatedAt) {
  if (!entity.iocs?.length || !entity.articles?.length) return [];
  const citation = entity.articles[0];
  const values = entity.iocs.slice(0, MAX_INDICATORS_PER_QUERY).map((i) => i.indicator);
  const quoted = values.map((v) => `"${v}"`);

  const base = {
    source: "entity",
    reportId: `entity::malware::${entity.id}`,
    articleTitle: citation.title,
    articleLink: citation.link,
    articleSource: citation.source,
    generatedAt,
    severity: "UNKNOWN",
    cveIds: [],
    malware: [entity.name],
    threatActors: [],
  };

  const kql =
    `let knownIndicators = dynamic([${quoted.join(", ")}]);\n` +
    `union DeviceNetworkEvents, DeviceFileEvents, DeviceProcessEvents\n` +
    `| where RemoteIP in (knownIndicators) or RemoteUrl has_any (knownIndicators) or SHA256 in (knownIndicators) or FileName in (knownIndicators)`;

  return [
    { ...base, id: `entity::malware::${entity.id}::splunkSpl::iocs`, platform: "splunkSpl", platformLabel: PLATFORM_LABELS.splunkSpl, query: `index=* (${quoted.join(" OR ")})` },
    { ...base, id: `entity::malware::${entity.id}::defenderXdrKql::iocs`, platform: "defenderXdrKql", platformLabel: PLATFORM_LABELS.defenderXdrKql, query: kql },
    { ...base, id: `entity::malware::${entity.id}::sentinelKql::iocs`, platform: "sentinelKql", platformLabel: PLATFORM_LABELS.sentinelKql, query: kql },
    {
      ...base,
      id: `entity::malware::${entity.id}::elastic::iocs`,
      platform: "elastic",
      platformLabel: PLATFORM_LABELS.elastic,
      query: `destination.ip: (${quoted.join(" or ")}) or url.full: (${quoted.join(" or ")}) or file.hash.sha256: (${quoted.join(" or ")})`,
    },
  ];
}

/**
 * Deterministic (no LLM) hunting queries sourced from Malware Intelligence
 * and Threat Actor Intelligence entities (server/malwareIntelligence.js,
 * server/threatActorIntelligence.js), not AI Summarization reports. Only
 * entities with real, current signal contribute: `verified` (confirmed
 * against ATT&CK or a live indicator, not just an unconfirmed extraction)
 * plus actual activity (`iocSightings`/`mentionCount` > 0) -- an entity
 * seeded from ATT&CK with no live indicators and no news mentions has
 * nothing real to hunt for yet.
 */
export function buildEntityHuntingQueries(malwareEntities, actorEntities, ruleIndex) {
  const generatedAt = new Date().toISOString();
  const items = [];

  const activeMalware = malwareEntities
    .filter((e) => e.verified && e.iocSightings > 0 && isRealName(e.name))
    .sort((a, b) => b.iocSightings - a.iocSightings)
    .slice(0, MAX_ENTITIES_PER_KIND);
  for (const entity of activeMalware) {
    items.push(...ruleCitationItems(entity, "malware", ruleIndex, generatedAt));
    items.push(...indicatorHuntItems(entity, generatedAt));
  }

  const activeActors = actorEntities
    .filter((e) => e.verified && e.mentionCount > 0 && isRealName(e.name))
    .sort((a, b) => b.mentionCount - a.mentionCount)
    .slice(0, MAX_ENTITIES_PER_KIND);
  for (const entity of activeActors) {
    items.push(...ruleCitationItems(entity, "actor", ruleIndex, generatedAt));
  }

  return items;
}

export function buildHuntingQueryLibrary(reports, malwareEntities = [], actorEntities = [], ruleIndex = []) {
  const items = [...reportHuntingItems(reports), ...buildEntityHuntingQueries(malwareEntities, actorEntities, ruleIndex)];
  return items.sort((a, b) => new Date(b.generatedAt) - new Date(a.generatedAt));
}
