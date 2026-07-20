// Flattens every AI Summarization report's detectionEngineeringOpportunities
// (see server/aiThreatSummary.js) into a trackable backlog -- the concrete
// "build this detection" gaps a report identifies (new analytics,
// correlation rules, MITRE coverage gaps, telemetry/log-source gaps),
// paired with a status this app has no other way to know (has Detection
// Engineering actually built it yet). Same pattern as
// server/remediationQueue.js + server/remediationTracker.js: the backlog
// items themselves are re-derived from the report store on every request
// (never persisted independently), only the human status decision is.
//
// buildEntityDetectionBacklog() below adds a second, deterministic (no LLM)
// source: Malware Intelligence and Threat Actor Intelligence entities
// (server/malwareIntelligence.js, server/threatActorIntelligence.js), which
// never flowed through this backlog at all before -- confirmed live the
// only thing feeding this view was the same sparse, CVE-skewed AI
// Summarization report pool the Hunting Query Library was limited to (see
// server/huntingLibrary.js). Both entity-derived checks are phrased as
// "confirm/verify", never "this IS a gap" -- this app never asserts a fact
// (like "no detection exists") it has no way to actually know.
import { detectionRulesFor } from "./correlate.js";

const CATEGORY_LABELS = {
  newAnalytics: "New Analytics",
  newCorrelationRules: "New Correlation Rules",
  newSigmaRules: "New Sigma Rules",
  newKqlDetections: "New KQL Detections",
  edrBehavioralDetections: "EDR Behavioral Detections",
  siemCorrelationLogic: "SIEM Correlation Logic",
  mitreCoverageGaps: "MITRE Coverage Gaps",
  telemetryGaps: "Telemetry Gaps",
  logSourceRequirements: "Log Source Requirements",
};

export const DETECTION_BACKLOG_CATEGORIES = Object.keys(CATEGORY_LABELS);

const SEVERITY_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

// Same proportionality cap as server/huntingLibrary.js -- only entities with
// real, current signal contribute, and even among those we cap volume so
// one prolific actor's technique list can't flood the backlog.
const MAX_ENTITIES_PER_KIND = 40;
const MAX_TECHNIQUES_PER_ACTOR = 5;

// Some articles genuinely use a generic phrase ("unknown malware") in place
// of a real family name -- confirmed live this extracts as if it were an
// actual name. Same spirit as the "Not Reported" filtering already applied
// to AI Summarization report malware/actor fields (server/huntingLibrary.js).
const GENERIC_ENTITY_NAMES = new Set(["unknown", "unknown malware", "unnamed malware", "unknown actor", "not reported", "n/a"]);
function isRealName(name) {
  return Boolean(name) && !GENERIC_ENTITY_NAMES.has(name.trim().toLowerCase());
}

function reportBacklogItems(reports) {
  const items = [];
  for (const report of reports) {
    const opportunities = report.detectionEngineeringOpportunities;
    if (!opportunities) continue;
    for (const category of DETECTION_BACKLOG_CATEGORIES) {
      const entries = opportunities[category] ?? [];
      entries.forEach((description, index) => {
        items.push({
          id: `${report.id}::${category}::${index}`,
          category,
          categoryLabel: CATEGORY_LABELS[category],
          description,
          source: "ai-report",
          reportId: report.id,
          articleTitle: report.articleTitle,
          articleLink: report.articleLink,
          articleSource: report.articleSource,
          generatedAt: report.generatedAt,
          severity: report.severity,
          cveIds: (report.cves ?? []).map((c) => c.id),
        });
      });
    }
  }
  return items;
}

/**
 * Deterministic (no LLM) backlog items sourced from Malware Intelligence and
 * Threat Actor Intelligence entities: a confirmed, currently-active malware
 * family with no matching public YARA/Sigma rule (via the same
 * detectionRulesFor() substring match the Hunting Query Library uses), or a
 * confirmed, currently-active actor's own ATT&CK techniqueIds -- both real,
 * already-computed fields on those entities that never reached this backlog
 * before.
 */
export function buildEntityDetectionBacklog(malwareEntities, actorEntities, ruleIndex, attackIndex) {
  const items = [];
  const generatedAt = new Date().toISOString();
  const techniqueById = new Map(attackIndex.map((t) => [t.id, t]));

  const activeMalware = malwareEntities
    .filter((e) => e.verified && e.iocSightings > 0 && isRealName(e.name))
    .sort((a, b) => b.iocSightings - a.iocSightings)
    .slice(0, MAX_ENTITIES_PER_KIND);
  for (const entity of activeMalware) {
    if (detectionRulesFor(entity.name, ruleIndex).length > 0) continue; // already covered by an existing public rule
    const citation = entity.articles?.[0];
    const link = citation?.link ?? entity.attackUrl;
    if (!link) continue; // no genuine citation to point Detection Engineering at -- skip rather than emit a dead link
    items.push({
      id: `entity::malware::${entity.id}::newAnalytics`,
      category: "newAnalytics",
      categoryLabel: CATEGORY_LABELS.newAnalytics,
      description: `${entity.name} has ${entity.iocSightings} live indicator(s) currently tracked in Malware Intelligence, but no matching public YARA/Sigma rule was found -- confirm a custom detection exists, or build one.`,
      source: "entity",
      reportId: `entity::malware::${entity.id}`,
      articleTitle: citation?.title ?? entity.name,
      articleLink: link,
      articleSource: citation?.source ?? "Malware Intelligence",
      generatedAt,
      severity: "UNKNOWN",
      cveIds: [],
    });
  }

  const activeActors = actorEntities
    .filter((e) => e.verified && e.mentionCount > 0 && e.techniqueIds?.length && isRealName(e.name))
    .sort((a, b) => b.mentionCount - a.mentionCount)
    .slice(0, MAX_ENTITIES_PER_KIND);
  for (const entity of activeActors) {
    const citation = entity.articles?.[0];
    for (const techniqueId of entity.techniqueIds.slice(0, MAX_TECHNIQUES_PER_ACTOR)) {
      const technique = techniqueById.get(techniqueId);
      const label = technique ? `${techniqueId} -- ${technique.name}` : techniqueId;
      const link = citation?.link ?? technique?.url ?? entity.attackUrl;
      if (!link) continue; // no genuine citation to point Detection Engineering at -- skip rather than emit a dead link
      items.push({
        id: `entity::actor::${entity.id}::${techniqueId}`,
        category: "mitreCoverageGaps",
        categoryLabel: CATEGORY_LABELS.mitreCoverageGaps,
        description: `${entity.name} is attributed with MITRE ATT&CK technique ${label} -- confirm detection coverage exists, or build one.`,
        source: "entity",
        reportId: `entity::actor::${entity.id}`,
        articleTitle: citation?.title ?? entity.name,
        articleLink: link,
        articleSource: citation?.source ?? "Threat Actor Intelligence",
        generatedAt,
        severity: "UNKNOWN",
        cveIds: entity.cveExploited?.slice(0, 3) ?? [],
      });
    }
  }

  return items;
}

export function buildDetectionBacklog(reports, statuses, malwareEntities = [], actorEntities = [], ruleIndex = [], attackIndex = []) {
  const raw = [...reportBacklogItems(reports), ...buildEntityDetectionBacklog(malwareEntities, actorEntities, ruleIndex, attackIndex)];

  const items = raw.map((item) => {
    const tracked = statuses[item.id];
    return { ...item, status: tracked?.status ?? "open", note: tracked?.note ?? null, statusUpdatedAt: tracked?.updatedAt ?? null };
  });

  return items.sort((a, b) => {
    const rankDiff = (SEVERITY_RANK[a.severity] ?? 4) - (SEVERITY_RANK[b.severity] ?? 4);
    if (rankDiff !== 0) return rankDiff;
    return new Date(b.generatedAt) - new Date(a.generatedAt);
  });
}
