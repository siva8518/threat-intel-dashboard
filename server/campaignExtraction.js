// Named-campaign/operation validation for article headline + summary
// extraction (e.g. "Operation Triangulation", "the MOVEit campaign",
// "SolarWinds Compromise"). Candidates now come from the combined
// per-article call in server/combinedExtraction.js (extraction is open-set:
// no hardcoded/manually-maintained list -- ATT&CK's own Campaigns list is
// sparse and, confirmed live in server/connectors/attack.js, gives campaigns
// no real display name beyond their code), but every candidate still passes
// through validateCandidates below first.
export const MAX_CAMPAIGNS_PER_ARTICLE = 3;

// Noise filtering on the model's own output, same category as
// server/malwareExtraction.js's GENERIC_STOPWORDS.
const GENERIC_STOPWORDS = new Set(["the attack", "the campaign", "the breach", "the incident", "the operation", "unknown", "unknown campaign"]);

/**
 * Filters raw LLM output before it's ever allowed to become a record.
 * `knownActorNamesLower` and `knownMalwareNamesLower` are cross-checks
 * against data this app already trusts, so the model can't accidentally
 * turn a threat-actor or malware-family mention into a fake campaign entity
 * -- the same "don't let one entity type bleed into another" guard as
 * server/malwareExtraction.js's knownActorNamesLower and
 * server/threatActorExtraction.js's knownMalwareNamesLower.
 */
export function validateCandidates(candidates, { articleSource, knownActorNamesLower, knownMalwareNamesLower }) {
  const seen = new Set();
  const valid = [];
  for (const raw of candidates.slice(0, MAX_CAMPAIGNS_PER_ARTICLE)) {
    const name = raw.trim();
    const lower = name.toLowerCase();
    if (name.length < 4 || name.length > 80) continue;
    if (GENERIC_STOPWORDS.has(lower)) continue;
    if (lower === (articleSource ?? "").toLowerCase()) continue;
    if (knownActorNamesLower?.has(lower)) continue;
    if (knownMalwareNamesLower?.has(lower)) continue;
    if (seen.has(lower)) continue;
    seen.add(lower);
    valid.push(name);
  }
  return valid;
}
