// Threat-actor-name validation for article headline + summary extraction --
// candidates (including TYPE classification -- APT/Cybercrime/Ransomware/
// Hacktivist/Initial Access Broker/Insider/Unknown) now come from the
// combined per-article call in server/combinedExtraction.js (extraction is
// open-set: no hardcoded/manually-maintained actor roster), but every
// candidate still passes through validateCandidates below first.
export const MAX_ACTORS_PER_ARTICLE = 5;

export const ACTOR_TYPES = ["APT", "Cybercrime", "Ransomware", "Hacktivist", "Initial Access Broker", "Insider", "Unknown"];

// Noise filtering on the model's own output, not a roster of actor names --
// same category as server/malwareExtraction.js's GENERIC_STOPWORDS.
const GENERIC_STOPWORDS = new Set([
  "hackers",
  "attackers",
  "threat actor",
  "threat actors",
  "cybercriminals",
  "cyber criminals",
  "unknown",
  "unknown actor",
  "unknown group",
]);

/**
 * Filters raw LLM output before it's ever allowed to become a record.
 * `articleSource`, `knownMalwareNamesLower` and `knownToolNamesLower` are
 * cross-checks against data this app already trusts, so the model can't
 * accidentally turn a malware family or a generic dual-use tool into a fake
 * actor entity -- the mirror-image of malwareExtraction.js's own
 * knownActorNamesLower exclusion set.
 */
export function validateCandidates(candidates, { articleSource, knownMalwareNamesLower, knownToolNamesLower }) {
  const seen = new Set();
  const valid = [];
  for (const raw of candidates.slice(0, MAX_ACTORS_PER_ARTICLE)) {
    const name = (raw.name ?? "").trim();
    const lower = name.toLowerCase();
    if (name.length < 3 || name.length > 60) continue;
    if (GENERIC_STOPWORDS.has(lower)) continue;
    if (lower === (articleSource ?? "").toLowerCase()) continue;
    if (knownMalwareNamesLower?.has(lower)) continue;
    if (knownToolNamesLower?.has(lower)) continue;
    if (seen.has(lower)) continue;
    seen.add(lower);
    const type = ACTOR_TYPES.includes(raw.type) ? raw.type : "Unknown";
    valid.push({ name, type });
  }
  return valid;
}
