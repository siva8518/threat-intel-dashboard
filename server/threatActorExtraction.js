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
  // Confirmed live: the model sometimes echoes the candidate's own
  // classification back as its *name* too (e.g. {"name": "Initial Access
  // Broker", "type": "Initial Access Broker"}), which polluted Top Threat
  // Actors with a role label sitting next to real group names. No real
  // threat actor is named exactly one of these category words.
  ...ACTOR_TYPES.map((t) => t.toLowerCase()),
]);

// Confirmed live: the local model occasionally lifts a bare nationality
// adjective out of phrasing like "Russian hackers" or "Chinese state-sponsored
// group" and returns it alone as if it were the group's actual name, which
// polluted Top Threat Actors with entries like "Russian" next to real group
// names. Single-word demonyms only -- a real, multi-word designation that
// happens to include a nationality (e.g. "North Korea's Lazarus Group") isn't
// affected since the whole candidate string wouldn't equal just the demonym.
const BARE_DEMONYMS = new Set([
  "russian",
  "chinese",
  "iranian",
  "north korean",
  "korean",
  "american",
  "ukrainian",
  "israeli",
  "belarusian",
  "syrian",
  "pakistani",
  "indian",
  "vietnamese",
  "turkish",
  "brazilian",
  "nigerian",
  "european",
  "western",
  "eastern",
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
    if (BARE_DEMONYMS.has(lower)) continue;
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
