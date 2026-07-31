// Malicious-tool name validation for article headline + summary extraction --
// candidates come from the combined per-article call in
// server/combinedExtraction.js (extraction is open-set: no hardcoded/manually-
// maintained list of names), but every candidate still passes through
// validateCandidates below before server/toolIntelligence.js#upsertMention
// ever sees it. Mirrors server/malwareExtraction.js exactly, one entity kind
// over: TOOLS here are legitimate/dual-use software (remote access, C2
// frameworks, red-team/pentest utilities, admin binaries) reported as used or
// abused by a threat actor -- MALWARE stays a purpose-built malicious family.
export const MAX_NAMES_PER_ARTICLE = 5;

const GENERIC_STOPWORDS = new Set(["tool", "tools", "software", "utility", "utilities", "the tool", "malware", "ransomware", "unknown"]);

// Catches phrases like "hacking tool" or "remote access software" -- the
// model sometimes composites a generic noun when a headline names no real
// tool, mirroring server/malwareExtraction.js's GENERIC_PHRASE_PATTERN.
const GENERIC_PHRASE_PATTERN = /^(new|unknown|latest|another|malicious|hacking|attack)?\s*(remote access|admin|pentest(ing)?|red[\s-]?team)?\s*(tool|tools|software|utility|utilities|framework)$/i;

/**
 * Filters raw LLM output before it's ever allowed to become a record.
 * `articleSource`, `knownMalwareNamesLower`, and `knownActorNamesLower` are
 * cross-checks against data this app already trusts, so the model can't
 * accidentally turn a malware-family or threat-actor mention into a fake
 * tool entity -- the ingestion-time validation step, same policy as
 * server/malwareExtraction.js and server/threatActorExtraction.js.
 */
export function validateCandidates(candidates, { articleSource, knownMalwareNamesLower, knownActorNamesLower }) {
  const seen = new Set();
  const valid = [];
  for (const raw of candidates.slice(0, MAX_NAMES_PER_ARTICLE)) {
    const name = raw.trim();
    const lower = name.toLowerCase();
    if (name.length < 3 || name.length > 60) continue;
    if (GENERIC_STOPWORDS.has(lower)) continue;
    if (GENERIC_PHRASE_PATTERN.test(name)) continue;
    if (lower === (articleSource ?? "").toLowerCase()) continue;
    if (knownMalwareNamesLower?.has(lower)) continue;
    if (knownActorNamesLower?.has(lower)) continue;
    if (seen.has(lower)) continue;
    seen.add(lower);
    valid.push(name);
  }
  return valid;
}
