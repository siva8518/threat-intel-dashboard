// MITRE ATT&CK technique-mention validation for article headline + summary
// extraction. Candidates now come from the combined per-article call in
// server/combinedExtraction.js, but validation here is stronger than the
// other three entity kinds: MITRE ATT&CK's technique list
// (server/connectors/attack.js) is a closed, authoritative catalog, so every
// extracted candidate is cross-checked against it and anything that doesn't
// match a real technique ID or name is dropped as a hallucination, not just
// noise-filtered.
export const MAX_TECHNIQUES_PER_ARTICLE = 5;

const TECHNIQUE_ID_PATTERN = /^T\d{4}(\.\d{3})?$/i;

// Below this length, a normalized-name substring match is too likely to be a
// coincidence (e.g. a short generic word matching inside an unrelated,
// longer technique name) -- same guard, same threshold, as
// server/correlate.js#detectionRulesFor's MIN_FUZZY_WORD_LENGTH.
const MIN_FUZZY_MATCH_LENGTH = 6;

/**
 * Strips hyphens/slashes/colons/punctuation down to plain lowercase words --
 * confirmed live that headline/summary text routinely phrases a technique
 * differently from MITRE's own formatting ("DLL side loading" vs MITRE's
 * "DLL Side-Loading"), and a strict string-equality match was missing real
 * mentions purely over punctuation, not because the technique wasn't
 * actually named.
 */
function normalizeForMatch(text) {
  return text.toLowerCase().replace(/[^a-z0-9]+/g, " ").replace(/\s+/g, " ").trim();
}

/**
 * Cross-references raw candidates against the real MITRE ATT&CK technique
 * index. Unlike malware family names (an open set with no single
 * authoritative list), every valid technique ID and name is already known
 * from server/connectors/attack.js's live STIX bundle -- so anything that
 * doesn't match one (allowing for punctuation/wording variance, not just
 * exact string equality) is a model hallucination and is dropped, not just
 * flagged as unverified.
 *
 * Matching against the real catalog alone isn't enough, though -- confirmed
 * live that the model can return a real, valid technique (one that's
 * genuinely in attackIndex) that simply isn't mentioned anywhere in the
 * given article text (e.g. inferring "T1055 Process Injection" from a
 * phishing article that never mentions injection). `sourceText`, when
 * provided, adds a second, deterministic check: the technique's own ID or
 * (normalized) name must appear in the text before it's accepted, the same
 * "don't trust the model's word alone" principle as the exact-match CVE
 * lookup in server/rag/retriever.js -- just tolerant of hyphenation/spacing
 * differences rather than requiring MITRE's exact formatting.
 */
export function resolveTechniques(candidates, attackIndex, sourceText = "") {
  const byId = new Map(attackIndex.map((t) => [t.id.toLowerCase(), t]));
  const byNormalizedName = new Map(attackIndex.map((t) => [normalizeForMatch(t.name), t]));
  const normalizedSource = normalizeForMatch(sourceText);

  function findByName(candidateNorm) {
    const exact = byNormalizedName.get(candidateNorm);
    if (exact) return exact;
    if (candidateNorm.length < MIN_FUZZY_MATCH_LENGTH) return null;
    for (const [normName, technique] of byNormalizedName) {
      if (normName.length < MIN_FUZZY_MATCH_LENGTH) continue;
      if (candidateNorm.includes(normName) || normName.includes(candidateNorm)) return technique;
    }
    return null;
  }

  const seen = new Set();
  const resolved = [];
  for (const raw of candidates.slice(0, MAX_TECHNIQUES_PER_ARTICLE)) {
    const trimmed = raw.trim();
    const technique = TECHNIQUE_ID_PATTERN.test(trimmed) ? byId.get(trimmed.toLowerCase()) : findByName(normalizeForMatch(trimmed));
    if (!technique || seen.has(technique.id)) continue;

    if (sourceText) {
      const idPresent = normalizedSource.includes(technique.id.toLowerCase());
      const normalizedName = normalizeForMatch(technique.name);
      const namePresent = normalizedName.length >= MIN_FUZZY_MATCH_LENGTH && normalizedSource.includes(normalizedName);
      if (!idPresent && !namePresent) continue;
    }

    seen.add(technique.id);
    resolved.push(technique);
  }
  return resolved;
}
