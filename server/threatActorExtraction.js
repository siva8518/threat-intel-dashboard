// Open-set threat-actor-name extraction from article headline + summary --
// same approach as server/malwareExtraction.js and server/attackTechniqueExtraction.js,
// applied to threat actor/group names this time. No hardcoded/manually-
// maintained actor roster: a brand-new group named by a vendor blog before
// it ever gets an ATT&CK Groups entry (or before ransomware.live lists it)
// still gets caught the first time news names it, same gap this closed for
// malware families ("Bumblebee").
//
// The model is also asked to classify each name's TYPE in the same call --
// APT/Cybercrime/Ransomware/Hacktivist/Initial Access Broker/Insider/Unknown
// -- since the article text itself usually signals this ("ransomware gang",
// "nation-state espionage operation", "hacktivist collective") and no
// authoritative catalog of actor-type classifications exists to cross-check
// against the way MITRE ATT&CK's Software list backs up malware names.
import { ollamaJson } from "./rag/ollamaClient.js";
import { OLLAMA_CHAT_MODEL } from "./rag/config.js";

export const MAX_ACTORS_PER_ARTICLE = 5;

export const ACTOR_TYPES = ["APT", "Cybercrime", "Ransomware", "Hacktivist", "Initial Access Broker", "Insider", "Unknown"];

const SYSTEM_PROMPT =
  "You are a threat intelligence analyst. You will be given one security news article's headline and, if available, its summary. " +
  'Identify every threat actor or intrusion-set/group name explicitly mentioned (e.g. "APT29", "FIN7", "LockBit", "Scattered Spider", "Lazarus Group"). ' +
  'For each one, classify its TYPE using ONLY one of these exact strings: "APT", "Cybercrime", "Ransomware", "Hacktivist", "Initial Access Broker", "Insider", "Unknown". ' +
  'Base the type on how the text itself describes the group (nation-state/espionage -> APT; a ransomware gang/operation -> Ransomware; a financially-motivated crime group -> Cybercrime; a hacktivist collective -> Hacktivist; a group that sells network access -> Initial Access Broker; a malicious insider -> Insider; unclear -> Unknown). ' +
  "Do NOT include: malware/tool/family names (e.g. Bumblebee, Cobalt Strike, AsyncRAT), CVE IDs, victim/vendor/company names, product names, generic terms (\"hackers\", \"attackers\", \"threat actor\", \"cybercriminals\" alone), or country names alone. " +
  'Respond with ONLY a JSON array of objects, each `{"name": "...", "type": "..."}`, using the name\'s exact capitalization as written in the text. Return [] if no actor is named. No other text.';

function parseJsonArray(text) {
  const start = text.indexOf("[");
  const end = text.lastIndexOf("]");
  if (start === -1 || end === -1 || end < start) return [];
  try {
    const parsed = JSON.parse(text.slice(start, end + 1));
    return Array.isArray(parsed) ? parsed.filter((x) => x && typeof x === "object" && typeof x.name === "string") : [];
  } catch {
    return []; // model returned malformed JSON -- treat as "found nothing" rather than guessing
  }
}

/**
 * Extracts candidate {name, type} pairs from one article's headline +
 * summary via the local model. Returns raw candidates, not yet validated --
 * see validateCandidates below for the filtering step.
 */
export async function extractActorMentions({ title, summary }) {
  const userContent = summary ? `Headline: ${title}\nSummary: ${summary}` : `Headline: ${title}`;
  const response = await ollamaJson("/api/chat", {
    model: OLLAMA_CHAT_MODEL,
    messages: [
      { role: "system", content: SYSTEM_PROMPT },
      { role: "user", content: userContent },
    ],
    options: { temperature: 0 },
  });
  return parseJsonArray(response.message?.content ?? "");
}

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
