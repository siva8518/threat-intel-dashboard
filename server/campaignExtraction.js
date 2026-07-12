// Open-set named-campaign/operation extraction from article headline +
// summary -- same approach as server/malwareExtraction.js and
// server/threatActorExtraction.js, applied to named campaigns/operations
// this time (e.g. "Operation Triangulation", "the MOVEit campaign",
// "SolarWinds Compromise"). No hardcoded/manually-maintained list: a
// campaign a vendor names before MITRE ATT&CK ever catalogs it (if it ever
// does -- ATT&CK's own Campaigns list is sparse and, confirmed live in
// server/connectors/attack.js, gives campaigns no real display name beyond
// their code) still gets its own record the first time news names it.
import { ollamaJson } from "./rag/ollamaClient.js";
import { OLLAMA_CHAT_MODEL } from "./rag/config.js";

export const MAX_CAMPAIGNS_PER_ARTICLE = 3;

const SYSTEM_PROMPT =
  "You are a threat intelligence analyst. You will be given one security news article's headline and, if available, its summary. " +
  'Identify every explicitly named cyberattack CAMPAIGN or OPERATION mentioned (e.g. "Operation Triangulation", "the MOVEit campaign", "SolarWinds Compromise", "Volt Typhoon campaign"). ' +
  "A campaign name refers to a specific named operation/incident/intrusion, not a malware family, not a threat-actor/group name, and not a generic phrase. " +
  "Do NOT include: malware/tool/family names (e.g. Bumblebee, Cobalt Strike), threat actor/group names (e.g. APT29, FIN7, LockBit), CVE IDs, victim/vendor/company names, or generic terms (\"the attack\", \"the campaign\", \"the breach\" alone). " +
  'Respond with ONLY a JSON array of strings, using each name\'s exact capitalization as written in the text. Return [] if no campaign is named. No other text.';

function parseJsonArray(text) {
  const start = text.indexOf("[");
  const end = text.lastIndexOf("]");
  if (start === -1 || end === -1 || end < start) return [];
  try {
    const parsed = JSON.parse(text.slice(start, end + 1));
    return Array.isArray(parsed) ? parsed.filter((x) => typeof x === "string") : [];
  } catch {
    return []; // model returned malformed JSON -- treat as "found nothing" rather than guessing
  }
}

/**
 * Extracts candidate campaign/operation names from one article's headline +
 * summary via the local model. Returns raw candidates, not yet validated --
 * see validateCandidates below for the filtering step.
 */
export async function extractCampaignMentions({ title, summary }) {
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
