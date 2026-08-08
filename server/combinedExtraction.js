// Single combined-prompt entity extraction from one article's headline +
// summary -- replaces six separate per-article LLM calls
// (malwareExtraction.js#extractMalwareNames, threatActorExtraction.js#extractActorMentions,
// campaignExtraction.js#extractCampaignMentions, attackTechniqueExtraction.js#extractTechniqueMentions,
// darkWebExtraction.js's finding candidates, toolExtraction.js's tool-name
// candidates) with one call asking for all six entity kinds at once. One
// well-specified multi-part extraction is about as reliable as six separate
// single-part ones, and this cuts LLM calls (the actual per-article
// bottleneck) 6x. Each extraction module's own validateCandidates/
// resolveTechniques still runs unchanged afterward -- only the "ask the
// model" step is merged.
//
// Runs through server/ai/aiRouter.js's Gemini->Mistral->Groq->Cohere
// failover, not local Ollama -- deliberately swapped so this pipeline (and
// the five Intelligence tabs it feeds: Malware/Actor/Campaign/Dark Web/
// Tools) works in any environment with at least one configured provider key,
// including a hosted demo deploy with no local model installed, and keeps
// running if any single provider is down/rate-limited. Requests each
// provider's {tier: "fast"} model (see server/ai/config.js) -- this prompt
// is a much lighter six-category name/ID extraction, not a 25+ section
// report, and the smaller/cheaper tier carries a materially higher
// free-tier rate limit, which matters more here since this job runs
// continuously against dozens of articles per cycle rather than once a day.
// The RAG chatbot (server/rag/) is a separate consumer and stays on local
// Ollama -- none of these providers has an embedding endpoint, so none can
// serve that half regardless.
import { aiRouter } from "./ai/aiRouter.js";
import { AI_TASK } from "./ai/aiTasks.js";

const SYSTEM_PROMPT =
  "You are a threat intelligence analyst. You will be given one security news article's headline and, if available, its summary. " +
  "Extract SIX kinds of entities, each only when explicitly named/ID'd in the text -- never infer one from a general behavior description. " +
  "\n\n1. MALWARE: every malware, ransomware, or trojan FAMILY NAME (e.g. \"Bumblebee\", \"DarkGate\", \"Lumma Stealer\", \"AsyncRAT\", \"QakBot\"). " +
  "Do NOT include threat actor/group names, CVE IDs, generic terms (\"malware\", \"ransomware\", \"trojan\" alone), company names, or legitimate/dual-use tool names even when abused -- those go under TOOLS instead. " +
  '\n\n2. ACTORS: every threat actor or intrusion-set/group name (e.g. "APT29", "FIN7", "LockBit", "Scattered Spider"). For each, classify its TYPE using ONLY one of: "APT", "Cybercrime", "Ransomware", "Hacktivist", "Initial Access Broker", "Insider", "Unknown" (nation-state/espionage -> APT; a ransomware gang/operation -> Ransomware; a financially-motivated crime group -> Cybercrime; a hacktivist collective -> Hacktivist; a group that sells network access -> Initial Access Broker; a malicious insider -> Insider; unclear -> Unknown). ' +
  "Do NOT include malware/tool/family names, CVE IDs, victim/vendor/company names, product names, or generic terms (\"hackers\", \"attackers\", \"threat actor\" alone). " +
  '\n\n3. CAMPAIGNS: every explicitly named cyberattack CAMPAIGN or OPERATION (e.g. "Operation Triangulation", "the MOVEit campaign", "SolarWinds Compromise"). A campaign name refers to a specific named operation/incident, not a malware family, not a threat-actor name, and not a generic phrase like "the attack" or "the breach". ' +
  '\n\n4. TECHNIQUES: every MITRE ATT&CK technique explicitly mentioned by ID (e.g. "T1055", "T1071.001") or exact named technique/sub-technique (e.g. "Process Injection", "Spearphishing Attachment", "DLL Side-Loading"). Do not infer one from a general behavior description unless it is actually named. ' +
  '\n\n5. DARKWEB: only when the article describes ONE SPECIFIC underground-forum/marketplace/leak-site/Telegram posting that a researcher or vendor actually observed -- a specific database being sold or leaked, a specific initial-access listing, a specific ransomware group\'s leak-site post about a real victim, a specific credential dump for sale. ' +
  "Do NOT extract anything from an article that only discusses forums/marketplaces/underground activity in GENERAL or STATISTICAL terms -- forum activity trends, how many tutorials/posts were made, marketplace-economy commentary, a research report about how criminals operate -- with no single specific posting/listing/leak actually named or described. If nothing in the text names a real, specific finding, return [] for this category; do NOT invent a plausible-sounding one and do NOT reuse any example wording from these instructions. " +
  'For each real finding found, return an object: {"label": a short factual title in your own words describing exactly what this article says (never a placeholder company name), "type": one of "Data Leak", "Credential Dump", "Initial Access Listing", "Marketplace Listing", "Forum Discussion", "Extortion Threat", "Other", "platform": the named forum/marketplace/channel if the text states one (e.g. "BreachForums", "XSS", "Exploit.in", "Telegram"), else null, "victimOrg": the named victim organization if the text names one, else null}. ' +
  '\n\n6. TOOLS: every named MALICIOUS or DUAL-USE TOOL a threat actor is reported to have used, deployed, or abused -- remote access/administration software, C2 frameworks, penetration-testing/red-team utilities, credential-dumping or lateral-movement utilities, off-the-shelf RATs (e.g. "Cobalt Strike", "Mimikatz", "PsExec", "Impacket", "AnyDesk", "Sliver", "BloodHound", "Rclone", "ngrok", "PowerShell Empire"). ' +
  'This is a real, legitimate, or dual-use piece of software being reported as USED BY an attacker -- not a purpose-built malicious FAMILY (those go under MALWARE) and not the threat actor/group itself (those go under ACTORS). ' +
  '\n\nRespond with ONLY a single JSON object with exactly these six keys: ' +
  '"malware" (array of strings), "actors" (array of {"name","type"} objects), "campaigns" (array of strings), "techniques" (array of strings), "darkweb" (array of {"label","type","platform","victimOrg"} objects), "tools" (array of strings). ' +
  "Use each name's exact capitalization as written in the text. Use [] for any category with nothing found. No other text.";

function parseJsonObject(text) {
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  const empty = { malware: [], actors: [], campaigns: [], techniques: [], darkweb: [], tools: [] };
  if (start === -1 || end === -1 || end < start) return empty;
  try {
    const parsed = JSON.parse(text.slice(start, end + 1));
    if (!parsed || typeof parsed !== "object") return empty;
    return {
      malware: Array.isArray(parsed.malware) ? parsed.malware.filter((x) => typeof x === "string") : [],
      actors: Array.isArray(parsed.actors) ? parsed.actors.filter((x) => x && typeof x === "object" && typeof x.name === "string") : [],
      campaigns: Array.isArray(parsed.campaigns) ? parsed.campaigns.filter((x) => typeof x === "string") : [],
      techniques: Array.isArray(parsed.techniques) ? parsed.techniques.filter((x) => typeof x === "string") : [],
      darkweb: Array.isArray(parsed.darkweb) ? parsed.darkweb.filter((x) => x && typeof x === "object" && typeof x.label === "string") : [],
      tools: Array.isArray(parsed.tools) ? parsed.tools.filter((x) => typeof x === "string") : [],
    };
  } catch {
    return empty; // model returned malformed JSON -- treat as "found nothing" rather than guessing
  }
}

/**
 * Extracts all six entity-kind candidates from one article's headline +
 * summary via a single hosted-model call. Returns raw candidates, not yet
 * validated -- each kind is still run through its own module's
 * validateCandidates/resolveTechniques exactly as before the merge.
 */
export async function extractAllEntities({ title, summary }) {
  const userContent = summary ? `Headline: ${title}\nSummary: ${summary}` : `Headline: ${title}`;
  const response = await aiRouter.summarizeJson(userContent, { systemPrompt: SYSTEM_PROMPT, temperature: 0, tier: "fast", task: AI_TASK.SUMMARY });
  return parseJsonObject(response.summary ?? "");
}
