// Turns one vendor/CISA advisory article into a structured SOC intelligence
// report -- built for detection engineers, threat hunters, IR, and security
// leadership, not a news summary. Same hybrid-grounding philosophy as the
// rest of this app (see server/newsCorrelation.js, server/githubIntel/enrich.js):
// facts this app can already verify (CVE IDs, KEV/EPSS status, severity, raw
// IOCs) are extracted with proven regex/lookup logic, never trusted to the
// model's own recall. The local LLM is only asked for the parts that
// genuinely require synthesis -- narrative analysis, detection/hunting
// guidance, and its own self-assessed confidence/risk scoring -- which is
// also why the prompt is smaller and more reliable than asking the model to
// invent CVE IDs or hashes from scratch.
import { ollamaJson } from "./rag/ollamaClient.js";
import { OLLAMA_CHAT_MODEL } from "./rag/config.js";
import { extractEntities } from "./githubIntel/extractor.js";

const SYSTEM_PROMPT =
  "You are a Senior Cyber Threat Intelligence Analyst in an enterprise SOC. You convert a single security article into actionable SOC intelligence for detection engineers, threat hunters, incident responders, and security leadership. " +
  "Never write like a news summary -- every field must be actionable and specific to what this article actually says. If the article doesn't give you enough to answer a field meaningfully, say so plainly (e.g. \"Not specified in source\") rather than inventing detail. " +
  "\n\nRespond with ONLY a single JSON object with exactly these keys:\n" +
  '"executiveSummary": 2-3 sentences a CISO could read in 10 seconds -- what happened and why it matters.\n' +
  '"businessImpact": 1-3 sentences on operational/financial/reputational impact if this affects the org.\n' +
  '"threatOverview": a paragraph explaining the technical nature of the threat (vuln class, attack vector, exploitation method, or campaign behavior).\n' +
  '"affectedProducts": array of strings naming the specific affected product(s)/version(s) as stated in the article.\n' +
  '"vendor": the primary vendor name this article concerns, or null if not product-specific.\n' +
  '"threatActors": array of named threat actor/group strings explicitly named in the article (real, verified group names only -- [] if none named).\n' +
  '"malwareFamily": array of named malware/tool family strings explicitly named in the article ([] if none named).\n' +
  '"mitreAttack": array of {"techniqueId": "T1234" or null, "techniqueName": string, "tactic": string} for techniques the article\'s described behavior maps to -- best-effort, base your mapping only on behavior actually described.\n' +
  '"detectionOpportunities": array of concrete, specific detection ideas (log sources, event IDs, telemetry, behavioral signatures) a detection engineer could act on today.\n' +
  '"threatHuntingQueries": array of hunting query sketches (KQL/Splunk SPL/Sigma-style pseudocode is fine) a hunter could adapt to their own SIEM.\n' +
  '"immediateRecommendations": array of concrete, prioritized actions a SOC should take right now.\n' +
  '"patchInformation": string describing patch/mitigation status per the article, or null if not mentioned.\n' +
  '"confidenceScore": integer 0-100 -- your own confidence that this report accurately reflects the source article (lower if the article is vague, secondhand, or speculative).\n' +
  '"aiRiskScore": integer 0-100 -- your own overall risk rating for this threat (considers exploitability, active exploitation, blast radius, and severity of impact described).\n' +
  "No other text, no markdown formatting, no code fences.";

function safeArray(value) {
  return Array.isArray(value) ? value.filter((v) => typeof v === "string" && v.trim()) : [];
}

function safeMitreArray(value) {
  if (!Array.isArray(value)) return [];
  return value
    .filter((v) => v && typeof v === "object" && typeof v.techniqueName === "string")
    .map((v) => ({
      techniqueId: typeof v.techniqueId === "string" ? v.techniqueId : null,
      techniqueName: v.techniqueName,
      tactic: typeof v.tactic === "string" ? v.tactic : "Unknown",
    }));
}

function clampScore(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return null;
  return Math.max(0, Math.min(100, Math.round(n)));
}

function parseModelReport(text) {
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start === -1 || end === -1 || end < start) return null;
  try {
    const parsed = JSON.parse(text.slice(start, end + 1));
    if (!parsed || typeof parsed !== "object") return null;
    return {
      executiveSummary: typeof parsed.executiveSummary === "string" ? parsed.executiveSummary : "",
      businessImpact: typeof parsed.businessImpact === "string" ? parsed.businessImpact : "",
      threatOverview: typeof parsed.threatOverview === "string" ? parsed.threatOverview : "",
      affectedProducts: safeArray(parsed.affectedProducts),
      vendor: typeof parsed.vendor === "string" && parsed.vendor.trim() ? parsed.vendor : null,
      threatActors: safeArray(parsed.threatActors),
      malwareFamily: safeArray(parsed.malwareFamily),
      mitreAttack: safeMitreArray(parsed.mitreAttack),
      detectionOpportunities: safeArray(parsed.detectionOpportunities),
      threatHuntingQueries: safeArray(parsed.threatHuntingQueries),
      immediateRecommendations: safeArray(parsed.immediateRecommendations),
      patchInformation: typeof parsed.patchInformation === "string" && parsed.patchInformation.trim() ? parsed.patchInformation : null,
      confidenceScore: clampScore(parsed.confidenceScore),
      aiRiskScore: clampScore(parsed.aiRiskScore),
    };
  } catch {
    return null; // model returned malformed JSON -- treat as "couldn't generate," not a guess
  }
}

const IOC_TYPES = ["sha256", "sha1", "md5", "ipv4", "ipv6", "domains", "urls"];

function extractIocs(text) {
  const extracted = extractEntities(text, {});
  const iocs = [];
  for (const type of IOC_TYPES) {
    for (const value of extracted[type] ?? []) iocs.push({ type, value });
  }
  return iocs;
}

/**
 * @param {object} article - {title, summary, link, source, publishedDate}
 * @param {object} grounded - already-verified per-article facts from server/newsCorrelation.js#tagNewsItems
 * @param {string[]} grounded.cveIds
 * @param {string} grounded.severity
 * @param {object} grounded.cveEnrichment - cveId -> {severity, cvssScore, knownExploited, epssScore, sourceUrl}, see server/routes/dashboard.js#correlateCves-style enrichment
 */
export async function generateThreatSummary(article, grounded) {
  const sourceText = `${article.title}\n${article.summary ?? ""}`;
  const iocs = extractIocs(sourceText);

  const userContent =
    `Source: ${article.source}\nHeadline: ${article.title}\n` +
    (article.summary ? `Summary: ${article.summary}\n` : "") +
    (grounded.cveIds.length ? `CVE IDs already confirmed present in this article: ${grounded.cveIds.join(", ")}\n` : "");

  const response = await ollamaJson("/api/chat", {
    model: OLLAMA_CHAT_MODEL,
    messages: [
      { role: "system", content: SYSTEM_PROMPT },
      { role: "user", content: userContent },
    ],
    options: { temperature: 0.2 },
  });

  const modelReport = parseModelReport(response.message?.content ?? "");
  if (!modelReport) return null;

  return {
    id: article.link,
    articleTitle: article.title,
    articleLink: article.link,
    articleSource: article.source,
    publishedDate: article.publishedDate,
    generatedAt: new Date().toISOString(),
    severity: grounded.severity,
    cves: grounded.cveIds.map((id) => grounded.cveEnrichment?.[id] ?? { id, severity: "UNKNOWN", cvssScore: null, knownExploited: false, epssScore: null, sourceUrl: `https://nvd.nist.gov/vuln/detail/${id}` }),
    iocs,
    references: [
      { label: article.source, url: article.link },
      ...grounded.cveIds.map((id) => ({ label: id, url: `https://nvd.nist.gov/vuln/detail/${id}` })),
    ],
    ...modelReport,
  };
}
