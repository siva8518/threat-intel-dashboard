// AI-drafted candidate Sigma/YARA rule for one Detection Backlog gap --
// closes the loop from "we don't have a rule for this" (server/detectionBacklog.js)
// to an actual starting-point rule a human can review, instead of only ever
// flagging the gap. Same Groq wiring as server/aiThreatSummary.js and
// server/industryBriefing.js. Explicitly a DRAFT: every response carries a
// confidence level and an explanation, and the rule's own metadata says so --
// this app never claims an AI-generated detection rule is validated or safe
// to deploy as-is. Generated on demand (one gap at a time, triggered from the
// UI), not scheduled/bulk -- with 200+ open gaps in the backlog at once,
// eagerly drafting all of them would be both slow and mostly wasted work
// against gaps nobody's actively triaging yet.
import { groqJson, GroqUnavailableError } from "./groqClient.js";

const GROQ_CHAT_MODEL = process.env.GROQ_CHAT_MODEL || "llama-3.3-70b-versatile";

export const DRAFT_RULE_FORMATS = ["sigma", "yara"];
const CONFIDENCE_LEVELS = new Set(["High", "Medium", "Low"]);
const MAX_RELATED_RULES = 5;

// Loose keyword overlap against the same rule-name index
// server/correlate.js's detectionRulesFor()/detectionRulesForCve() already
// use for the "is there a public rule?" gate that put this item in the
// backlog in the first place -- surfaced to the model as "don't just
// reproduce one of these, and say so if one might already substantially
// cover this" so a fresh sync between backlog-build time and draft time can
// still self-correct instead of confidently drafting a true duplicate.
// Every entity/CVE-derived gap description repeats this app's own fixed
// boilerplate phrasing ("no matching public YARA/Sigma rule was found --
// confirm a custom detection exists, or build one"), which trivially
// self-matches rule-repo infrastructure filenames (e.g. SigmaHQ's own
// "sigma-rule-deprecated.yml" CI workflow) via the plain words "sigma"/
// "yara"/"rule" themselves -- confirmed live this drowned out any genuinely
// subject-relevant match. Filtered out here rather than from
// server/connectors/detectionRules.js's own STOPWORDS, since those words are
// legitimate/meaningful there (a real rule literally about Sigma internals);
// they're only noise in THIS module's specific boilerplate-heavy input text.
const BOILERPLATE_WORDS = new Set([
  "sigma", "yara", "rule", "rules", "malware", "detect", "detection", "detected",
  "found", "matching", "public", "confirm", "custom", "exists", "build", "exploited",
]);

function relatedRules(text, ruleIndex) {
  const words = new Set((text.toLowerCase().match(/[a-z0-9]{4,}/g) ?? []).filter((w) => !BOILERPLATE_WORDS.has(w)));
  if (words.size === 0 || !ruleIndex?.length) return [];
  const seenPaths = new Set();
  const matches = [];
  for (const row of ruleIndex) {
    if (!words.has(row.word) || seenPaths.has(row.path)) continue;
    seenPaths.add(row.path);
    matches.push(row);
    if (matches.length >= MAX_RELATED_RULES) break;
  }
  return matches;
}

const SYSTEM_PROMPT =
  "You are a Detection Engineer drafting a STARTING-POINT candidate detection rule for a named gap in a Detection Backlog. " +
  "You will be given a gap description (and sometimes a related CVE and source article) and must draft exactly ONE rule, in whichever format genuinely fits better: " +
  "Sigma (YAML, log/telemetry-based -- the right choice for most gaps: process creation, network connections, auth events, MITRE ATT&CK techniques, log-source-driven detections) " +
  "or YARA (file/byte/string-pattern based -- only when the gap is fundamentally about matching file content, a malware family's static indicators, or similar). " +
  "This is explicitly a DRAFT for a human Detection Engineer to review, adapt, and test -- never claim it is validated, tuned, or ready to deploy as-is. " +
  "Do not invent specific IOCs (hashes, IPs, domains) that were not given to you -- if the gap doesn't supply one, write a rule around the described behavior/technique instead, using placeholder field names a real analyst would recognize and fill in (e.g. a named but empty selection list), not a fabricated indicator. " +
  "If a list of possibly-related existing public rules is given, do not just reproduce one -- write something that adds value, and mention in your explanation if one of them might already substantially cover this gap.\n\n" +
  "SIGMA SKELETON (follow this structure, fill in real content, omit fields that don't apply):\n" +
  "title: <short, specific title>\n" +
  "status: experimental\n" +
  "description: <what this detects and why>\n" +
  "author: AI-drafted (Cyber Intelligence Platform) -- requires human review\n" +
  "date: <YYYY/MM/DD>\n" +
  "tags:\n    - attack.<tactic>\n    - attack.<txxxx if known>\n" +
  "logsource:\n    category: <e.g. process_creation, network_connection, dns_query>\n    product: <e.g. windows, linux, azure>\n" +
  "detection:\n    selection:\n        <FieldName>: <value or list>\n    condition: selection\n" +
  "falsepositives:\n    - <known false positive scenario, or 'Unknown'>\n" +
  "level: <informational|low|medium|high|critical>\n\n" +
  "YARA SKELETON (follow this structure, fill in real content):\n" +
  "rule <RuleName_no_spaces>\n{\n    meta:\n        description = \"...\"\n        author = \"AI-drafted (Cyber Intelligence Platform) -- requires human review\"\n        date = \"<YYYY-MM-DD>\"\n        reference = \"<source article URL if given>\"\n    strings:\n        $s1 = \"...\" ascii wide\n    condition:\n        any of them\n}\n\n" +
  "Respond with ONLY a single JSON object with exactly these keys:\n" +
  '"format": "sigma" | "yara"\n' +
  '"ruleTitle": string, short and specific\n' +
  '"ruleContent": string, the FULL raw rule text (the skeleton above filled in for real, not the literal placeholder text) -- this is copy-pasted directly into a file, so no markdown code fences and no commentary inside it\n' +
  '"explanation": string, 2-4 sentences: what this detects, why this approach, and any caveats (false-positive risk, missing telemetry, tuning needed)\n' +
  '"confidence": "High" | "Medium" | "Low" -- your honest confidence this is a directly useful starting point vs. a rough skeleton\n' +
  "No other text, no markdown formatting, no code fences.";

function safeString(value, fallback = "") {
  return typeof value === "string" && value.trim() ? value.trim() : fallback;
}

function parseDraft(text) {
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start === -1 || end === -1 || end < start) return null;
  try {
    const parsed = JSON.parse(text.slice(start, end + 1));
    const ruleContent = safeString(parsed?.ruleContent);
    if (!ruleContent) return null;
    return {
      format: DRAFT_RULE_FORMATS.includes(parsed?.format) ? parsed.format : "sigma",
      ruleTitle: safeString(parsed?.ruleTitle, "Untitled draft rule"),
      ruleContent,
      explanation: safeString(parsed?.explanation, "No explanation provided."),
      confidence: CONFIDENCE_LEVELS.has(parsed?.confidence) ? parsed.confidence : "Low",
    };
  } catch {
    return null; // model returned malformed JSON -- treat as "couldn't generate," not a guess
  }
}

/**
 * @param {object} item - a Detection Backlog item (server/detectionBacklog.js's output shape)
 * @param {Array} [ruleIndex] - server/connectors/detectionRules.js's synced {word, path, url, label}[] index
 */
export async function generateDraftRule(item, ruleIndex = []) {
  const related = relatedRules(`${item.description} ${item.articleTitle ?? ""}`, ruleIndex);
  const relatedBlock = related.length
    ? `\nPOSSIBLY-RELATED EXISTING PUBLIC RULES (filenames only from YARA-Rules/SigmaHQ, not full content -- don't assume these fully cover the gap, but don't blindly duplicate them either):\n${related.map((r) => `- ${r.label}: ${r.path}`).join("\n")}\n`
    : "";

  const userContent =
    `DETECTION GAP TO DRAFT A RULE FOR:\n` +
    `Category: ${item.categoryLabel}\n` +
    `Gap description: ${item.description}\n` +
    `Severity: ${item.severity}\n` +
    (item.cveIds?.length ? `Related CVE(s): ${item.cveIds.join(", ")}\n` : "") +
    `Source article: "${item.articleTitle}" (${item.articleSource})\n` +
    relatedBlock +
    `\nDraft ONE candidate detection rule for a Detection Engineer to review.`;

  let parsed;
  try {
    const response = await groqJson({
      model: GROQ_CHAT_MODEL,
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: userContent },
      ],
      temperature: 0.2,
    });
    parsed = parseDraft(response.message?.content ?? "");
  } catch (error) {
    if (error instanceof GroqUnavailableError) throw error;
    throw new GroqUnavailableError(`failed to generate draft rule (${error.message})`);
  }
  if (!parsed) throw new GroqUnavailableError("model returned an unusable draft -- try again");

  return {
    ...parsed,
    relatedRules: related.map((r) => ({ label: r.label, path: r.path, url: r.url })),
    model: GROQ_CHAT_MODEL,
    generatedAt: new Date().toISOString(),
  };
}
