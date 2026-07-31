// AI-drafted detection artifacts for one Detection Backlog gap -- closes the
// loop from "we don't have a rule for this" (server/detectionBacklog.js) to
// actual starting-point artifacts a human can review, instead of only ever
// flagging the gap. Same Groq wiring as server/aiThreatSummary.js and
// server/industryBriefing.js.
//
// Unlike the single-rule version this replaced, every one of the 12 artifact
// types below is independently assessed: each is either genuinely supported
// by the gap's own description/CVE/article context (Sigma, three query
// languages, YARA, two network-rule languages, IOC/analytic-rule
// recommendations, hunting hypotheses, detection-engineering notes) or
// explicitly marked Not Generated with a reason -- never silently padded out
// with a plausible-looking artifact the evidence doesn't actually support.
// Most gaps in this backlog are thin (a CISA ICS advisory naming no raw
// IOCs, or a bare ATT&CK technique attribution) -- for those, YARA/Suricata/
// Snort/Defender-IOC-recs will correctly and routinely come back Not
// Generated while the lower-bar behavioral/hunting/engineering artifacts
// still generate. A mostly-Not-Generated response is the CORRECT output for
// a low-signal gap, not an incomplete one.
//
// Every Generated artifact is explicitly a DRAFT: confidence level,
// human-review flag, and missing-information notes travel with it, and this
// app never claims an AI-generated rule is validated or safe to deploy as-is.
// Generated on demand (one gap at a time, triggered from the UI), not
// scheduled/bulk -- with 200+ open gaps in the backlog at once, eagerly
// drafting all of them would be both slow and mostly wasted work against
// gaps nobody's actively triaging yet.
import { groqJson, GroqUnavailableError } from "./groqClient.js";

const GROQ_CHAT_MODEL = process.env.GROQ_CHAT_MODEL || "llama-3.3-70b-versatile";

const CONFIDENCE_LEVELS = new Set(["High", "Medium", "Low"]);
const MAX_RELATED_RULES = 5;

// {key, label, guidance} -- guidance is the per-type "what counts as
// genuinely supported" bar handed to the model, since the eight rule/query
// artifacts have real, different technical floors (YARA needs a file/byte-
// level indicator; Suricata/Snort need a real network-protocol specific;
// the three log-query languages need an inferable log source + condition)
// while the last four (recommendations/hypotheses/engineering notes) are
// intentionally lower-bar and should generate for almost any real gap.
const ARTIFACT_TYPES = [
  {
    key: "sigmaRule",
    label: "Sigma Rule",
    guidance:
      "Supported when the gap describes a specific, log-source-observable behavior (a process/registry/network/auth event pattern) precise enough to express as a Sigma detection block. Not supported for a bare technique name with no described observable.",
  },
  {
    key: "sentinelKql",
    label: "Microsoft Sentinel KQL",
    guidance:
      "Supported when a specific Sentinel/Log Analytics table (e.g. SecurityEvent, Syslog, CommonSecurityLog, a named connector table) and a concrete filter/join condition can be reasonably inferred from the gap.",
  },
  {
    key: "defenderXdrKql",
    label: "Microsoft Defender XDR Advanced Hunting KQL",
    guidance:
      "Supported when the behavior maps to a real Defender XDR advanced hunting table (DeviceProcessEvents, DeviceNetworkEvents, DeviceRegistryEvents, DeviceFileEvents, IdentityLogonEvents, EmailEvents, etc.) with an inferable filter condition.",
  },
  {
    key: "splunkSpl",
    label: "Splunk SPL",
    guidance: "Supported when a log source/sourcetype and a searchable field pattern can be reasonably inferred from the gap.",
  },
  {
    key: "elasticEql",
    label: "Elastic EQL",
    guidance: "Supported when a specific event category (process, network, file, registry) and sequence/condition can be expressed precisely from the gap.",
  },
  {
    key: "yaraRule",
    label: "YARA Rule",
    guidance:
      "Supported ONLY when there is a described file-level/static indicator (a dropped payload, a webshell, a named malware family with described static characteristics). NOT supported for a pure network/logic vulnerability with no file artifact -- this is the single most commonly Not Generated artifact in this backlog, and that is correct.",
  },
  {
    key: "suricataRule",
    label: "Suricata Rule",
    guidance:
      "Supported ONLY when there is a genuine described network-level indicator (a specific protocol field, port, payload byte pattern, or C2 URI pattern). Not supported for a vague \"network activity\" mention with no protocol-level specifics.",
  },
  {
    key: "snortRule",
    label: "Snort Rule",
    guidance: "Same bar as Suricata above -- a genuine network-protocol-level specific, not a vague network mention.",
  },
  {
    key: "defenderIocRecommendations",
    label: "Microsoft Defender IOC Recommendations",
    guidance: "Supported ONLY when at least one concrete IOC (hash/IP/domain/URL) is present in the given context to recommend adding as a custom indicator -- this is IOC-driven, not behavior-driven, so most gaps here will legitimately be Not Generated.",
  },
  {
    key: "sentinelAnalyticRuleRecommendations",
    label: "Microsoft Sentinel Analytic Rule Recommendations",
    guidance: "Lower bar than full KQL: supported whenever there is a genuine, specific new detection concept to describe (rule idea, MITRE mapping, schedule/threshold), even without complete query syntax.",
  },
  {
    key: "threatHuntingHypotheses",
    label: "Threat Hunting Hypotheses",
    guidance: "Lower bar: supported whenever the gap gives a genuine, specific, testable hypothesis (never \"hunt for suspicious activity\") -- almost always generatable for any real behavioral gap.",
  },
  {
    key: "detectionEngineeringRecommendations",
    label: "Detection Engineering Recommendations",
    guidance: "Lowest bar: process/coverage-level notes (build vs. update an existing rule, log sources needed, expected false positives, what additional data would close the remaining gap) -- almost always generatable since this is about the detection program, not raw technical content.",
  },
];
export const ARTIFACT_TYPE_KEYS = ARTIFACT_TYPES.map((t) => t.key);
const ARTIFACT_LABEL = new Map(ARTIFACT_TYPES.map((t) => [t.key, t.label]));

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

function buildArtifactTypesBlock() {
  return ARTIFACT_TYPES.map((t, i) => `${i + 1}. "${t.key}" (${t.label}) -- ${t.guidance}`).join("\n");
}

const SYSTEM_PROMPT =
  "You are a Senior Detection Engineer and Threat Intelligence Analyst. Analyze the detection gap and its context given to you below and independently assess, for EACH of the 12 artifact types listed, whether it is genuinely supported by the evidence given. " +
  "Generate an artifact ONLY when it is fully supported by the intelligence provided -- never invent IOCs, file paths, registry keys, domains, hashes, IP addresses, command lines, or ATT&CK technique IDs. If a technical value is not explicitly present in the context below, do not fabricate one to fill a field -- either write the artifact around the described BEHAVIOR using a named-but-empty placeholder a real analyst would fill in, or mark that artifact Not Generated if there genuinely isn't enough to build anything meaningful. Never generate an artifact just because the type is on the list -- most gaps in this backlog are thin advisories with no raw file/network indicators, so a response where most of the 12 come back Not Generated is the CORRECT, honest output for those, not an incomplete one. " +
  "If a list of possibly-related existing public rules is given (Sigma/YARA only), do not just reproduce one -- write something that adds value, and mention in that artifact's implementationNotes if one of them might already substantially cover the gap.\n\n" +
  "THE 12 ARTIFACT TYPES AND THEIR SUPPORT BAR:\n" +
  `${buildArtifactTypesBlock()}\n\n` +
  "SIGMA SKELETON (fill in real content, omit fields that don't apply):\n" +
  "title: <short, specific title>\nstatus: experimental\ndescription: <what this detects and why>\nauthor: AI-drafted (Cyber Intelligence Platform) -- requires human review\ndate: <YYYY/MM/DD>\ntags:\n    - attack.<tactic>\n    - attack.<txxxx if known>\nlogsource:\n    category: <e.g. process_creation, network_connection, dns_query>\n    product: <e.g. windows, linux, azure>\ndetection:\n    selection:\n        <FieldName>: <value or list>\n    condition: selection\nfalsepositives:\n    - <known false positive scenario, or 'Unknown'>\nlevel: <informational|low|medium|high|critical>\n\n" +
  "YARA SKELETON:\nrule <RuleName_no_spaces>\n{\n    meta:\n        description = \"...\"\n        author = \"AI-drafted (Cyber Intelligence Platform) -- requires human review\"\n        date = \"<YYYY-MM-DD>\"\n        reference = \"<source article URL if given>\"\n    strings:\n        $s1 = \"...\" ascii wide\n    condition:\n        any of them\n}\n\n" +
  "For sentinelKql/defenderXdrKql/splunkSpl/elasticEql: write a complete, real, runnable query against the real table/index/sourcetype naming convention of that platform -- not pseudocode. For suricataRule/snortRule: a complete, real rule line in that platform's own syntax (alert <proto> ... msg:\"...\"; sid:<a placeholder like 9000001>; rev:1;). For defenderIocRecommendations/sentinelAnalyticRuleRecommendations: concise, concrete write-ups (2-5 sentences or a short bullet list), not a full rule syntax. For threatHuntingHypotheses: 1-3 specific, testable hypotheses with what data source proves/disproves each. For detectionEngineeringRecommendations: 2-4 concrete, concise recommendations.\n\n" +
  "Respond with ONLY a single JSON object with exactly one key, \"artifacts\": an array of EXACTLY 12 entries, one per type above in the exact order listed, each shaped:\n" +
  '{"type": string (copied exactly from the type list, e.g. "sigmaRule"), "status": "Generated" | "Not Generated", ' +
  '"content": string or null (the FULL raw rule/query/recommendation text if Generated -- copy-pasted directly, no markdown code fences, no commentary inside it; null if Not Generated), ' +
  '"confidence": "High" | "Medium" | "Low" or null (your honest confidence this is a directly useful starting point vs. a rough skeleton; null if Not Generated), ' +
  '"humanReviewRequired": boolean or null (true for essentially every Generated artifact -- this app never claims an AI-drafted artifact is deploy-ready; null if Not Generated), ' +
  '"missingInformation": string[] (what would strengthen this artifact further even though it was still genuinely generatable -- [] if nothing notable is missing; [] if Not Generated), ' +
  '"implementationNotes": string or null (caveats, false-positive risk, tuning needed, or a note that an existing public rule might already cover this; null if Not Generated), ' +
  '"reason": string or null (why this artifact could NOT be generated -- null if Generated), ' +
  '"requiredInformation": string[] (what specific technical detail, if it existed in the source reporting, would have made this artifact generatable -- [] if Generated), ' +
  '"suggestedIntelligenceCollection": string[] (what a Threat Intelligence analyst could go collect/request to close that gap -- e.g. "Request the vendor advisory\'s full IOC appendix", "Sandbox the described payload for static strings" -- [] if Generated)}\n' +
  "No other text, no markdown formatting, no code fences outside the artifact content fields themselves.";

function safeString(value, fallback = null) {
  return typeof value === "string" && value.trim() ? value.trim() : fallback;
}

function safeStringArray(value) {
  return Array.isArray(value) ? value.filter((v) => typeof v === "string" && v.trim()).map((v) => v.trim()) : [];
}

/** Every artifact is validated defensively regardless of which branch (Generated/Not Generated) the model actually populated -- a model that gets the status/field pairing wrong still produces a safe, consistently-shaped result rather than a half-null object. */
function safeArtifact(raw, type) {
  const status = raw?.status === "Generated" ? "Generated" : "Not Generated";
  const content = status === "Generated" ? safeString(raw?.content) : null;
  if (status === "Generated" && !content) {
    // Model claimed Generated but supplied no real content -- treat as Not Generated rather than show an empty artifact card.
    return {
      type,
      label: ARTIFACT_LABEL.get(type) ?? type,
      status: "Not Generated",
      content: null,
      confidence: null,
      humanReviewRequired: null,
      missingInformation: [],
      implementationNotes: null,
      reason: "Model did not supply usable content for this artifact.",
      requiredInformation: [],
      suggestedIntelligenceCollection: [],
    };
  }
  return {
    type,
    label: ARTIFACT_LABEL.get(type) ?? type,
    status,
    content,
    confidence: status === "Generated" ? (CONFIDENCE_LEVELS.has(raw?.confidence) ? raw.confidence : "Low") : null,
    humanReviewRequired: status === "Generated" ? raw?.humanReviewRequired !== false : null,
    missingInformation: status === "Generated" ? safeStringArray(raw?.missingInformation) : [],
    implementationNotes: status === "Generated" ? safeString(raw?.implementationNotes) : null,
    reason: status === "Not Generated" ? safeString(raw?.reason, "Not enough evidence in the source intelligence to generate this artifact.") : null,
    requiredInformation: status === "Not Generated" ? safeStringArray(raw?.requiredInformation) : [],
    suggestedIntelligenceCollection: status === "Not Generated" ? safeStringArray(raw?.suggestedIntelligenceCollection) : [],
  };
}

function parseArtifacts(text) {
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start === -1 || end === -1 || end < start) return null;
  try {
    const parsed = JSON.parse(text.slice(start, end + 1));
    if (!Array.isArray(parsed?.artifacts)) return null;
    const byType = new Map(parsed.artifacts.filter((a) => a && typeof a.type === "string").map((a) => [a.type, a]));
    // Always return all 12 in the fixed order, regardless of what order (or
    // subset) the model returned -- a model that drops a type entirely still
    // gets a well-formed Not Generated entry for it rather than a missing card.
    return ARTIFACT_TYPE_KEYS.map((key) => safeArtifact(byType.get(key), key));
  } catch {
    return null; // model returned malformed JSON -- treat as "couldn't generate," not a guess
  }
}

/**
 * @param {object} item - a Detection Backlog item (server/detectionBacklog.js's output shape)
 * @param {Array} [ruleIndex] - server/connectors/detectionRules.js's synced {word, path, url, label}[] index
 */
export async function generateDraftArtifacts(item, ruleIndex = []) {
  const related = relatedRules(`${item.description} ${item.articleTitle ?? ""}`, ruleIndex);
  const relatedBlock = related.length
    ? `\nPOSSIBLY-RELATED EXISTING PUBLIC RULES (filenames only from YARA-Rules/SigmaHQ, not full content -- relevant to sigmaRule/yaraRule only; don't assume these fully cover the gap, but don't blindly duplicate them either):\n${related.map((r) => `- ${r.label}: ${r.path}`).join("\n")}\n`
    : "";

  const userContent =
    `DETECTION GAP TO ANALYZE:\n` +
    `Category: ${item.categoryLabel}\n` +
    `Gap description: ${item.description}\n` +
    `Severity: ${item.severity}\n` +
    (item.cveIds?.length ? `Related CVE(s): ${item.cveIds.join(", ")}\n` : "") +
    `Source article: "${item.articleTitle}" (${item.articleSource})\n` +
    relatedBlock +
    `\nAssess all 12 artifact types independently for a Detection Engineer to review.`;

  let artifacts;
  try {
    const response = await groqJson({
      model: GROQ_CHAT_MODEL,
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: userContent },
      ],
      temperature: 0.2,
    });
    artifacts = parseArtifacts(response.message?.content ?? "");
  } catch (error) {
    if (error instanceof GroqUnavailableError) throw error;
    throw new GroqUnavailableError(`failed to generate draft artifacts (${error.message})`);
  }
  if (!artifacts) throw new GroqUnavailableError("model returned an unusable response -- try again");

  return {
    artifacts,
    relatedRules: related.map((r) => ({ label: r.label, path: r.path, url: r.url })),
    model: GROQ_CHAT_MODEL,
    generatedAt: new Date().toISOString(),
  };
}
