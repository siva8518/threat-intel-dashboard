// Turns one vendor/CISA advisory article into a full enterprise-grade SOC
// threat intelligence report -- built for Tier 1/2/3 analysts, incident
// responders, threat hunters, detection engineers, security architects, and
// leadership, not a news summary. Same hybrid-grounding philosophy as the
// rest of this app (see server/newsCorrelation.js, server/githubIntel/enrich.js):
// facts this app can already verify (CVE IDs, KEV/EPSS status, severity, raw
// IOCs pulled from the article's own text) are extracted with proven
// regex/lookup logic, never trusted to the model's own recall -- this is
// also the mechanism that actually enforces the "never invent IOCs" rule
// below, not just a prompt instruction. The local LLM is only asked for the
// parts that genuinely require synthesis: narrative analysis, attack-chain
// reconstruction, detection/hunting/IR guidance, and its own self-assessed
// confidence/risk scoring.
//
// Report shape (v2): collapsed from ~15 narrative sections down to three --
// businessRisk, technicalAnalysis, operationalActions -- driven by an
// explicit reasoning chain (what happened / why it matters / who's affected
// / is exploitation confirmed) rather than a flat "summarize this" ask, and
// with operationalActions organized per-team with platform-specific
// specificity (real event IDs/tables, named hunting hypotheses, existing-
// rule awareness) instead of generic "monitor logs" advice. Verified/
// grounded fields (cves, iocs, mitreAttack, threatActors, malware,
// references) are unchanged -- this redesign only touches the model's own
// synthesis, not the extraction pipeline.
import { groqJson } from "./groqClient.js";
import { extractEntities } from "./githubIntel/extractor.js";
import { detectionRulesFor } from "./correlate.js";
import { fetchArticleText } from "./lib/articleText.js";

// Groq's largest generally-available free-tier model -- this report's own
// schema is exactly the kind of output a smaller model struggles to fill
// out reliably (confirmed live earlier with a local 1.5B-parameter model
// producing mostly "Not Reported"/empty fields) -- so this stays on the
// strongest free option rather than trading down for speed/quota headroom.
const GROQ_CHAT_MODEL = process.env.GROQ_CHAT_MODEL || "llama-3.3-70b-versatile";

const SYSTEM_PROMPT =
  "You are a Principal Cyber Threat Intelligence Analyst supporting an enterprise SOC, Detection Engineering, Incident Response, Threat Hunting, and Security Leadership. " +
  "Your objective is NOT to summarize the article -- it is to transform it into operational intelligence a security team can immediately act on. Never copy the article's own wording. Never use vendor marketing language. Never invent IOCs, CVE IDs, or facts not stated or reasonably inferable from the article -- if something isn't reported, say exactly \"Not Reported\" for that field rather than guessing. Clearly keep confirmed information separate from your own inference. " +
  "Work through this reasoning chain before writing any field, and let it drive the technicalAnalysis section specifically: (1) What happened -- what is the vulnerability/attack, named specifically, not abstracted. (2) Why it matters -- what does an attacker actually gain, what's the blast radius. (3) Who is affected -- which products, environments, or user populations. (4) Is exploitation confirmed -- active exploitation, PoC only, or theoretical, with the evidence for that classification. " +
  "This is a TECHNICAL EXTRACTION task, not an executive summary, for every field below except where a field is explicitly marked as business-language. Do not compress or abstract away technical specifics: if the article names a specific vulnerability class, attack technique, configuration setting, trigger, parameter, API, or mechanism, that exact name belongs in your output -- \"attackers abused GitHub Actions\" is not acceptable when the article says \"a pwn request vulnerability via a pull_request_target-triggered workflow, which runs in the context of the base repository with access to repository secrets.\" " +
  "For every piece of detection/hunting/engineering guidance, replace generic advice with the specific telemetry that actually detects this: real Windows Event IDs, Sysmon event IDs, EDR table/schema names (Microsoft Defender for Endpoint advanced hunting tables, CrowdStrike event names, etc.), Splunk sourcetypes/indexes, Sentinel table names, firewall/proxy log fields -- \"monitor logs\" or \"detect unauthorized access\" is not acceptable when a specific, real telemetry source applies. For threat hunting, do not say \"hunt for suspicious activity\" -- state the actual hypothesis a hunter should validate (e.g. \"internet-facing instances of the affected service exposed before the patch date\", \"unexpected admin logins immediately following exploitation\", \"process spawning from the affected web service\"), which data source proves or disproves it, and what a genuine positive looks like versus a benign false positive. For detection engineering, first ask whether Sigma, Elastic, or Microsoft-native rules already exist for this activity (real ones are supplied to you separately when found -- reason about whether those are sufficient or need updating) before asking the model to draft new logic, and note expected false-positive sources and any real detection gaps. " +
  "Before finalizing, remove duplicated content -- if the same fact or recommendation would appear in two fields, keep it in the one field it belongs in and leave the other field's array/string empty rather than repeating it. Do not pad any list to look complete; an accurate short list beats a padded long one. " +
  "\n\nRespond with ONLY a single JSON object with exactly these top-level keys (all string fields: use \"Not Reported\" if the article doesn't support an answer; all array fields: use [] if none apply -- never pad with generic filler):\n" +
  '"executiveHeadline": a single headline (under 12 words) an executive skimming a list of reports would see first, e.g. "Critical WordPress flaw under active exploitation -- patch this week." Grounded only in what the article states, never sensationalized beyond it.\n' +
  '"executiveSummary": 2-4 sentences, written for an executive audience with zero technical jargon, that will be read as-is with no further context -- clear and crisp, and grounded ONLY in what the article/verified data actually supports (never speculate, never invent a detail to sound more complete). It MUST answer, in this order: (1) what this means for the business in concrete terms -- financial, operational, reputational, legal/compliance exposure, stated directly rather than vaguely; (2) what decision or action is being asked of the reader right now (e.g. approve an emergency patch window, allocate remediation budget, authorize customer notification) -- if nothing is currently being asked of leadership, say so explicitly (e.g. "No executive decision is required at this time; the SOC is handling remediation.") rather than omitting it.\n' +
  '"businessRisk": {"businessRisk": string, "operationalDisruption": string, "likelihoodOfExploitation": string, "impactIfUnpatched": string, "industriesCommonlyTargeted": string[], "regionsCommonlyTargeted": string[], "requiresExecutiveAttention": boolean, "topActions": string[] (the single most important 1-3 actions across every team -- not a repeat of every recommendation elsewhere, just the top priorities), "whatsMissing": string or null (what information a reader would want that this article/data genuinely doesn\'t provide -- null if nothing notable is missing)} -- regionsCommonlyTargeted: specific countries/regions the article says are impacted, targeted, or where victims/exploitation were observed, [] if the article doesn\'t specify geography -- never guess a region the article doesn\'t state.\n' +
  '"technicalAnalysis": {"whatHappened": string, "whyItMatters": string (technical/operational significance -- what an attacker gains, the blast radius -- distinct from the business-language executiveSummary), "whoIsAffected": string, "exploitationStatus": string (state plainly: confirmed active exploitation / public PoC only / theoretical, with the evidence), "attackVector": string[], "rootCause": string[], "exploitationDetails": string[], "technicalFindings": string[], "attackChain": string (1-2 sentence kill-chain overview), "initialAccess": string|null, "privilegeEscalation": string|null, "execution": string|null, "persistence": string|null, "defenseEvasion": string|null, "lateralMovement": string|null, "commandAndControl": string|null, "dataTheft": string|null, "ransomwareDeployment": string|null, "products": string[], "versions": string[], "operatingSystems": string[], "cloudServices": string[], "applications": string[], "vendorSeverity": string, "activeExploitation": string, "overallSocPriority": "Critical"|"High"|"Medium"|"Low"} -- kill-chain fields: null (not "Not Reported") for any stage not described in the article, do not fabricate a kill chain the article doesn\'t support. affectedProducts fields: exactly as named in the article. vendorSeverity is the vendor\'s own stated rating, not your own guess -- CVSS/EPSS/KEV are supplied separately, don\'t restate them here. Every bullet should read like it came from a technical researcher, not a press release -- name the specific thing, don\'t generalize it away.\n' +
  '"mitreAttack": array of {"technique": string, "techniqueId": string or null, "reason": string (why this technique applies, grounded in what the article describes), "killChainPhase": string} -- techniqueId MUST be copied exactly from the CANDIDATE MITRE ATT&CK TECHNIQUES list in the user message, or null if none genuinely apply. Never invent a technique ID that isn\'t in that list, even if it looks plausible.\n' +
  '"threatActors": array of {"group": string, "aliases": string[], "motivation": string|null, "targetSectors": string[], "geography": string|null, "knownCampaigns": string[]} -- only actors explicitly named in the article.\n' +
  '"malware": array of {"family": string, "capabilities": string[], "persistence": string|null, "payload": string|null, "deliveryMechanism": string|null} -- only malware explicitly named in the article.\n' +
  '"operationalActions": {\n' +
  '  "socAnalyst": {"telemetryToCheck": string[] (real, specific telemetry sources for THIS attack -- e.g. "Windows Event ID 4688 (process creation) for the child process spawned by the web service", "Sysmon Event ID 3 (network connection) for outbound C2 beacons", "Microsoft Defender for Endpoint DeviceProcessEvents / DeviceNetworkEvents advanced hunting tables", "firewall/proxy logs for requests to the vulnerable endpoint path" -- never just "logs" or "EDR telemetry" with no specifics), "whatToLookFor": string (the specific indicator/behavior that confirms this is happening in this environment), "immediateNextStep": string (the concrete next step if the indicator is found)},\n' +
  '  "threatHunter": {"hypotheses": array of {"hypothesis": string (a specific, testable hunting hypothesis grounded in this attack\'s actual behavior, e.g. "internet-facing instances of the affected service still unpatched", "unexpected administrative logins immediately following the exploitation window", "process spawning from the vulnerable web service"), "dataSources": string[] (what to query to test it), "positiveFindingLooksLike": string, "falsePositiveNote": string (what a benign explanation for the same signal would look like)} -- 2-4 hypotheses, each genuinely distinct, not restatements of each other},\n' +
  '  "detectionEngineer": {"existingRulesAvailable": string[] (your own knowledge of whether public Sigma/Elastic/Microsoft-native detection rules already cover this activity -- name them if you know of specific ones, otherwise state plainly that none are known to exist yet; real, verified public rule matches are supplied separately and merged in automatically, don\'t restate those), "recommendedAction": string (update an existing rule vs. author a new one, and why), "yaraApplicable": string or null (is YARA a fit here -- e.g. for a dropped payload/webshell -- or null if not applicable to this attack type), "newDetectionLogic": string[] (concrete new detection logic to build, described precisely enough for an engineer to implement -- not vague "add a rule"), "logSourcesRequired": string[], "expectedFalsePositives": string, "detectionGaps": string[] (what this attack could still evade even with the above detections in place)},\n' +
  '  "vulnerabilityManagement": {"applicable": boolean (false if this article involves no specific CVE -- if false, every other field in this object should be "Not Applicable"/[]), "affectedAssetsSummary": string (affected products/versions and how to identify/scope them in a typical environment), "internetFacing": string, "exploitMaturity": string (weaponized/PoC/theoretical), "patchPriority": string, "maintenanceWindowRecommendation": string, "businessCriticality": string, "compensatingControls": string[] (if patching must be delayed), "knownWorkaround": string or null},\n' +
  '  "incidentResponse": {"immediateTriageSteps": string[], "containmentActions": string[], "recoveryActions": string[]},\n' +
  '  "threatIntelTakeaway": string (a detailed paragraph, 3-5 sentences -- attribution and campaign tracking, correlating this activity/actor/malware against existing intelligence holdings, watching for related infrastructure or TTPs reappearing elsewhere, and who internally needs this disseminated),\n' +
  '  "executiveLeadershipTakeaway": string (under 100 words, the business risk with zero technical jargon)\n' +
  '}\n' +
  '"confidenceAssessment": {"level": "High"|"Medium"|"Low", "reasoning": string} -- your confidence this report accurately reflects the source article. reasoning MUST explain the specific reason for that level (e.g. "High: the article includes a full technical writeup with confirmed IOCs and a named vendor" or "Medium: the article covers the vulnerability but exploitation details beyond the vendor advisory are limited") -- this reasoning is shown directly to the analyst, so a vague or generic sentence is not acceptable.\n' +
  '"aiRiskScoring": {"score": integer 0-100, "priority": "Critical"|"High"|"Medium"|"Low", "reasoning": string} -- build the score by adding: active exploitation +20, ransomware usage +15, public PoC +15, internet-exposed service +15, privilege escalation +10, authentication bypass +15, critical CVSS +10, widely deployed software +10; subtract points if exploitation requires unlikely conditions. Explain which factors applied.\n' +
  "No other text, no markdown formatting, no code fences.";

function safeArray(value) {
  return Array.isArray(value) ? value.filter((v) => typeof v === "string" && v.trim()) : [];
}

function safeString(value, fallback = "Not Reported") {
  return typeof value === "string" && value.trim() ? value : fallback;
}

function safeNullableString(value) {
  return typeof value === "string" && value.trim() ? value : null;
}

function safeBoolean(value) {
  return typeof value === "boolean" ? value : false;
}

// Matches an optional immediately-adjacent paren pair too, so a mention the
// model already wrote as "Name (T1234)" doesn't get double-wrapped into
// "Name (Name (T1234))" -- captured separately so the replacer can tell the
// two shapes apart. Deliberately no \s* around the paren/ID -- an earlier
// version had that and it silently ate legitimate word-separating
// whitespace between unrelated matches (e.g. turned "T1204.002, T1204.001"
// into "...002),Malicious..." by swallowing the space after the comma).
const TECHNIQUE_MENTION_PATTERN = /(\()?\b(T\d{4}(?:\.\d{3})?)\b(\))?/gi;

// Same grounding principle as safeMitreArray further down, extended to
// free-text fields it never touches (technicalAnalysis's narrative/kill-
// chain fields) -- confirmed live the model sometimes leaks a bare
// technique-ID token into these narrative fields instead of an actual
// description (e.g. initialAccess coming back as literally "T1689" rather
// than prose). Real IDs get annotated with their real name for readability;
// anything that doesn't match the synced catalog is stripped rather than
// left as an unverifiable claim embedded in prose.
function groundTechniqueMentions(text, validTechniqueIds, idToTechniqueName) {
  if (typeof text !== "string" || !text.trim()) return text;
  const grounded = text.replace(TECHNIQUE_MENTION_PATTERN, (_match, openParen, idPart, closeParen) => {
    const id = idPart.toUpperCase();
    const wasParenthesized = Boolean(openParen && closeParen);
    if (!validTechniqueIds.has(id)) return "";
    if (wasParenthesized) return `(${id})`; // model already supplied its own name right before this -- don't re-annotate
    const name = idToTechniqueName.get(id);
    return name ? `${name} (${id})` : id;
  });
  return grounded
    .replace(/\(\s*\)/g, "")
    .replace(/\s{2,}/g, " ")
    .replace(/\s+([,.;:])/g, "$1")
    .trim();
}

function safeNullableGroundedString(value, validTechniqueIds, idToTechniqueName) {
  const str = safeNullableString(value);
  if (!str) return null;
  const grounded = groundTechniqueMentions(str, validTechniqueIds, idToTechniqueName);
  return grounded || null;
}

function safeGroundedString(value, validTechniqueIds, idToTechniqueName, fallback = "Not Reported") {
  const str = safeString(value, fallback);
  if (str === fallback) return str;
  return groundTechniqueMentions(str, validTechniqueIds, idToTechniqueName) || fallback;
}

function groundedBullets(values, validTechniqueIds, idToTechniqueName) {
  return safeArray(values)
    .map((v) => groundTechniqueMentions(v, validTechniqueIds, idToTechniqueName))
    .filter((v) => v && v.trim());
}

const SOC_PRIORITIES = new Set(["Critical", "High", "Medium", "Low"]);
function safePriority(value) {
  return SOC_PRIORITIES.has(value) ? value : "Medium";
}

const CONFIDENCE_LEVELS = new Set(["High", "Medium", "Low"]);
function safeConfidenceLevel(value) {
  return CONFIDENCE_LEVELS.has(value) ? value : "Low";
}

function safeBusinessRisk(v) {
  v ??= {};
  return {
    businessRisk: safeString(v.businessRisk),
    operationalDisruption: safeString(v.operationalDisruption),
    likelihoodOfExploitation: safeString(v.likelihoodOfExploitation),
    impactIfUnpatched: safeString(v.impactIfUnpatched),
    industriesCommonlyTargeted: safeArray(v.industriesCommonlyTargeted),
    regionsCommonlyTargeted: safeArray(v.regionsCommonlyTargeted),
    requiresExecutiveAttention: safeBoolean(v.requiresExecutiveAttention),
    topActions: safeArray(v.topActions).slice(0, 3),
    whatsMissing: safeNullableString(v.whatsMissing),
  };
}

function safeTechnicalAnalysis(v, validTechniqueIds, idToTechniqueName) {
  v ??= {};
  const ground = (val) => safeNullableGroundedString(val, validTechniqueIds, idToTechniqueName);
  const groundBullets = (val) => groundedBullets(val, validTechniqueIds, idToTechniqueName);
  return {
    whatHappened: safeGroundedString(v.whatHappened, validTechniqueIds, idToTechniqueName),
    whyItMatters: safeGroundedString(v.whyItMatters, validTechniqueIds, idToTechniqueName),
    whoIsAffected: safeString(v.whoIsAffected),
    exploitationStatus: safeGroundedString(v.exploitationStatus, validTechniqueIds, idToTechniqueName),
    attackVector: groundBullets(v.attackVector),
    rootCause: groundBullets(v.rootCause),
    exploitationDetails: groundBullets(v.exploitationDetails),
    technicalFindings: groundBullets(v.technicalFindings),
    attackChain: safeString(v.attackChain),
    initialAccess: ground(v.initialAccess),
    privilegeEscalation: ground(v.privilegeEscalation),
    execution: ground(v.execution),
    persistence: ground(v.persistence),
    defenseEvasion: ground(v.defenseEvasion),
    lateralMovement: ground(v.lateralMovement),
    commandAndControl: ground(v.commandAndControl),
    dataTheft: ground(v.dataTheft),
    ransomwareDeployment: ground(v.ransomwareDeployment),
    products: safeArray(v.products),
    versions: safeArray(v.versions),
    operatingSystems: safeArray(v.operatingSystems),
    cloudServices: safeArray(v.cloudServices),
    applications: safeArray(v.applications),
    vendorSeverity: safeString(v.vendorSeverity),
    activeExploitation: safeString(v.activeExploitation),
    overallSocPriority: safePriority(v.overallSocPriority),
  };
}

const TECHNIQUE_ID_SHAPE = /^T\d{4}(\.\d{3})?$/i;

// validTechniqueIds/techniqueNameToId/idToTechniqueName come from this app's
// own synced MITRE ATT&CK catalog (server/connectors/attack.js) -- the model
// is asked to only choose from a candidate subset in the prompt
// (buildTechniqueCandidatesBlock below), but this validates whatever
// actually comes back regardless of whether the model followed that
// instruction, the same "verify, don't trust recall" pattern used for
// CVEs/severity/IOCs elsewhere in this app. Confirmed live this catches two
// distinct failure modes: (1) outright fabrication -- a report once
// returned "T1042.003" for a supply-chain technique, which is factually
// wrong (T1042 is "Change Default File Association"); (2) field-swapping --
// a later report put a genuinely correct ID ("T1213.002", SharePoint data
// collection) into the `technique` (name) field instead of `techniqueId`,
// which the ID-only check above would have silently missed.
// Second-tier recovery for the exact-name lookup above: the model
// frequently paraphrases MITRE's own technique names (e.g. "Exploitation of
// Public-Facing Application" instead of MITRE's actual "Exploit
// Public-Facing Application" for T1190) well enough that a human reads it as
// obviously the same technique, but a plain case-insensitive string compare
// misses it -- confirmed live this was rendering as the "T????" placeholder
// for a completely standard, correctly-identified technique. Stripping
// filler words and crude-stemming common verb suffixes (-ation/-ing/-ed/-s)
// collapses both phrasings to the same key without ever inventing an ID that
// isn't already in the real catalog -- a normalized match still only ever
// resolves to a real (id, name) pair pulled from idToTechniqueName.
const MITRE_NAME_STOPWORDS = new Set(["of", "the", "a", "an", "via", "and", "or", "in", "on", "to", "for", "with"]);

function stemTechniqueWord(word) {
  if (word.length > 6 && word.endsWith("ation")) return word.slice(0, -5);
  if (word.length > 5 && word.endsWith("ing")) return word.slice(0, -3);
  if (word.length > 4 && word.endsWith("ed")) return word.slice(0, -2);
  if (word.length > 3 && word.endsWith("s") && !word.endsWith("ss")) return word.slice(0, -1);
  return word;
}

function normalizeTechniqueName(name) {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, "")
    .split(/\s+/)
    .filter((w) => w && !MITRE_NAME_STOPWORDS.has(w))
    .map(stemTechniqueWord)
    .sort()
    .join(" ");
}

function buildNormalizedNameToId(idToTechniqueName) {
  const map = new Map();
  for (const [id, name] of idToTechniqueName) {
    const key = normalizeTechniqueName(name);
    if (!map.has(key)) map.set(key, id);
  }
  return map;
}

function safeMitreArray(value, validTechniqueIds, techniqueNameToId, idToTechniqueName) {
  if (!Array.isArray(value)) return [];
  const normalizedNameToId = buildNormalizedNameToId(idToTechniqueName);
  return value
    .filter((v) => v && typeof v === "object" && typeof v.technique === "string")
    .map((v) => {
      let techniqueName = v.technique.trim();
      let rawId = typeof v.techniqueId === "string" ? v.techniqueId.trim().toUpperCase() : null;

      // Detect the model having swapped the two fields: `technique` holds
      // something shaped like "T1234" or "T1234.567" rather than a name.
      // Only trust it if it's also a real ID -- shape alone isn't enough.
      if (TECHNIQUE_ID_SHAPE.test(techniqueName)) {
        const candidateId = techniqueName.toUpperCase();
        if (validTechniqueIds.has(candidateId)) {
          rawId = candidateId;
          techniqueName = idToTechniqueName.get(candidateId) ?? techniqueName;
        }
      }

      let techniqueId = rawId && validTechniqueIds.has(rawId) ? rawId : null;
      if (!techniqueId) {
        // Bonus recovery, not a requirement: if the model got the real
        // technique name right but botched/omitted the ID, an exact
        // (case-insensitive) name match against the real catalog is safe to
        // backfill -- it's not a guess, it's looking up a name the model
        // already committed to.
        techniqueId = techniqueNameToId.get(techniqueName.toLowerCase()) ?? null;
      }
      if (!techniqueId) {
        techniqueId = normalizedNameToId.get(normalizeTechniqueName(techniqueName)) ?? null;
      }
      return {
        technique: techniqueName,
        techniqueId,
        reason: safeString(v.reason),
        killChainPhase: safeString(v.killChainPhase),
      };
    });
}

function safeThreatActors(value) {
  if (!Array.isArray(value)) return [];
  return value
    .filter((v) => v && typeof v === "object" && typeof v.group === "string" && v.group.trim())
    .map((v) => ({
      group: v.group,
      aliases: safeArray(v.aliases),
      motivation: safeNullableString(v.motivation),
      targetSectors: safeArray(v.targetSectors),
      geography: safeNullableString(v.geography),
      knownCampaigns: safeArray(v.knownCampaigns),
    }));
}

function safeMalware(value) {
  if (!Array.isArray(value)) return [];
  return value
    .filter((v) => v && typeof v === "object" && typeof v.family === "string" && v.family.trim())
    .map((v) => ({
      family: v.family,
      capabilities: safeArray(v.capabilities),
      persistence: safeNullableString(v.persistence),
      payload: safeNullableString(v.payload),
      deliveryMechanism: safeNullableString(v.deliveryMechanism),
    }));
}

function safeSocAnalyst(v) {
  v ??= {};
  return {
    telemetryToCheck: safeArray(v.telemetryToCheck),
    whatToLookFor: safeString(v.whatToLookFor),
    immediateNextStep: safeString(v.immediateNextStep),
  };
}

function safeThreatHunter(v) {
  v ??= {};
  const hypotheses = Array.isArray(v.hypotheses) ? v.hypotheses : [];
  return {
    hypotheses: hypotheses
      .filter((h) => h && typeof h === "object" && typeof h.hypothesis === "string" && h.hypothesis.trim())
      .map((h) => ({
        hypothesis: h.hypothesis.trim(),
        dataSources: safeArray(h.dataSources),
        positiveFindingLooksLike: safeString(h.positiveFindingLooksLike),
        falsePositiveNote: safeString(h.falsePositiveNote),
      })),
  };
}

function safeDetectionEngineer(v) {
  v ??= {};
  return {
    existingRulesAvailable: safeArray(v.existingRulesAvailable),
    recommendedAction: safeString(v.recommendedAction),
    yaraApplicable: safeNullableString(v.yaraApplicable),
    newDetectionLogic: safeArray(v.newDetectionLogic),
    logSourcesRequired: safeArray(v.logSourcesRequired),
    expectedFalsePositives: safeString(v.expectedFalsePositives),
    detectionGaps: safeArray(v.detectionGaps),
  };
}

function safeVulnerabilityManagement(v) {
  v ??= {};
  const applicable = safeBoolean(v.applicable);
  if (!applicable) {
    return {
      applicable: false,
      affectedAssetsSummary: "Not Applicable",
      internetFacing: "Not Applicable",
      exploitMaturity: "Not Applicable",
      patchPriority: "Not Applicable",
      maintenanceWindowRecommendation: "Not Applicable",
      businessCriticality: "Not Applicable",
      compensatingControls: [],
      knownWorkaround: null,
    };
  }
  return {
    applicable: true,
    affectedAssetsSummary: safeString(v.affectedAssetsSummary),
    internetFacing: safeString(v.internetFacing),
    exploitMaturity: safeString(v.exploitMaturity),
    patchPriority: safeString(v.patchPriority),
    maintenanceWindowRecommendation: safeString(v.maintenanceWindowRecommendation),
    businessCriticality: safeString(v.businessCriticality),
    compensatingControls: safeArray(v.compensatingControls),
    knownWorkaround: safeNullableString(v.knownWorkaround),
  };
}

function safeIncidentResponse(v) {
  v ??= {};
  return {
    immediateTriageSteps: safeArray(v.immediateTriageSteps),
    containmentActions: safeArray(v.containmentActions),
    recoveryActions: safeArray(v.recoveryActions),
  };
}

function safeOperationalActions(v) {
  v ??= {};
  return {
    socAnalyst: safeSocAnalyst(v.socAnalyst),
    threatHunter: safeThreatHunter(v.threatHunter),
    detectionEngineer: safeDetectionEngineer(v.detectionEngineer),
    vulnerabilityManagement: safeVulnerabilityManagement(v.vulnerabilityManagement),
    incidentResponse: safeIncidentResponse(v.incidentResponse),
    threatIntelTakeaway: safeString(v.threatIntelTakeaway),
    executiveLeadershipTakeaway: safeString(v.executiveLeadershipTakeaway),
  };
}

function safeConfidenceAssessment(v) {
  v ??= {};
  return { level: safeConfidenceLevel(v.level), reasoning: safeString(v.reasoning) };
}

function safeAiRiskScoring(v) {
  v ??= {};
  const n = Number(v.score);
  return {
    score: Number.isFinite(n) ? Math.max(0, Math.min(100, Math.round(n))) : null,
    priority: safePriority(v.priority),
    reasoning: safeString(v.reasoning),
  };
}

function parseModelReport(text, validTechniqueIds, techniqueNameToId, idToTechniqueName) {
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start === -1 || end === -1 || end < start) return null;
  try {
    const parsed = JSON.parse(text.slice(start, end + 1));
    if (!parsed || typeof parsed !== "object") return null;
    return {
      executiveHeadline: safeString(parsed.executiveHeadline),
      executiveSummary: safeString(parsed.executiveSummary),
      businessRisk: safeBusinessRisk(parsed.businessRisk),
      technicalAnalysis: safeTechnicalAnalysis(parsed.technicalAnalysis, validTechniqueIds, idToTechniqueName),
      mitreAttack: safeMitreArray(parsed.mitreAttack, validTechniqueIds, techniqueNameToId, idToTechniqueName),
      threatActors: safeThreatActors(parsed.threatActors),
      malware: safeMalware(parsed.malware),
      operationalActions: safeOperationalActions(parsed.operationalActions),
      confidenceAssessment: safeConfidenceAssessment(parsed.confidenceAssessment),
      aiRiskScoring: safeAiRiskScoring(parsed.aiRiskScoring),
    };
  } catch {
    return null; // model returned malformed JSON -- treat as "couldn't generate," not a guess
  }
}

// Only the IOC types this app can extract with proven, regex-verified logic
// (server/githubIntel/extractor.js, already used elsewhere in this app) are
// populated -- mutex names, registry keys, scheduled tasks, services, user
// agents, certificates etc. have no reliable extraction path from prose news
// text, so rather than ask the model to fabricate them (directly violating
// the "never invent IOCs" rule), those categories are always reported empty.
const IOC_CATEGORY_BY_TYPE = {
  ipv4: "ipAddresses",
  ipv6: "ipAddresses",
  domains: "domains",
  urls: "urls",
  sha256: "hashes",
  sha1: "hashes",
  md5: "hashes",
  emails: "emailAddresses",
};

function extractIocs(text) {
  const extracted = extractEntities(text, {});
  const categories = { ipAddresses: [], domains: [], urls: [], hashes: [], emailAddresses: [] };
  for (const [type, category] of Object.entries(IOC_CATEGORY_BY_TYPE)) {
    for (const value of extracted[type] ?? []) categories[category].push(value);
  }
  return categories;
}

const TECHNIQUE_CANDIDATE_LIMIT = 30;

// Keyword-overlap scoring against this app's own synced MITRE ATT&CK catalog
// (server/connectors/attack.js), same weighted-keyword-match philosophy as
// server/githubIntel/classifier.js -- not a semantic match, just enough to
// hand the model a short, plausible, real-ID candidate list instead of
// letting it free-associate from ~600 techniques' worth of training memory.
function selectCandidateTechniques(article, techniques) {
  const words = new Set(`${article.title} ${article.summary ?? ""}`.toLowerCase().match(/[a-z0-9]{4,}/g) ?? []);
  if (words.size === 0) return [];
  const scored = [];
  for (const t of techniques) {
    const nameWords = t.name.toLowerCase().match(/[a-z0-9]{4,}/g) ?? [];
    const score = nameWords.filter((w) => words.has(w)).length;
    if (score > 0) scored.push({ t, score });
  }
  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, TECHNIQUE_CANDIDATE_LIMIT).map((s) => s.t);
}

function buildTechniqueCandidatesBlock(candidates) {
  if (candidates.length === 0) {
    return "CANDIDATE MITRE ATT&CK TECHNIQUES: none pre-matched this article's keywords. Set techniqueId to null for every entry unless you are certain of a real, well-known technique ID -- never invent one.";
  }
  const lines = candidates.map((t) => `${t.id} -- ${t.name} (${t.tactic})`).join("\n");
  return `CANDIDATE MITRE ATT&CK TECHNIQUES (techniqueId must be copied exactly from this list, or null if none genuinely apply):\n${lines}`;
}

// Grounds the detection engineer's "existingRulesAvailable" field the same
// way the rest of this module grounds CVEs/IOCs/MITRE IDs: cross-references
// the model's own named malware families/threat actors (not the model's
// invented rule content) against server/connectors/detectionRules.js's
// real, synced index of ~4000 SigmaHQ/Yara-Rules community rules, via the
// exact same substring-match helper server/correlate.js already uses
// elsewhere in this app. Real hits are appended (not swapped in), so the
// model's own narrative about rule coverage isn't lost.
const MAX_DETECTION_RULE_HITS = 8;

function groundExistingRules(modelReport, ruleIndex) {
  if (!ruleIndex?.length) return modelReport;

  const names = [...modelReport.malware.map((m) => m.family), ...modelReport.threatActors.map((a) => a.group)].filter((n) => n && n !== "Not Reported");

  const seen = new Set();
  const hits = [];
  for (const name of names) {
    for (const hit of detectionRulesFor(name, ruleIndex)) {
      const key = `${hit.label}:${hit.path}`;
      if (seen.has(key)) continue;
      seen.add(key);
      hits.push(`${hit.label} (public, existing rule): ${hit.path} -- ${hit.url}`);
    }
  }
  if (hits.length === 0) return modelReport;

  return {
    ...modelReport,
    operationalActions: {
      ...modelReport.operationalActions,
      detectionEngineer: {
        ...modelReport.operationalActions.detectionEngineer,
        existingRulesAvailable: [...modelReport.operationalActions.detectionEngineer.existingRulesAvailable, ...hits].slice(0, MAX_DETECTION_RULE_HITS),
      },
    },
  };
}

/**
 * @param {object} article - {title, summary, link, source, publishedDate}
 * @param {object} grounded - already-verified per-article facts from server/newsCorrelation.js#tagNewsItems
 * @param {string[]} grounded.cveIds
 * @param {string} grounded.severity - uppercase Severity ("CRITICAL"/"HIGH"/"MEDIUM"/"LOW")
 * @param {object} grounded.cveEnrichment - cveId -> {severity, cvssScore, knownExploited, epssScore, sourceUrl}
 * @param {Array} grounded.attackTechniques - this app's synced MITRE ATT&CK technique catalog, {id, name, tactic}[]
 * @param {Array} grounded.detectionRuleIndex - server/connectors/detectionRules.js's synced SigmaHQ/YARA-Rules filename-word index
 */
export async function generateThreatSummary(article, grounded) {
  // The RSS title+summary alone is a ~200-400 character teaser -- nowhere
  // near enough for the "preserve every technical detail" brief below.
  // Confirmed live a Datadog Security Labs report on CVE-2026-31431 came
  // back with detection engineering, hunting queries, IR guidance, patch
  // info, and every role takeaway empty/"Not Reported", not because the
  // model hallucinated or failed, but because the real article (19,774
  // characters, with a full SECL detection rule chain and working hunting
  // queries) was never given to it -- only a 271-character blurb was.
  // fetchArticleText() never throws; a paywalled/blocked/slow source just
  // falls back to the RSS summary exactly as before.
  const articleText = await fetchArticleText(article.link, article.source);
  const sourceText = `${article.title}\n${article.summary ?? ""}\n${articleText ?? ""}`;
  const iocs = extractIocs(sourceText);

  const cveContext = grounded.cveIds
    .map((id) => {
      const c = grounded.cveEnrichment?.[id];
      return `${id}: CVSS ${c?.cvssScore ?? "unknown"}, KEV ${c?.knownExploited ? "yes" : "no"}, EPSS ${c?.epssScore ?? "unknown"}`;
    })
    .join("; ");

  const techniques = grounded.attackTechniques ?? [];
  const candidateTechniques = selectCandidateTechniques(article, techniques);
  const validTechniqueIds = new Set(techniques.map((t) => t.id));
  const techniqueNameToId = new Map(techniques.map((t) => [t.name.toLowerCase(), t.id]));
  const idToTechniqueName = new Map(techniques.map((t) => [t.id, t.name]));

  const userContent =
    `Source: ${article.source}\nHeadline: ${article.title}\n` +
    (articleText
      ? `Full Article Text (use this as your primary source -- extract every concrete technical detail, detection rule, query, and recommendation it contains):\n${articleText}\n`
      : article.summary
        ? `Summary (full article text was unavailable -- work only from this, and use "Not Reported"/[] for anything it doesn't cover): ${article.summary}\n`
        : "") +
    (cveContext ? `Verified CVE data for this article (use this, don't restate or contradict it): ${cveContext}\n` : "") +
    `Overall severity already computed for this article: ${grounded.severity}\n` +
    `${buildTechniqueCandidatesBlock(candidateTechniques)}\n`;

  // Groq is a hosted service with its own large context window (well past
  // what this prompt + article text + completion ever needs), so none of
  // the num_ctx/keep_alive tuning the old local-Ollama call needed here
  // applies -- that was all working around this machine's own limited free
  // RAM, not a property of the model or the task itself.
  const response = await groqJson({
    model: GROQ_CHAT_MODEL,
    messages: [
      { role: "system", content: SYSTEM_PROMPT },
      { role: "user", content: userContent },
    ],
    temperature: 0.2,
  });

  const modelReport = parseModelReport(response.message?.content ?? "", validTechniqueIds, techniqueNameToId, idToTechniqueName);
  if (!modelReport) return null;

  const groundedReport = groundExistingRules(modelReport, grounded.detectionRuleIndex);

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
    ...groundedReport,
  };
}
