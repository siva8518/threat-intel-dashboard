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
import { aiRouter } from "./ai/aiRouter.js";
import { extractEntities } from "./githubIntel/extractor.js";
import { detectionRulesFor } from "./correlate.js";
import { fetchArticleText } from "./lib/articleText.js";

const SYSTEM_PROMPT =
  "You are a Principal Cyber Threat Intelligence Analyst supporting an enterprise SOC, Detection Engineering, Incident Response, Threat Hunting, and Security Leadership. " +
  "Your objective is NOT to summarize the article -- it is to transform it into operational intelligence a security team can immediately act on. Never copy the article's own wording. Never use vendor marketing language. Never invent IOCs, CVE IDs, or facts not stated or reasonably inferable from the article -- if something isn't reported, say exactly \"Not Reported\" for that field rather than guessing. Clearly keep confirmed information separate from your own inference. " +
  "Work through this reasoning chain before writing any field, and let it drive the technicalAnalysis section specifically: (1) What happened -- what is the vulnerability/attack, named specifically, not abstracted. (2) Why it matters -- what does an attacker actually gain, what's the blast radius. (3) Who is affected -- which products, environments, or user populations. (4) Is exploitation confirmed -- active exploitation, PoC only, or theoretical, with the evidence for that classification. " +
  "This is a TECHNICAL EXTRACTION task, not an executive summary, for every field below except where a field is explicitly marked as business-language. Do not compress or abstract away technical specifics: if the article names a specific vulnerability class, attack technique, configuration setting, trigger, parameter, API, or mechanism, that exact name belongs in your output -- \"attackers abused GitHub Actions\" is not acceptable when the article says \"a pwn request vulnerability via a pull_request_target-triggered workflow, which runs in the context of the base repository with access to repository secrets.\" " +
  "For every piece of detection/hunting/engineering guidance, replace generic advice with the specific telemetry that actually detects this: real Windows Event IDs, Sysmon event IDs, EDR table/schema names (Microsoft Defender for Endpoint advanced hunting tables, CrowdStrike event names, etc.), Splunk sourcetypes/indexes, Sentinel table names, firewall/proxy log fields -- \"monitor logs\" or \"detect unauthorized access\" is not acceptable when a specific, real telemetry source applies. For threat hunting, do not say \"hunt for suspicious activity\" -- state the actual hypothesis a hunter should validate (e.g. \"internet-facing instances of the affected service exposed before the patch date\", \"unexpected admin logins immediately following exploitation\", \"process spawning from the affected web service\"), which data source proves or disproves it, and what a genuine positive looks like versus a benign false positive. For detection engineering, first ask whether Sigma, Elastic, or Microsoft-native rules already exist for this activity (real ones are supplied to you separately when found -- reason about whether those are sufficient or need updating) before asking the model to draft new logic, and note expected false-positive sources and any real detection gaps. " +
  "Every field below must answer a genuinely different question -- never let the same sentence, claim, or risk-level phrase (e.g. \"could allow unauthorized access\", \"poses a moderate risk\") appear in more than one of them. Specifically: executiveSummary answers \"what happened, in business terms\" (situational, not analysis or opinion); intelligenceAssessment answers \"why does this matter, and what's your judgment about it\" (your own analytic opinion, see below -- never a restatement of executiveSummary or technicalAnalysis); businessRisk is the executive-facing risk framing (financial/operational/reputational exposure) while operationalImpact is the separate SOC/analyst-facing operational reality (detection challenges, evasion, attacker objectives) -- these must not restate each other's sentences; exposureAssessment answers \"are we exposed\" (a self-service check, not analysis); operationalActions.socAnalyst/recommendedActions answer \"what should analysts do today\" (concrete, immediate); operationalActions.detectionEngineer answers \"can we detect it\" (detection posture); operationalActions.executiveLeadershipTakeaway answers \"does management specifically need to get personally involved, and why\" (a decision-relevance verdict, distinct from executiveSummary's situational read); operationalActions.threatIntelTakeaway answers \"is this part of a larger trend, and what should an analyst watch for next\" (forward-looking trajectory judgment, see below). If you catch yourself writing the same idea in two of these, delete it from every field except the single one it most belongs to. " +
  "Before finalizing, remove duplicated content -- if the same fact or recommendation would appear in two fields, keep it in the one field it belongs in and leave the other field's array/string empty rather than repeating it. This applies to narrative prose just as much as lists. Do not pad any list to look complete; an accurate short list beats a padded long one. " +
  "\n\nRespond with ONLY a single JSON object with exactly these top-level keys (all string fields: use \"Not Reported\" if the article doesn't support an answer; all array fields: use [] if none apply -- never pad with generic filler):\n" +
  '"executiveHeadline": a single headline (under 12 words) an executive skimming a list of reports would see first, e.g. "Critical WordPress flaw under active exploitation -- patch this week." Grounded only in what the article states, never sensationalized beyond it.\n' +
  '"executiveSummary": 2-4 sentences, written for an executive audience with zero technical jargon, that will be read as-is with no further context -- clear and crisp, and grounded ONLY in what the article/verified data actually supports (never speculate, never invent a detail to sound more complete). It MUST answer, in this order: (1) what this means for the business in concrete terms -- financial, operational, reputational, legal/compliance exposure, stated directly rather than vaguely; (2) what decision or action is being asked of the reader right now (e.g. approve an emergency patch window, allocate remediation budget, authorize customer notification) -- if nothing is currently being asked of leadership, say so explicitly (e.g. "No executive decision is required at this time; the SOC is handling remediation.") rather than omitting it. This is a situational read of what happened, not your analysis or opinion -- save judgment and trajectory reasoning for intelligenceAssessment.\n' +
  '"intelligenceAssessment": your own analytic judgment as a CTI analyst, not a restatement of facts already given elsewhere -- 2-4 concise paragraphs (separated by \\n\\n) that read as an opinion grounded in evidence and well-established threat-intelligence patterns. Never open with a generic risk-level phrase like "poses a moderate risk" or restate what the vulnerability "could allow" -- that\'s businessRisk\'s and technicalAnalysis\'s job, not this field\'s. Instead: name the specific underlying weakness being exposed (not the vulnerability description itself, which technicalAnalysis already covers), then make an actual judgment call about trajectory -- e.g. whether vulnerabilities of this type/mechanism/device class have historically moved quickly to automated exploitation or weaponization after disclosure, and what that implies defenders should do NOW rather than waiting for confirmed exploitation. Ground any historical-pattern claim in a clearly-hedged, defensible generalization about the vulnerability class/technique/device category (e.g. "similar weaknesses have historically been incorporated into automated exploitation shortly after public disclosure") -- never assert a specific unconfirmed fact about THIS incident (no invented exploitation, no invented actor, no invented campaign). This is the one field that should read as an opinion, not a report.\n' +
  '"businessRisk": {"businessRisk": string, "operationalDisruption": string, "likelihoodOfExploitation": string, "impactIfUnpatched": string, "industriesCommonlyTargeted": string[], "regionsCommonlyTargeted": string[], "requiresExecutiveAttention": boolean, "topActions": string[] (the single most important 1-3 actions across every team -- not a repeat of every recommendation elsewhere, just the top priorities), "whatsMissing": string or null (what information a reader would want that this article/data genuinely doesn\'t provide -- null if nothing notable is missing)} -- regionsCommonlyTargeted: specific countries/regions the article says are impacted, targeted, or where victims/exploitation were observed, [] if the article doesn\'t specify geography -- never guess a region the article doesn\'t state. This is the executive-facing risk framing only -- do not restate these sentences in operationalImpact, which covers the separate SOC/analyst-facing operational reality.\n' +
  '"shouldICare": {"verdict": "YES"|"NO"|"UNKNOWN", "reasoning": string} -- this app has no knowledge of the specific reader\'s own environment, so answer as a conditional decision aid, not a personalized verdict: "YES" if the affected technology is so broadly deployed or the exploitation so indiscriminate that almost any reader should assume it applies to them (e.g. a mass-exploited, widely-used product/library, or active internet-wide scanning); "NO" if the described risk is narrow, theoretical, vendor-internal, or otherwise not something a typical reader needs to act on (e.g. an AI research announcement, a already-patched issue with no current relevance); "UNKNOWN" (the common case for a specific-product vulnerability) with reasoning that tells the reader exactly what to check, e.g. "YES if you run Fortinet FortiOS or Arista VeloCloud Orchestrator; otherwise this specific advisory does not apply to you directly." Ground the verdict only in what the article states about affected products/scope -- never guess at a reader\'s stack.\n' +
  '"exposureAssessment": {"applicable": boolean (true only when the article describes a risk tied to a specific, nameable product/software a reader could check for -- false for threat-actor/malware-only, research, or non-product news, in which case every other field here is "Not Applicable"), "product": string (the single most relevant product/software a reader should check for, exactly as named in the article, e.g. "Microsoft Exchange Server", "FortiOS", "Ivanti Connect Secure"), "howToCheckVersion": string (a concrete, specific command or UI path a reader can run right now to find their installed version, e.g. "Exchange Management Shell: Get-ExchangeServer | ft Name, AdminDisplayVersion" or "Help > About" -- generic advice like "check your version" is not acceptable), "affectedVersions": string (exactly what the article/advisory states is affected, e.g. "Exchange Server 2019 before CU15, 2016 before CU24"), "affectedGuidance": string (what to do if the reader confirms they are on an affected version -- concrete and prioritized, e.g. "Patch immediately to the fixed build; this is under active exploitation"), "notAffectedGuidance": string (what to do if the reader confirms they are on a version NOT listed as affected, e.g. "No immediate action required; continue routine patch cadence")} -- this is a self-service exposure check the reader runs against their own environment (this app has no visibility into what the reader actually has installed) -- supply the check itself, never guess whether the reader personally has this product or which version they run.\n' +
  '"technicalAnalysis": {"whatHappened": string, "whyItMatters": string (technical/operational significance -- what an attacker gains, the blast radius -- distinct from the business-language executiveSummary), "whoIsAffected": string, "exploitationStatus": string (state plainly: confirmed active exploitation / public PoC only / theoretical, with the evidence), "attackVector": string[], "rootCause": string[], "exploitationDetails": string[], "technicalFindings": string[], "attackChain": string (1-2 sentence kill-chain overview), "initialAccess": string|null, "privilegeEscalation": string|null, "execution": string|null, "persistence": string|null, "defenseEvasion": string|null, "lateralMovement": string|null, "commandAndControl": string|null, "dataTheft": string|null, "ransomwareDeployment": string|null, "products": string[], "versions": string[], "operatingSystems": string[], "cloudServices": string[], "applications": string[], "vendorSeverity": string, "activeExploitation": string, "overallSocPriority": "Critical"|"High"|"Medium"|"Low"} -- kill-chain fields: null (not "Not Reported") for any stage not described in the article, do not fabricate a kill chain the article doesn\'t support. affectedProducts fields: exactly as named in the article. vendorSeverity is the vendor\'s own stated rating, not your own guess -- CVSS/EPSS/KEV are supplied separately, don\'t restate them here. Every bullet should read like it came from a technical researcher, not a press release -- name the specific thing, don\'t generalize it away.\n' +
  '"threatRelevance": {"industriesAtRisk": string[], "technologiesTargeted": string[], "geographicFocus": string[], "victimProfile": string (who is likely to be targeted or affected -- role, organization type, user population, not a repeat of technicalAnalysis.whoIsAffected\'s product-scoping answer), "initialAccessVector": string (how attackers most likely gain initial entry for THIS specific threat, e.g. "phishing email with malicious attachment", "exploitation of the internet-facing vulnerable service", "compromised credentials via password spray" -- state plainly, don\'t hedge)} -- ground every field only in what the article states or directly implies; [] or "Not Reported" if unsupported. Do not restate MITRE technique IDs here -- those belong in mitreAttack below.\n' +
  '"operationalImpact": {"businessImpact": string (the operational/systemic consequence for the SOC/analyst -- what actually breaks or is at risk operationally, not the executive risk framing already covered in businessRisk; do not restate businessRisk\'s or executiveSummary\'s sentences here), "detectionChallenges": string[] (specific, concrete reasons this activity is hard to detect with typical tooling -- e.g. "living-off-the-land binary abuse blends with legitimate admin activity", "C2 traffic uses valid TLS to a reputable CDN" -- never generic "hard to detect"), "evasionTechniques": string[] (specific evasion/anti-detection methods the article describes or that are well-documented for this technique/malware family -- name the actual method, not generic "obfuscation"), "attackerObjectives": string[] (what the attacker is actually trying to achieve here -- data theft, ransomware deployment, espionage, financial fraud, initial-access resale, etc., grounded in the article, not assumed)}\n' +
  '"industryRelevance": array of EXACTLY these 10 entries, one each, in this exact order and with these exact "industry" strings -- "Financial Services", "Consumer", "Technology, Media & Telecommunications", "Life Sciences & Health Care", "Manufacturing", "Energy & Utilities", "Government & Public Sector", "Retail & eCommerce", "Education", "Transportation & Logistics" -- each shaped {"industry": string (copied exactly from the list above), "relevance": "Critical"|"High"|"Medium"|"Low"|"Not Applicable", "confidence": "High"|"Medium"|"Low" (your confidence in the relevance call itself), "whyAffected": string (2-3 sentences: why attackers may target this sector, which business processes are at risk, which technologies common in this sector are relevant here, and why this sector is more or less applicable than others -- "Not Applicable" if relevance is Not Applicable), "potentialImpact": string[] (2-4 items, e.g. "Credential Theft", "Ransomware", "Business Email Compromise", "Customer Data Exposure" -- [] if Not Applicable), "likelyTargetAssets": string[] (2-4 items, e.g. "Active Directory", "SAP", "OT/ICS Systems", "VPN" -- [] if Not Applicable), "defensiveFocus": string[] (3-5 concrete, sector-specific recommendations, e.g. for Manufacturing: "Monitor OT/ICS segmentation", "Review engineering workstation access" -- never generic advice, [] if Not Applicable), "riskScore": integer 0-10, "priority": "Immediate"|"High"|"Normal"|"Low"} -- DO NOT rate every industry Critical or High: only assign Critical/High when there is a clear technical or operational reason grounded in what the article actually describes (the affected product/sector, the attack vector, who is named as a target); for the common case of a narrow, sector-agnostic vulnerability or an article that names no specific victim sector, most industries should be "Low" or "Not Applicable" -- a heatmap that is mostly Low/Not Applicable with 1-3 genuinely elevated sectors is correct, not incomplete. Ground every "why" in the article or in well-established sector/technology overlap (e.g. a vulnerability in a hospital-focused device is High for Life Sciences & Health Care) -- never invent a sector-specific detail the article doesn\'t support.\n' +
  '"mitreAttack": array of {"technique": string, "techniqueId": string or null, "reason": string (why this technique applies, grounded in what the article describes), "killChainPhase": string} -- techniqueId MUST be copied exactly from the CANDIDATE MITRE ATT&CK TECHNIQUES list in the user message, or null if none genuinely apply. Never invent a technique ID that isn\'t in that list, even if it looks plausible.\n' +
  '"threatActors": array of {"group": string, "aliases": string[], "motivation": string|null, "targetSectors": string[], "geography": string|null, "knownCampaigns": string[]} -- only actors explicitly named in the article.\n' +
  '"malware": array of {"family": string, "capabilities": string[], "persistence": string|null, "payload": string|null, "deliveryMechanism": string|null} -- only malware explicitly named in the article.\n' +
  '"operationalActions": {\n' +
  '  "socAnalyst": {"telemetryToCheck": string[] (real, specific telemetry sources for THIS attack -- e.g. "Windows Event ID 4688 (process creation) for the child process spawned by the web service", "Sysmon Event ID 3 (network connection) for outbound C2 beacons", "Microsoft Defender for Endpoint DeviceProcessEvents / DeviceNetworkEvents advanced hunting tables", "firewall/proxy logs for requests to the vulnerable endpoint path" -- never just "logs" or "EDR telemetry" with no specifics), "whatToLookFor": string (the specific indicator/behavior that confirms this is happening in this environment), "immediateNextStep": string (the concrete next step if the indicator is found)},\n' +
  '  "recommendedActions": array of EXACTLY these 7 entries, one each, in this exact order and with these exact "action" strings -- "Block Firewall", "Block DNS", "Add to Defender IOC", "Create Sentinel Analytic Rule", "Hunt in MDE", "Search Proxy Logs", "Search Email Gateway" -- each shaped {"action": string (copied exactly from the list above), "applicable": boolean (true only if THIS article/data genuinely supports taking that specific action -- e.g. "Block Firewall" is only true if there are IP-based indicators worth blocking, "Search Email Gateway" is only true if the delivery mechanism described is phishing/email-based, "Create Sentinel Analytic Rule" is only true if there is a genuinely new, specific detection opportunity here, not for every report), "details": string (if applicable: the concrete thing to do -- which specific IPs/domains/hashes, which query, which technique, phrased as an instruction a Tier-1 analyst can execute immediately; if not applicable: "Not Applicable")} -- do not mark more than 2-3 as applicable unless the article genuinely supports it; a mostly-not-applicable checklist for a low-signal article is correct, not incomplete.\n' +
  '  "platformRecommendations": {"logSourcesToReview": string[] (specific log sources beyond telemetryToCheck above -- e.g. named firewall/proxy/DNS/cloud-audit log types relevant to this threat), "microsoftDefenderRecommendations": string[] (specific Microsoft Defender XDR / Defender for Endpoint actions -- custom indicators, specific Attack Surface Reduction rules, specific advanced hunting table/query ideas relevant to THIS threat, not generic "enable Defender"), "microsoftSentinelRecommendations": string[] (specific Sentinel analytic rule concepts or KQL hunting query ideas relevant to THIS threat -- describe the query\'s logic/target table, not a full KQL statement), "firewallDnsRecommendations": string[] (specific firewall/DNS blocking, sinkholing, or egress-filtering actions relevant to THIS threat), "emailSecurityRecommendations": string[] (specific Defender for Office 365 / email gateway actions -- ONLY if the delivery mechanism described is email/phishing-related, otherwise []), "identityMonitoringRecommendations": string[] (specific Entra ID / Conditional Access / MFA / credential-monitoring actions -- ONLY if credential theft, identity compromise, or account abuse is part of this threat, otherwise []), "edrRecommendations": string[] (specific EDR containment/isolation/response actions beyond socAnalyst.immediateNextStep)} -- every list must be specific to THIS threat, never generic platform best-practices; assume the reader\'s organization runs Microsoft Defender XDR, Microsoft Sentinel, and Microsoft Defender for Office 365 unless the article states otherwise. Do not repeat content already covered in recommendedActions or telemetryToCheck -- add depth, not restatement.\n' +
  '  "threatHunter": {"hypotheses": array of {"hypothesis": string (a specific, testable hunting hypothesis grounded in this attack\'s actual behavior, e.g. "internet-facing instances of the affected service still unpatched", "unexpected administrative logins immediately following the exploitation window", "process spawning from the vulnerable web service"), "dataSources": string[] (what to query to test it), "positiveFindingLooksLike": string, "falsePositiveNote": string (what a benign explanation for the same signal would look like)} -- 2-4 hypotheses, each genuinely distinct, not restatements of each other, "behavioralIndicators": {"networkBehaviors": string[], "processBehaviors": string[], "authenticationAnomalies": string[], "dnsActivity": string[], "powershellActivity": string[], "scheduledTasks": string[], "registryModifications": string[], "persistenceIndicators": string[]} -- each a short list of concrete, hunt-actionable behavioral signatures specific to THIS threat (e.g. processBehaviors: "rundll32.exe spawned with no command-line arguments from a Word process", not "unusual process activity"); leave a category [] if this threat genuinely has no behavior there (a web-only exploit chain legitimately has no scheduledTasks/registryModifications) rather than padding it with generic filler},\n' +
  '  "detectionEngineer": {"existingRulesAvailable": string[] (your own knowledge of whether public Sigma/Elastic/Microsoft-native detection rules already cover this activity -- name them if you know of specific ones, otherwise state plainly that none are known to exist yet; real, verified public rule matches are supplied separately and merged in automatically, don\'t restate those), "recommendedAction": string (update an existing rule vs. author a new one, and why), "yaraApplicable": string or null (is YARA a fit here -- e.g. for a dropped payload/webshell -- or null if not applicable to this attack type), "newDetectionLogic": string[] (concrete new detection RULE logic to build, described precisely enough for an engineer to implement -- not vague "add a rule"), "logSourcesRequired": string[], "expectedFalsePositives": string, "detectionGaps": string[] (blind spots -- what this attack could still evade even with the above detections in place), "likelyManifestation": string (how this threat would concretely show up in telemetry/logs/alerts in a typical enterprise environment -- the observable footprint, distinct from a rule spec), "behavioralDetectionOpportunities": string[] (the underlying attacker BEHAVIORS that are inherently detectable regardless of any specific rule -- e.g. process lineage anomalies, command-line patterns, beacon timing regularity -- distinct from newDetectionLogic\'s concrete rule-building tasks; if the two would restate each other, put the rule-specific version in newDetectionLogic and the behavioral rationale here, don\'t duplicate)},\n' +
  '  "vulnerabilityManagement": {"applicable": boolean (false if this article involves no specific CVE -- if false, every other field in this object should be "Not Applicable"/[]), "affectedAssetsSummary": string (affected products/versions and how to identify/scope them in a typical environment), "internetFacing": string, "exploitMaturity": string (weaponized/PoC/theoretical), "patchPriority": string, "maintenanceWindowRecommendation": string, "businessCriticality": string, "compensatingControls": string[] (if patching must be delayed), "knownWorkaround": string or null},\n' +
  '  "incidentResponse": {"immediateTriageSteps": string[], "containmentActions": string[], "recoveryActions": string[]},\n' +
  '  "threatIntelTakeaway": string -- a forward-looking trend/trajectory judgment for a CTI analyst, never a restatement of the vulnerability, patch guidance, or business risk already covered above. Answer whichever of these genuinely apply: is this part of a broader trend (device class, vulnerability class, technique) rather than an isolated incident? Is attacker capability or tooling sophistication increasing? Is this a new TTP or reuse of an established one? Is this likely tied to or a continuation of an existing campaign? Should follow-on activity be expected (weaponization, PoC release, botnet incorporation, ransomware targeting), and on what kind of timeline based on comparable historical disclosures? What specifically should an analyst watch for next? Ground every claim either in what the article states OR in a clearly-hedged general pattern for this vulnerability/device/technique category (e.g. "vulnerabilities affecting IoT access-control systems have increasingly been incorporated into botnets within days of disclosure") -- never assert a specific unconfirmed fact about THIS incident (no invented actor, no invented campaign name, no claim that exploitation IS happening if the article doesn\'t say so). Only write "Not Reported" if neither the article nor any well-established general pattern for this category offers a genuine trend/trajectory angle -- this should be rare; "apply the patch" is never an acceptable answer here.\n' +
  '  "executiveLeadershipTakeaway": string (under 100 words, zero technical jargon) -- answers "does management specifically need to get personally involved, and why" (tie this directly to businessRisk.requiresExecutiveAttention), a decision-relevance verdict distinct from executiveSummary\'s situational "what happened" read -- do not restate executiveSummary\'s sentences.\n' +
  '}\n' +
  '"operationalRecommendations": array of role-specific action items across exactly these 6 teams -- "Threat Intelligence", "Threat Hunting", "Detection Engineering", "SOC Operations", "Vulnerability Management", "Incident Response" -- each shaped {"team": string (copied exactly from that list), "priority": "Critical"|"High"|"Medium"|"Low", "recommendation": string (MUST begin with an action verb -- Track, Hunt, Validate, Correlate, Update, Review, Create, Monitor, Search, Block, Escalate, Isolate, Contain, Audit, Investigate, Scan, Deploy, etc. -- specific and operational, e.g. "Hunt for internet-facing instances of the affected service exposed before the patch date" not "monitor for suspicious activity"), "rationale": string (exactly one sentence explaining why THIS threat specifically supports this action)}. This is a distinct, flat, prioritized CHECKLIST view across all six teams, not a restatement of operationalActions above -- distill and prioritize that guidance into short, scannable action items rather than repeating its sentences verbatim. Generate a recommendation for a team ONLY if the article\'s actual reported threat activity genuinely supports it -- never generic advice like "monitor for suspicious activity" or "apply patches." Do not invent a plausible-sounding action a team could theoretically take on any threat; ground every recommendation in what this specific article describes. If a team genuinely has no article-supported action, include exactly ONE entry for that team: {"team": that team, "priority": "Low", "recommendation": "No additional actions identified", "rationale": a one-sentence reason why (e.g. "Article contains no indicators or activity actionable by this team")}. A team may have multiple entries (up to 4) if the article genuinely supports several distinct actions for it; most single-CVE-advisory articles will not.\n' +
  '"confidenceAssessment": {"level": "High"|"Medium"|"Low", "score": integer 0-100, "reasoning": string, "factorsPresent": string[] (specific, concrete factors that are actually true of THIS article/data and increase confidence -- e.g. "Official CISA advisory", "KEV inclusion confirmed", "CVE ID confirmed against NVD", "Active exploitation confirmed by vendor", "Named vendor advisory available", "Full technical writeup with confirmed IOCs" -- only list what genuinely applies here, never pad with factors that don\'t apply), "factorsMissing": string[] (what would have increased confidence further but isn\'t available for this article -- e.g. "No IOC validation available", "No public PoC confirmed", "Not confirmed via independent telemetry", "Exploitation details beyond the vendor advisory are limited")} -- score must be justified purely by which factorsPresent/factorsMissing apply (roughly 85-100 High, 50-84 Medium, below 50 Low) -- never assign a score without grounding it in the specific factors listed. reasoning is a one-sentence summary of the same judgment, shown alongside the factor lists.\n' +
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

const SHOULD_I_CARE_VERDICTS = new Set(["YES", "NO", "UNKNOWN"]);
function safeShouldICare(v) {
  v ??= {};
  const verdict = typeof v.verdict === "string" ? v.verdict.trim().toUpperCase() : "";
  return {
    verdict: SHOULD_I_CARE_VERDICTS.has(verdict) ? verdict : "UNKNOWN",
    reasoning: safeString(v.reasoning),
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

function safeThreatRelevance(v) {
  v ??= {};
  return {
    industriesAtRisk: safeArray(v.industriesAtRisk),
    technologiesTargeted: safeArray(v.technologiesTargeted),
    geographicFocus: safeArray(v.geographicFocus),
    victimProfile: safeString(v.victimProfile),
    initialAccessVector: safeString(v.initialAccessVector),
    // Derived from the already-parsed/grounded mitreAttack array (unique,
    // real killChainPhase values) rather than asked of the model a second
    // time here -- avoids the exact restatement-drift this app's own "remove
    // duplicated content" prompt instruction warns against, and guarantees
    // this list can never name a tactic the grounded technique list doesn't
    // actually support.
    mitreTactics: [],
  };
}

function safeOperationalImpact(v) {
  v ??= {};
  return {
    businessImpact: safeString(v.businessImpact),
    detectionChallenges: safeArray(v.detectionChallenges),
    evasionTechniques: safeArray(v.evasionTechniques),
    attackerObjectives: safeArray(v.attackerObjectives),
  };
}

// Fixed catalog, not model-defined -- same reasoning as RECOMMENDED_ACTION_CATALOG
// above: lets the UI render a stable 10-row heatmap every time (and the
// Emerging Threats tab aggregate one across reports) and lets a genuinely
// unsupported response default to "Not Applicable" per row rather than
// dropping the industry entirely.
export const INDUSTRY_CATALOG = [
  "Financial Services",
  "Consumer",
  "Technology, Media & Telecommunications",
  "Life Sciences & Health Care",
  "Manufacturing",
  "Energy & Utilities",
  "Government & Public Sector",
  "Retail & eCommerce",
  "Education",
  "Transportation & Logistics",
];

const INDUSTRY_RELEVANCE_LEVELS = new Set(["Critical", "High", "Medium", "Low", "Not Applicable"]);
const INDUSTRY_CONFIDENCE_LEVELS = new Set(["High", "Medium", "Low"]);
const INDUSTRY_PRIORITIES = new Set(["Immediate", "High", "Normal", "Low"]);

function safeIndustryRelevance(v) {
  const byIndustry = new Map();
  if (Array.isArray(v)) {
    for (const entry of v) {
      if (entry && typeof entry === "object" && typeof entry.industry === "string") {
        byIndustry.set(entry.industry.trim(), entry);
      }
    }
  }
  return INDUSTRY_CATALOG.map((industry) => {
    const entry = byIndustry.get(industry);
    const relevance = INDUSTRY_RELEVANCE_LEVELS.has(entry?.relevance) ? entry.relevance : "Not Applicable";
    const applicable = relevance !== "Not Applicable";
    const n = Number(entry?.riskScore);
    return {
      industry,
      relevance,
      confidence: INDUSTRY_CONFIDENCE_LEVELS.has(entry?.confidence) ? entry.confidence : "Low",
      whyAffected: applicable ? safeString(entry?.whyAffected) : "Not Applicable",
      potentialImpact: applicable ? safeArray(entry?.potentialImpact) : [],
      likelyTargetAssets: applicable ? safeArray(entry?.likelyTargetAssets) : [],
      defensiveFocus: applicable ? safeArray(entry?.defensiveFocus) : [],
      riskScore: Number.isFinite(n) ? Math.max(0, Math.min(10, Math.round(n))) : 0,
      priority: INDUSTRY_PRIORITIES.has(entry?.priority) ? entry.priority : "Low",
    };
  });
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

// Fixed catalog, not model-defined -- lets the UI render a stable checklist
// (same 7 rows every time) and lets groundRecommendedActions below upgrade
// specific rows using objectively-extracted IOCs rather than trusting the
// model's own judgment for the ones this app can actually verify.
const RECOMMENDED_ACTION_CATALOG = [
  "Block Firewall",
  "Block DNS",
  "Add to Defender IOC",
  "Create Sentinel Analytic Rule",
  "Hunt in MDE",
  "Search Proxy Logs",
  "Search Email Gateway",
];

function safeRecommendedActions(v) {
  const byAction = new Map();
  if (Array.isArray(v)) {
    for (const entry of v) {
      if (entry && typeof entry === "object" && typeof entry.action === "string") {
        byAction.set(entry.action.trim(), entry);
      }
    }
  }
  return RECOMMENDED_ACTION_CATALOG.map((action) => {
    const entry = byAction.get(action);
    const applicable = entry ? safeBoolean(entry.applicable) : false;
    return {
      action,
      applicable,
      details: applicable ? safeString(entry?.details) : "Not Applicable",
    };
  });
}

function safeBehavioralIndicators(v) {
  v ??= {};
  return {
    networkBehaviors: safeArray(v.networkBehaviors),
    processBehaviors: safeArray(v.processBehaviors),
    authenticationAnomalies: safeArray(v.authenticationAnomalies),
    dnsActivity: safeArray(v.dnsActivity),
    powershellActivity: safeArray(v.powershellActivity),
    scheduledTasks: safeArray(v.scheduledTasks),
    registryModifications: safeArray(v.registryModifications),
    persistenceIndicators: safeArray(v.persistenceIndicators),
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
    behavioralIndicators: safeBehavioralIndicators(v.behavioralIndicators),
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
    likelyManifestation: safeString(v.likelyManifestation),
    behavioralDetectionOpportunities: safeArray(v.behavioralDetectionOpportunities),
  };
}

function safePlatformRecommendations(v) {
  v ??= {};
  return {
    logSourcesToReview: safeArray(v.logSourcesToReview),
    microsoftDefenderRecommendations: safeArray(v.microsoftDefenderRecommendations),
    microsoftSentinelRecommendations: safeArray(v.microsoftSentinelRecommendations),
    firewallDnsRecommendations: safeArray(v.firewallDnsRecommendations),
    emailSecurityRecommendations: safeArray(v.emailSecurityRecommendations),
    identityMonitoringRecommendations: safeArray(v.identityMonitoringRecommendations),
    edrRecommendations: safeArray(v.edrRecommendations),
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

// Deliberately a different SHAPE than operationalActions above, not a
// duplicate of its content: operationalActions is deep, per-team, tool-
// specific guidance (real event IDs, KQL logic, hunting hypotheses);
// operationalRecommendations is the flat, scannable, prioritized checklist
// view across all six teams -- the "what do I do, in what order" table a
// team lead skims first, distinct from the "how exactly do I do it"
// narrative sections it draws on. The model is instructed not to restate
// those sections' sentences verbatim, only to distill/prioritize them.
const OPERATIONAL_RECOMMENDATION_TEAMS = ["Threat Intelligence", "Threat Hunting", "Detection Engineering", "SOC Operations", "Vulnerability Management", "Incident Response"];
const MAX_RECOMMENDATIONS_PER_TEAM = 4;

function safeOperationalRecommendations(value) {
  if (!Array.isArray(value)) return [];
  const perTeamCount = new Map();
  const out = [];
  for (const entry of value) {
    const team = OPERATIONAL_RECOMMENDATION_TEAMS.includes(entry?.team) ? entry.team : null;
    const recommendation = typeof entry?.recommendation === "string" && entry.recommendation.trim() ? entry.recommendation.trim() : null;
    if (!team || !recommendation) continue; // drop rather than guess a team/recommendation the model didn't clearly supply
    const count = perTeamCount.get(team) ?? 0;
    if (count >= MAX_RECOMMENDATIONS_PER_TEAM) continue;
    perTeamCount.set(team, count + 1);
    out.push({
      team,
      priority: safePriority(entry.priority),
      recommendation,
      rationale: safeString(entry.rationale, "Not Reported"),
    });
  }
  // Fixed team order (matches OPERATIONAL_RECOMMENDATION_TEAMS), Critical-first within a team -- a stable, scannable reading order regardless of what order the model emitted entries in.
  const teamRank = new Map(OPERATIONAL_RECOMMENDATION_TEAMS.map((t, i) => [t, i]));
  const priorityRank = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  return out.sort((a, b) => teamRank.get(a.team) - teamRank.get(b.team) || priorityRank[a.priority] - priorityRank[b.priority]);
}

function safeOperationalActions(v) {
  v ??= {};
  return {
    socAnalyst: safeSocAnalyst(v.socAnalyst),
    recommendedActions: safeRecommendedActions(v.recommendedActions),
    platformRecommendations: safePlatformRecommendations(v.platformRecommendations),
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
  const n = Number(v.score);
  return {
    level: safeConfidenceLevel(v.level),
    score: Number.isFinite(n) ? Math.max(0, Math.min(100, Math.round(n))) : null,
    reasoning: safeString(v.reasoning),
    factorsPresent: safeArray(v.factorsPresent),
    factorsMissing: safeArray(v.factorsMissing),
  };
}

function safeExposureAssessment(v) {
  v ??= {};
  const applicable = safeBoolean(v.applicable);
  if (!applicable) {
    return {
      applicable: false,
      product: "Not Applicable",
      howToCheckVersion: "Not Applicable",
      affectedVersions: "Not Applicable",
      affectedGuidance: "Not Applicable",
      notAffectedGuidance: "Not Applicable",
    };
  }
  return {
    applicable: true,
    product: safeString(v.product),
    howToCheckVersion: safeString(v.howToCheckVersion),
    affectedVersions: safeString(v.affectedVersions),
    affectedGuidance: safeString(v.affectedGuidance),
    notAffectedGuidance: safeString(v.notAffectedGuidance),
  };
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
    const mitreAttack = safeMitreArray(parsed.mitreAttack, validTechniqueIds, techniqueNameToId, idToTechniqueName);
    const threatRelevance = safeThreatRelevance(parsed.threatRelevance);
    // Derived, not model-authored -- see safeThreatRelevance's comment.
    threatRelevance.mitreTactics = [...new Set(mitreAttack.map((t) => t.killChainPhase).filter((phase) => phase && phase !== "Not Reported"))];
    return {
      executiveHeadline: safeString(parsed.executiveHeadline),
      executiveSummary: safeString(parsed.executiveSummary),
      intelligenceAssessment: safeString(parsed.intelligenceAssessment),
      businessRisk: safeBusinessRisk(parsed.businessRisk),
      shouldICare: safeShouldICare(parsed.shouldICare),
      exposureAssessment: safeExposureAssessment(parsed.exposureAssessment),
      technicalAnalysis: safeTechnicalAnalysis(parsed.technicalAnalysis, validTechniqueIds, idToTechniqueName),
      threatRelevance,
      operationalImpact: safeOperationalImpact(parsed.operationalImpact),
      industryRelevance: safeIndustryRelevance(parsed.industryRelevance),
      mitreAttack,
      threatActors: safeThreatActors(parsed.threatActors),
      malware: safeMalware(parsed.malware),
      operationalActions: safeOperationalActions(parsed.operationalActions),
      operationalRecommendations: safeOperationalRecommendations(parsed.operationalRecommendations),
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

// Same hybrid-grounding principle as groundExistingRules above, applied to
// the 3 recommendedActions rows this app can verify objectively from its own
// IOC extraction rather than trust the model's judgment call on: only ever
// upgrades false -> true (with real, synthesized details listing the actual
// extracted indicators), never overrides a model-reasoned true or the
// judgment-only rows ("Create Sentinel Analytic Rule", "Hunt in MDE",
// "Search Email Gateway") that require synthesis this app can't verify.
function groundRecommendedActions(modelReport, iocs) {
  const ipAddresses = iocs.ipAddresses ?? [];
  const domains = iocs.domains ?? [];
  const urls = iocs.urls ?? [];
  const hashes = iocs.hashes ?? [];
  const anyIocCount = ipAddresses.length + domains.length + urls.length + hashes.length + (iocs.emailAddresses?.length ?? 0);

  const upgrades = {
    "Block Firewall": ipAddresses.length > 0 && { details: `Block the following IP address(es) at the perimeter firewall: ${ipAddresses.join(", ")}` },
    "Block DNS": domains.length > 0 && { details: `Sinkhole/block the following domain(s) at the DNS resolver: ${domains.join(", ")}` },
    "Add to Defender IOC": anyIocCount > 0 && { details: "Add the extracted indicators (IPs/domains/URLs/hashes above) to Microsoft Defender's custom indicator list." },
    "Search Proxy Logs": domains.length + urls.length > 0 && { details: `Search proxy logs for requests to: ${[...domains, ...urls].join(", ")}` },
  };

  const recommendedActions = modelReport.operationalActions.recommendedActions.map((entry) => {
    const upgrade = upgrades[entry.action];
    if (upgrade && !entry.applicable) return { ...entry, applicable: true, details: upgrade.details };
    return entry;
  });

  return {
    ...modelReport,
    operationalActions: { ...modelReport.operationalActions, recommendedActions },
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

  // Routed through server/ai/aiRouter.js (Gemini -> Qwen -> Groq -> Cohere,
  // automatic failover on rate limits/quota/timeouts/5xx) rather than
  // calling Groq directly -- this report generation is the single heaviest,
  // most latency-sensitive LLM call in the app, so it benefits the most
  // from not going fully dark whenever one provider's free tier is
  // exhausted. AllProvidersFailedError (thrown only once every configured
  // provider has been attempted) is caught by server/aiThreatSummaryJob.js
  // the same way GroqUnavailableError used to be -- stop the cycle, don't
  // advance lastCycleAt, retry on the next tick.
  const response = await aiRouter.summarizeJson(userContent, {
    systemPrompt: SYSTEM_PROMPT,
    temperature: 0.2,
  });

  const modelReport = parseModelReport(response.summary ?? "", validTechniqueIds, techniqueNameToId, idToTechniqueName);
  if (!modelReport) return null;

  const groundedReport = groundRecommendedActions(groundExistingRules(modelReport, grounded.detectionRuleIndex), iocs);

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
