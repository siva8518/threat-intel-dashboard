// Actionable Guidance -- the final stage of the shared platform-wide
// intelligence assessment pipeline. Concrete, entity-type-specific next
// steps derived from the verdict/evidence this search already computed --
// never generic "investigate the IOC" boilerplate. Hunting queries are NOT
// recomputed here: they're read straight from the Investigation Graph
// node's own metadata (server/investigation/investigationGraph.js's
// enrichmentFor()/detectionAndHuntingForFamilies(), already built from
// server/huntingLibrary.js#buildEntityHuntingQueries for this exact search),
// the same real content already shown in Detection & Hunting -- reused, not
// duplicated.
//
// PLATFORM CONSTRAINT (applies to every action string below): this platform
// has NO EDR/SIEM/XDR/firewall/DNS/proxy/netflow/VPN or other internal
// security telemetry integration anywhere. Every action that touches one of
// those systems must be phrased as a recommendation FOR the analyst,
// conditioned on "if observed in your X" -- never as something this
// platform already searched, checked, identified, or found. External-
// intelligence-only actions (block at the perimeter, pivot the graph,
// deploy a detection rule) may stay imperative since those genuinely are
// this platform's own job. `environmentalValidationPlan()` below is
// the deterministic, always-conditional counterpart: what the analyst must
// check in their own tools, kept structurally separate from `actions` so
// the frontend never conflates "what this platform found" with "what you
// still need to check."
import { BLOCKABLE_TYPES } from "./verdictEngine.js";

function action(text, rationale, role, priority) {
  return { action: text, rationale, role, priority };
}

// Actions branch on verdict.blockRecommendation (server/investigation/verdictEngine.js#computeBlockRecommendation)
// rather than re-deriving their own block/don't-block reading of verdict.state
// -- one source of truth for "should this be blocked", so this text can
// never drift out of sync with the Block Recommendation shown elsewhere.
function iocActions(type, indicator, verdict, moduleData) {
  const label = { ip: "IP address", domain: "domain", url: "URL" }[type] ?? "indicator";
  const actions = [];
  const recencyNote = verdict.confidenceFactors.recencyDays != null ? ` (most recently seen ${verdict.confidenceFactors.recencyDays} day(s) ago)` : "";

  if (verdict.blockRecommendation === "Block") {
    actions.push(action(`Block ${label} "${indicator}" at the perimeter firewall/proxy (egress and ingress) and add it to the SIEM watchlist.`, verdict.reasoning, "socAnalyst", verdict.recommendedPriority));
    actions.push(
      action(
        `If "${indicator}" is observed in your firewall/proxy/DNS/network logs, hunt for prior connections to it across the last 90 days${recencyNote}.`,
        "This platform's own external evidence indicates active malicious use -- this platform has no network-telemetry integration, so whether it was actually observed can only be confirmed in your own logs.",
        "threatHunter",
        verdict.recommendedPriority,
      ),
    );
  } else if (verdict.state === "Conflicting Intelligence") {
    actions.push(
      action(
        `Investigate "${indicator}" before deciding to block or dismiss -- reputation sources disagree, so neither an outright block nor a dismissal is justified on reputation alone. ${verdict.blockRecommendationReasoning}`,
        verdict.reasoning,
        "socAnalyst",
        "Normal",
      ),
    );
  } else if (verdict.blockRecommendation === "Monitor — Do Not Block") {
    actions.push(action(`Add "${indicator}" to a monitoring watchlist rather than an outright block. ${verdict.blockRecommendationReasoning}`, verdict.reasoning, "socAnalyst", "Normal"));
  } else if (verdict.state === "Clean-Benign") {
    actions.push(action(`No blocking action needed for "${indicator}" based on current evidence.`, verdict.reasoning, "socAnalyst", "Low"));
  } else {
    actions.push(action(`No external reputation evidence found for "${indicator}" -- re-check if new context emerges.`, verdict.reasoning, "threatIntel", "Low"));
  }
  return { actions, notApplicable: ["vulnerabilityManagement"] };
}

// Real detection rules only ever come from graph.node.metadata.detectionRules
// (server/investigation/investigationGraph.js#detectionAndHuntingForFamilies,
// itself sourced from server/correlate.js#detectionRulesFor -- an actual
// index of ingested SigmaHQ/YARA-Rules content). moduleData.malwareFamily
// being truthy means a live AV/sandbox lookup NAMED a family -- it says
// nothing about whether this platform has a real public rule for it. The
// literal fix for the reported "recommends deploying a YARA/Sigma rule even
// when the platform explicitly says none was found" bug: this used to fire
// on malwareFamily alone.
function hashActions(indicator, verdict, moduleData, graph) {
  const actions = [];
  const malwareFamily = moduleData?.malwareFamily ?? null;
  const detectionRules = graph?.node?.metadata?.detectionRules ?? [];
  const hasRealDetectionRule = detectionRules.length > 0;
  const familyEdge = (graph?.edges ?? []).find((e) => e.targetType === "malware" && e.relationship === "classified as malware family");
  const familyIsTracked = Boolean(familyEdge);

  if (verdict.blockRecommendation === "Block") {
    actions.push(action(`Add hash "${indicator}" to the EDR block-list.`, verdict.reasoning, "socAnalyst", verdict.recommendedPriority));
    actions.push(
      action(
        `External intelligence confirms "${indicator}" is malicious. This platform has no EDR/endpoint-telemetry integration, so it cannot tell you whether this file exists in your environment -- if the hash is observed in your EDR, investigate the affected host(s): identify every endpoint where it was written or executed, the parent process, the user/account involved, and any outbound network connections made after execution.`,
        "Confirmed/likely-malicious file per external evidence -- whether it was actually executed anywhere is only knowable from your own EDR telemetry, which this platform does not have access to.",
        "socAnalyst",
        verdict.recommendedPriority,
      ),
    );
    actions.push(
      action(
        `If execution of "${indicator}" is confirmed on any endpoint in your EDR, quarantine that endpoint per policy.`,
        "Isolation should follow CONFIRMED execution, not mere presence of the file on disk -- and confirmation can only come from your own EDR.",
        "socAnalyst",
        verdict.recommendedPriority,
      ),
    );
    actions.push(
      action(
        `If "${indicator}"${malwareFamily ? ` or other samples/filenames associated with the "${malwareFamily}" family` : ""} is observed in your endpoint telemetry, retro-hunt across all endpoints and historical data, and check for lateral spread or persistence mechanisms if any host is confirmed.`,
        "Confirmed/likely-malicious file per external evidence -- this platform cannot see your endpoint telemetry, so any prior exposure beyond the single sample already known can only be found in your own historical data.",
        "threatHunter",
        verdict.recommendedPriority,
      ),
    );
    if (malwareFamily) {
      actions.push(
        action(
          `Identify this malware family's known campaigns, threat actors, and infrastructure reuse in the Relationships graph below, and monitor for newly observed related indicators.`,
          `A live lookup classified this file as "${malwareFamily}"${familyIsTracked ? `, matched to this platform's own tracked "${familyEdge.targetLabel}" family record` : " -- this platform has no tracked entity record for that exact family name yet"}.`,
          "threatIntel",
          "High",
        ),
      );
    }
    if (hasRealDetectionRule) {
      actions.push(
        action(
          `Deploy the ${detectionRules.length} matched detection rule(s) for "${malwareFamily}" (see Detection & Hunting below).`,
          `This platform has ${detectionRules.length} real, ingested public detection rule(s) indexed for this family.`,
          "detectionEngineer",
          "High",
        ),
      );
    } else {
      actions.push(
        action(
          "No existing public detection rule was identified. Detection Engineering should consider creating a custom detection based on the confirmed file hash, malware family, filename, behavioral characteristics, or observed network indicators.",
          malwareFamily
            ? `A live lookup named the "${malwareFamily}" family, but this platform found no matching SigmaHQ/YARA-Rules content for it.`
            : "No malware family classification and no matching detection-rule content were found for this hash.",
          "detectionEngineer",
          "Normal",
        ),
      );
    }
  } else if (verdict.state === "Conflicting Intelligence") {
    actions.push(
      action(
        `Investigate hash "${indicator}" before deciding to block or dismiss -- reputation sources disagree, so neither an outright block nor a dismissal is justified on reputation alone. ${verdict.blockRecommendationReasoning}`,
        verdict.reasoning,
        "socAnalyst",
        "Normal",
      ),
    );
    actions.push(
      action(
        `This platform cannot determine whether "${indicator}" has been observed in your environment -- search it in your own EDR/endpoint telemetry before deciding whether to escalate.`,
        verdict.reasoning,
        "threatHunter",
        "Normal",
      ),
    );
  } else if (verdict.blockRecommendation === "Monitor — Do Not Block") {
    actions.push(action(`Add hash "${indicator}" to a monitoring watchlist rather than an outright block. ${verdict.blockRecommendationReasoning}`, verdict.reasoning, "socAnalyst", "Normal"));
    actions.push(
      action(
        `This platform cannot determine whether "${indicator}" has been observed in your environment -- search it in your own EDR/endpoint telemetry before deciding whether to escalate.`,
        verdict.reasoning,
        "threatHunter",
        "Normal",
      ),
    );
  } else if (verdict.state === "Clean-Benign") {
    actions.push(action(`No blocking action needed for hash "${indicator}" based on current evidence.`, verdict.reasoning, "socAnalyst", "Low"));
  } else {
    actions.push(action(`No strong reputation evidence found for hash "${indicator}" -- re-check if new context emerges.`, verdict.reasoning, "threatIntel", "Low"));
  }
  return { actions, notApplicable: ["vulnerabilityManagement", "incidentResponse"] };
}

// Phrasing is deliberately scaled to the exploitation state -- KEV language
// ("patch immediately") is reserved for confirmed_actively_exploited only,
// never used for a CVE that merely has high CVSS/EPSS or public exploit code.
function cveActions(indicator, verdict, moduleData, cveExploitationState) {
  const actions = [];
  const state = cveExploitationState?.state;
  if (state === "confirmed_actively_exploited") {
    actions.push(action(`Patch "${indicator}" immediately -- CISA KEV confirms active exploitation.`, cveExploitationState.reasoning, "vulnerabilityManagement", "Immediate"));
    actions.push(action("Check CISA's KEV catalog for this CVE's federal remediation due date and treat it as the outside deadline.", "KEV entries carry a binding federal remediation deadline.", "vulnerabilityManagement", "Immediate"));
  } else if (state === "exploitation_reported_unconfirmed") {
    actions.push(action(`Prioritize patching "${indicator}" -- news reporting describes exploitation language, even though it is not yet in the CISA KEV catalog.`, cveExploitationState.reasoning, "vulnerabilityManagement", "High"));
  } else if (state === "public_exploit_available" || state === "poc_only") {
    actions.push(action(`Schedule patching for "${indicator}" ahead of routine cadence -- exploit code or a proof-of-concept exists publicly.`, cveExploitationState.reasoning, "vulnerabilityManagement", "High"));
  } else if (state === "predicted_high_risk_epss") {
    actions.push(action(`Prioritize "${indicator}" above baseline in the patch queue -- EPSS predicts elevated exploitation probability, though no exploitation has been observed.`, cveExploitationState.reasoning, "vulnerabilityManagement", "Normal"));
  } else {
    actions.push(action(`Patch "${indicator}" on normal cadence -- no known exploitation signal.`, cveExploitationState?.reasoning ?? "No exploitation signal found.", "vulnerabilityManagement", "Normal"));
  }
  actions.push(action("Confirm whether any asset in your environment actually runs the affected product/version before treating this as urgent.", "This platform has no asset-inventory integration -- applicability must be confirmed locally.", "vulnerabilityManagement", "Normal"));
  return { actions, notApplicable: ["socAnalyst", "incidentResponse"] };
}

function nameActions(indicator, verdict, moduleData) {
  const actions = [];
  const actor = moduleData?.actors?.[0];
  const malware = moduleData?.malware?.[0]?.entity;
  const campaign = moduleData?.campaigns?.[0];

  if (actor) {
    actions.push(action(`Review the Relationships graph for "${actor.name}"'s known malware/CVEs/infrastructure and cross-check against your own environment.`, `Tracked ${actor.type} actor.`, "threatIntel", actor.type === "Ransomware" || actor.type === "APT" ? "High" : "Normal"));
    if ((actor.techniqueIds ?? []).length > 0) actions.push(action(`Prioritize detection coverage for the ${actor.techniqueIds.length} ATT&CK technique(s) this actor is known to use.`, "Technique IDs are tracked directly on this actor's record.", "detectionEngineer", "Normal"));
  }
  if (malware) {
    actions.push(action(`Deploy/verify detection coverage for "${malware.name}" (see Detection & Hunting) and hunt for its ${malware.iocSightings ?? 0} tracked live indicator(s).`, "Malware family with tracked live indicators.", "threatHunter", (malware.iocSightings ?? 0) > 0 ? "High" : "Normal"));
  }
  if (campaign) {
    actions.push(action(`Review "${campaign.name}"'s associated actors/malware for a fuller picture before acting on this campaign in isolation.`, "Campaigns are rarely actionable without their associated actor/malware context.", "threatIntel", "Normal"));
  }
  if (actions.length === 0) actions.push(action(`No tracked malware/actor/campaign record found for "${indicator}".`, verdict.reasoning, "threatIntel", "Low"));
  return { actions, notApplicable: ["vulnerabilityManagement", "incidentResponse"] };
}

function ransomwareGroupActions(indicator, verdict, moduleData) {
  const count = moduleData?.victimCount ?? 0;
  const actions = [];
  if (count > 0) {
    actions.push(action(`Review "${indicator}"'s disclosed victims and known malware/TTPs in the Relationships graph for applicable detection/hunting coverage.`, `${count} disclosed victim(s) confirm active operations.`, "incidentResponse", "Immediate"));
    actions.push(action("Brief leadership on this group's typical double-extortion pattern (encryption plus data theft) if any exposure is found.", "Ransomware groups tracked here typically combine encryption with data exfiltration/extortion.", "incidentResponse", "High"));
  } else {
    actions.push(action(`No disclosed victims in this platform's data for "${indicator}" -- monitor for new disclosures.`, verdict.reasoning, "threatIntel", "Low"));
  }
  return { actions, notApplicable: ["vulnerabilityManagement"] };
}

function artifactActions(type, indicator, verdict, moduleData) {
  const hasHit = (moduleData?.crossReference?.matchedMalwareFamilies?.length ?? 0) > 0;
  const actions = hasHit
    ? [action(`Hunt for "${indicator}" (${type}) across endpoint/email telemetry -- already linked to tracked malicious activity in this platform's own data.`, verdict.reasoning, "threatHunter", verdict.recommendedPriority)]
    : [action("No external reputation source exists for this indicator type -- no action beyond noting it was checked.", verdict.reasoning, "threatIntel", "Low")];
  return { actions, notApplicable: ["vulnerabilityManagement", "detectionEngineer"] };
}

function genericActions(type, indicator, verdict) {
  return {
    actions: [action(`Review the Relationships graph for "${indicator}" -- no direct action applies to a ${type} indicator on its own.`, verdict.reasoning, "threatIntel", "Low")],
    notApplicable: ["socAnalyst", "threatHunter", "detectionEngineer", "incidentResponse", "vulnerabilityManagement"],
  };
}

function step(title, items, decision) {
  return { title, items, decision };
}

const STANDARD_SCOPE_EXPOSURE = [
  "Number of affected hosts",
  "Number of affected users",
  "First observed date",
  "Last observed date",
  "Execution/access count",
  "Network connections",
  "Persistence mechanisms",
  "Additional IOCs generated from affected systems",
];

const STANDARD_DECISION_MATRIX = [
  { finding: "No internal sightings", priority: "Monitor" },
  { finding: "Indicator present but not executed/accessed", priority: "Investigate / Remove" },
  { finding: "Executed/accessed on one host", priority: "High" },
  { finding: "Executed/accessed on multiple hosts", priority: "Critical" },
  { finding: "Execution + C2/network activity", priority: "Critical / Incident Response" },
  { finding: "Credential theft, persistence, or lateral movement observed", priority: "Critical" },
];

// --- Improvement 1: IOC-type-aware telemetry sources -------------------
// The exact, curated per-type source list this validation workflow is
// scoped to -- deliberately NOT a single shared list. Every step's wording
// below only ever names sources from THIS type's own list (e.g. "Email" is
// never mentioned for an IP, "NetFlow" is never mentioned for a hash), so
// the workflow never bleeds domain-specific or hash-specific instructions
// into an IP search or vice versa.
const HASH_TELEMETRY = ["EDR", "Email attachment telemetry", "File creation", "Process execution", "Sandbox"];
const TELEMETRY_SOURCES = {
  ip: ["Firewall", "Proxy", "NetFlow", "EDR", "SIEM", "DNS", "VPN", "Cloud network logs"],
  domain: ["DNS", "Proxy", "Web Gateway", "Email", "HTTP/HTTPS", "Endpoint", "SIEM"],
  url: ["Proxy", "Web Gateway", "Email", "Browser telemetry", "EDR", "Sandbox"],
  sha256: HASH_TELEMETRY,
  sha1: HASH_TELEMETRY,
  md5: HASH_TELEMETRY,
  email: ["Email gateway", "Identity", "Mailbox audit", "Authentication", "URL clicks", "Attachment telemetry"],
  fileName: ["EDR", "File creation", "Process execution", "Sandbox"],
  processName: ["EDR", "Process execution", "Sandbox"],
  registryKey: ["EDR", "Endpoint"],
  userAgent: ["Proxy", "Web Gateway", "SIEM"],
  cve: ["Asset Inventory", "Vulnerability Scanner", "SIEM", "EDR"],
  name: ["SIEM", "EDR", "Proxy", "DNS"],
  ransomwareGroup: ["SIEM", "EDR", "Proxy", "DNS", "Identity"],
};

/** Every source in a type's list, marked unavailable -- this platform has no internal telemetry integration of any kind, so this is never partial; it's an honest, complete "here is exactly what you must check yourself, and none of it is connected" roster, scoped to this specific IOC type. */
function telemetryCoverageFor(type) {
  return (TELEMETRY_SOURCES[type] ?? []).map((source) => ({
    source,
    available: false,
    note: `Not connected to this platform -- check directly in your ${source} tool/console.`,
  }));
}

// --- Improvement 2: observation window (first/last seen + confidence caveat) ---

/**
 * Two genuinely different, real windows -- never conflated:
 * (1) the external reputation window this platform's own live lookups
 * reported (VirusTotal/AbuseIPDB/etc. -- see index.js#firstLastSeenFor),
 * and (2) this platform's own historical ingestion window from the
 * canonical IOC store (server/iocIntelligence.js), when this exact value
 * has been independently extracted from ingested articles before. Neither
 * one is an "internal environment" window -- that one this platform
 * structurally cannot compute, and is called out explicitly rather than
 * silently omitted.
 */
function buildObservationWindow(firstSeen, lastSeen, canonicalRecord) {
  return {
    externalFirstSeen: firstSeen ?? null,
    externalLastSeen: lastSeen ?? null,
    externalWindowNote:
      firstSeen || lastSeen
        ? "Reflects the observation window reported by this platform's live external reputation/intelligence lookups."
        : "No external source reported a first/last-seen date for this indicator.",
    historicalFirstSeen: canonicalRecord?.firstSeen ?? null,
    historicalLastSeen: canonicalRecord?.lastSeen ?? null,
    historicalSightingCount: canonicalRecord?.sightingCount ?? null,
    historicalWindowNote: canonicalRecord
      ? `This platform has independently tracked this indicator across ${canonicalRecord.sightingCount} sighting(s) in its own ingested intelligence.`
      : "This indicator has no history in this platform's own ingested intelligence archive.",
    internalWindowNote:
      "This platform has no internal telemetry integration, so it cannot define an internal investigation window. Choose a lookback period appropriate to your own log retention (commonly 30-90 days) when searching your own tools.",
  };
}

// --- Improvement 3: Analyst Verdict (synthesized, not just a checklist) ---

const TYPE_LABEL = {
  ip: "IP address",
  domain: "domain",
  url: "URL",
  sha256: "file hash",
  sha1: "file hash",
  md5: "file hash",
  email: "email address",
  fileName: "file name",
  processName: "process name",
  registryKey: "registry key",
  userAgent: "user agent string",
  cve: "vulnerability",
  name: "entity",
  ransomwareGroup: "ransomware group",
};

const EXPOSURE_NOTES = {
  Confirmed:
    "This indicator is confirmed malicious per external threat intelligence. This is NOT confirmation that it has reached or affected your environment -- that can only be established by checking the telemetry sources below.",
  Suspected:
    "External evidence suggests this indicator may be malicious, but is not yet strong enough to confirm on its own. Environmental exposure is unknown until validated in your own tools.",
  None:
    "No external evidence currently indicates this indicator is malicious. This reflects what this platform's configured sources currently report, not a guarantee of safety.",
};

/** Never "Confirmed" for exposure -- this platform has no internal telemetry, so it can confirm an indicator is malicious, never that it has actually reached your environment. That distinction is carried in EXPOSURE_NOTES, not in the label itself (kept to the 3 values an analyst expects to see). */
function deriveExposure(state) {
  if (state === "Confirmed Malicious" || state === "Malicious") return "Confirmed";
  if (state === "Suspicious" || state === "Conflicting Intelligence" || state === "Unconfirmed") return "Suspected";
  return "None"; // Clean-Benign, Informational, Insufficient Evidence
}

function derivePriority(exposure, impact) {
  if (exposure === "None") return "Monitor";
  if (exposure === "Suspected") return "Investigate";
  if (impact === "Critical") return "Critical / Incident Response";
  if (impact === "High") return "Critical";
  return "High"; // Confirmed + Low/Medium impact
}

function recommendedNextActions(type, exposure, verdict) {
  const sources = TELEMETRY_SOURCES[type] ?? [];
  const topSources = sources.slice(0, 3).join(", ") || "your internal telemetry";
  const actions = [];
  if (exposure === "Confirmed") {
    actions.push(`Check ${topSources} for this indicator now -- external evidence is strong enough to act on, but only your own logs can confirm actual exposure.`);
    if (BLOCKABLE_TYPES.has(type)) {
      actions.push(
        verdict.blockRecommendation === "Block"
          ? `Block per this platform's recommendation while internal validation is in progress.`
          : `Do not block yet (${verdict.blockRecommendation}) -- monitor and validate internally first. ${verdict.blockRecommendationReasoning}`,
      );
    }
  } else if (exposure === "Suspected") {
    actions.push(`Check ${topSources} for this indicator before deciding whether to escalate -- external evidence alone is not yet conclusive.`);
  } else {
    actions.push("No action required based on current external evidence -- re-run this search if new context or intelligence emerges.");
  }
  actions.push("Re-check this indicator periodically; classification can change as new intelligence arrives.");
  return actions;
}

/**
 * Synthesizes the already-computed verdict (server/investigation/verdictEngine.js)
 * into the 4-question analyst-facing read this section exists to answer --
 * never re-derives its own malicious/benign judgment, only relabels the
 * same real, evidence-driven verdict for this specific context. Exposure/
 * Impact/Confidence/Priority map onto verdict.state/riskLevel/confidence/
 * (state+riskLevel) respectively -- see the functions above for exactly how.
 */
function deriveAnalystVerdict(type, verdict) {
  const exposure = deriveExposure(verdict.state);
  const impact = verdict.riskLevel; // Low/Medium/High/Critical -- computed independently of confidence in verdictEngine.js
  const confidence = verdict.confidence; // High/Medium/Low -- computed from evidence quantity/independence/agreement/recency
  const priority = derivePriority(exposure, impact);
  const typeLabel = TYPE_LABEL[type] ?? "indicator";

  const whatHappened =
    exposure === "None"
      ? `No source currently reports malicious or suspicious activity for this ${typeLabel}.`
      : `This platform's external intelligence classifies this ${typeLabel} as "${verdict.label}" -- ${verdict.reasoning}`;

  const howSerious = `Potential impact is rated ${impact} -- ${verdict.severityFactors.potentialImpact}`;

  const howConfident = `${confidence} confidence in this classification (${verdict.confidenceFactors.reasoning}) This is confidence in the external threat intelligence only -- confidence in whether this indicator has actually reached your environment is separately unknown until validated against the telemetry sources below, none of which are currently connected to this platform.`;

  return { exposure, exposureNote: EXPOSURE_NOTES[exposure], impact, confidence, priority, whatHappened, howSerious, howConfident, recommendedActions: recommendedNextActions(type, exposure, verdict) };
}

/**
 * Deterministic, never-AI-authored per-type runbook -- what the analyst
 * must check in their OWN internal tools, structured as a staged workflow
 * a SOC analyst actually works through, not a flat bullet list. Every step
 * below names ONLY sources from THIS type's own TELEMETRY_SOURCES entry
 * (Improvement 1) -- a domain search never mentions Sandbox (not in
 * domain's list), a hash search never mentions NetFlow (not in hash's
 * list), an IP search never mentions Email (not in IP's list). This
 * platform has no EDR/SIEM/firewall/DNS/proxy/email-security/network-
 * telemetry integration anywhere (same fact shouldICare.js's
 * ENVIRONMENTAL_RELEVANCE_UNKNOWN is built from), so every item here is
 * phrased as something the analyst must go confirm, never something this
 * platform already checked.
 */
function typeSpecificValidation(type, indicator, moduleData) {
  const quoted = `"${indicator}"`;
  const purpose = "Determine whether this indicator has actually affected your environment.";
  const platformLimitation =
    "This platform has no direct EDR, SIEM, email-security, or network-telemetry integration. The following validation must therefore be performed in your organization's security tools.";

  if (type === "sha256" || type === "sha1" || type === "md5") {
    const malwareFamily = moduleData?.malwareFamily ?? null;
    return {
      purpose,
      platformLimitation,
      steps: [
        step(
          "1. EDR — File Creation & Process Execution",
          [
            `Search EDR for file-creation events matching the exact hash ${quoted} across all endpoints.`,
            "Search EDR for process-execution events matching this hash.",
            "Identify affected hostname, user, process, parent process, first/last execution time, and any network connections the process itself made.",
            "Check whether multiple endpoints show the same hash.",
          ],
          ["No sightings → no known internal exposure based on available telemetry.", "File present but not executed → investigate delivery mechanism and remove/quarantine.", "Executed → escalate for host investigation and scoping."],
        ),
        step(
          "2. Email Attachment Telemetry — Determine delivery vector",
          ["Search email attachment telemetry for this hash, its filename, and any associated URLs/domains.", "Identify the originating sender, recipient population, download volume, and number of users exposed."],
          ["Multiple recipients or repeated delivery indicates potential campaign activity."],
        ),
        step("3. Sandbox — Analyze behavior", [
          "If the file is available, submit or retrieve the existing sandbox analysis.",
          "Review process execution, persistence, network connections, dropped files and command-line activity.",
          malwareFamily ? `Compare observed behavior against the reported "${malwareFamily}" family.` : "Compare observed behavior against the reported malware family.",
        ]),
      ],
      scopeExposure: STANDARD_SCOPE_EXPOSURE,
      decisionMatrix: STANDARD_DECISION_MATRIX,
    };
  }

  if (type === "ip") {
    return {
      purpose,
      platformLimitation,
      steps: [
        step(
          "1. Firewall / Proxy / NetFlow — Confirm network communication",
          [
            `Search ${quoted} in firewall, proxy, and NetFlow logs (both inbound and outbound).`,
            "Determine whether any host initiated or received a connection to/from this IP, and over which ports/protocols.",
            "Identify affected hostname(s), user(s), connection volume, and first/last connection time.",
            "Check whether multiple hosts connected to the same IP.",
          ],
          ["No connections → no known internal exposure based on available telemetry.", "Connection attempted but blocked at the perimeter → no compromise, but log for trend awareness.", "Connection succeeded → escalate for host investigation and scoping."],
        ),
        step(
          "2. EDR / SIEM — Correlate endpoint and aggregated telemetry",
          ["Search EDR for host-level activity correlating with any connection to this IP.", "Search SIEM for an aggregated, cross-source view of activity involving this IP.", "Identify the process/user context on any host that connected."],
          ["Repeated or sustained connections after initial contact significantly increases incident priority."],
        ),
        step(
          "3. DNS / VPN / Cloud Network Logs — Determine broader exposure",
          ["Search DNS logs for resolution activity to domains hosted on this IP.", "Check VPN logs for remote-access sessions involving this IP as source or destination.", "Check cloud network/VPC flow logs for connections from cloud workloads."],
        ),
        step("4. Threat Intel Correlation", [
          "Cross-check this IP against the malware family/actor/campaign context in the Relationships graph below.",
          "Review ASN/hosting-provider context to rule out shared or benign infrastructure before treating a match as malicious.",
        ]),
      ],
      scopeExposure: STANDARD_SCOPE_EXPOSURE,
      decisionMatrix: STANDARD_DECISION_MATRIX,
    };
  }

  if (type === "domain") {
    return {
      purpose,
      platformLimitation,
      steps: [
        step(
          "1. DNS / Proxy / Web Gateway — Confirm resolution and access",
          [
            `Search ${quoted} in DNS, proxy, and web gateway logs.`,
            "Determine whether any host resolved or connected to this domain, and identify the requesting hostname/user.",
            "Identify first/last access time and request volume.",
            "Check whether multiple hosts accessed the same domain.",
          ],
          ["No resolutions/connections → no known internal exposure based on available telemetry.", "Resolved but not connected → investigate what triggered the lookup.", "Connected or content downloaded → escalate for host investigation and scoping."],
        ),
        step(
          "2. HTTP/HTTPS / SIEM — Determine communication",
          ["Search HTTP/HTTPS traffic logs for connections to this domain's resolved IP(s) around the access time.", "Search SIEM for an aggregated view of activity involving this domain across the environment.", "Identify destination ports, protocols, and connection frequency."],
          ["Confirmed post-access outbound activity significantly increases incident priority."],
        ),
        step(
          "3. Email — Determine delivery vector",
          [`Search email logs for this domain in phishing or spam attempts.`, "Identify the originating sender, recipient population, and number of users exposed."],
          ["Multiple recipients or repeated delivery indicates potential campaign activity."],
        ),
        step("4. Endpoint — Correlate host-level activity", [
          "Search endpoint telemetry for hosts/processes that triggered a DNS/HTTP request to this domain.",
          "Identify the user/process context on any matching host.",
        ]),
        step("5. Threat Intel Correlation", ["Cross-check this domain against the malware family/actor/campaign context in the Relationships graph below."]),
      ],
      scopeExposure: STANDARD_SCOPE_EXPOSURE,
      decisionMatrix: STANDARD_DECISION_MATRIX,
    };
  }

  if (type === "url") {
    return {
      purpose,
      platformLimitation,
      steps: [
        step(
          "1. Proxy / Web Gateway — Confirm access",
          [`Search ${quoted} in proxy and web gateway logs.`, "Identify the requesting hostname/user, first/last access time, and request volume.", "Check whether multiple hosts accessed the same URL."],
          ["No access → no known internal exposure based on available telemetry.", "Accessed but blocked → no compromise, but log for trend awareness.", "Accessed and allowed → escalate for host investigation and scoping."],
        ),
        step(
          "2. Browser Telemetry / EDR — Determine host-level activity",
          ["Search browser telemetry (history/downloads) for any host that visited this URL.", "Search EDR for any file downloaded from or execution originating from this URL."],
          ["Confirmed download or execution following access significantly increases incident priority."],
        ),
        step(
          "3. Email — Determine delivery vector",
          ["Search email logs for this URL in phishing or spam attempts.", "Identify the originating sender, recipient population, and number of users exposed."],
          ["Multiple recipients or repeated delivery indicates potential campaign activity."],
        ),
        step("4. Sandbox — Analyze content", ["If content from this URL was downloaded, submit or retrieve the existing sandbox analysis."]),
        step("5. Threat Intel Correlation", ["Cross-check this URL against the malware family/actor/campaign context in the Relationships graph below."]),
      ],
      scopeExposure: STANDARD_SCOPE_EXPOSURE,
      decisionMatrix: STANDARD_DECISION_MATRIX,
    };
  }

  if (type === "email") {
    return {
      purpose,
      platformLimitation,
      steps: [
        step(
          "1. Email Gateway — Confirm delivery",
          [`Search email gateway/security logs for messages involving ${quoted}.`, "Identify recipient population, subject lines, delivery volume, and the spam/phishing verdict recorded at delivery time."],
          ["No messages found → no known internal exposure based on available telemetry.", "Messages delivered → continue to interaction check below."],
        ),
        step(
          "2. Mailbox Audit / URL Clicks / Attachment Telemetry — Determine interaction",
          ["Search mailbox audit logs for open/read/reply/forward events on messages from this sender.", "Check URL-click telemetry (e.g. safe-links/click-time protection) for any link in messages from this sender.", "Check attachment telemetry for any file opened or executed from this sender."],
          ["No interaction → block sender, no further action required.", "User interaction confirmed → continue to identity check below."],
        ),
        step("3. Identity / Authentication — Check for downstream compromise", [
          "If interaction was confirmed, check identity/authentication logs for anomalous sign-ins, MFA challenges, or credential changes on the affected account(s) around that time.",
        ]),
      ],
      scopeExposure: ["Number of affected users", "First observed date", "Last observed date", "Delivery volume", "Confirmed interactions", "Additional IOCs generated from affected accounts"],
      decisionMatrix: [
        { finding: "No messages found", priority: "Monitor" },
        { finding: "Delivered, no user interaction", priority: "Investigate / Remove" },
        { finding: "User interacted (opened/clicked) on one account", priority: "High" },
        { finding: "User interacted on multiple accounts", priority: "Critical" },
        { finding: "Interaction + account compromise or credential theft", priority: "Critical / Incident Response" },
      ],
    };
  }

  if (type === "fileName" || type === "processName") {
    return {
      purpose,
      platformLimitation,
      steps: [
        step(
          "1. EDR — File Creation & Process Execution — Confirm presence",
          [`Search EDR for file-creation and process-execution events matching ${quoted} across all endpoints.`, "Identify affected hostname, user, and first/last observed time.", "Check whether this matches any known-legitimate software in your environment before treating a match as suspicious."],
          ["No sightings → no known internal exposure based on available telemetry.", "Present but matches known-legitimate software → no action required.", "Present/executing and not legitimate → escalate for host investigation and scoping."],
        ),
        step("2. Sandbox — Analyze behavior (if applicable)", ["If a sample is available, submit or retrieve the existing sandbox analysis and compare against the reported malware family."]),
      ],
      scopeExposure: STANDARD_SCOPE_EXPOSURE,
      decisionMatrix: STANDARD_DECISION_MATRIX,
    };
  }

  if (type === "registryKey") {
    return {
      purpose,
      platformLimitation,
      steps: [
        step("1. EDR / Endpoint — Confirm presence", ["Search EDR/endpoint telemetry for this registry key on any host.", "Identify affected hostname, user, and first/last observed time.", "Determine whether the key correlates with a known persistence technique."], ["No sightings → no known internal exposure based on available telemetry.", "Present on one or more hosts → escalate for host investigation and scoping."]),
      ],
      scopeExposure: STANDARD_SCOPE_EXPOSURE,
      decisionMatrix: STANDARD_DECISION_MATRIX,
    };
  }

  if (type === "userAgent") {
    return {
      purpose,
      platformLimitation,
      steps: [
        step("1. Proxy / Web Gateway / SIEM — Confirm activity", ["Search proxy and web gateway logs for requests using this user-agent string.", "Search SIEM for an aggregated view of matching activity across the environment.", "Identify source host(s), destination(s), and request volume.", "Determine whether this correlates with automated/malicious tooling rather than a legitimate browser or application."], ["No matching requests → no known internal exposure based on available telemetry.", "Matching requests found → correlate destination and volume before escalating."]),
      ],
      scopeExposure: ["Number of affected hosts", "First observed date", "Last observed date", "Request volume", "Destinations contacted"],
      decisionMatrix: STANDARD_DECISION_MATRIX,
    };
  }

  if (type === "cve") {
    return {
      purpose: "Determine whether this vulnerability is actually exposed in your environment.",
      platformLimitation: "This platform has no asset-inventory or vulnerability-scanner integration. The following validation must therefore be performed in your organization's own tools.",
      steps: [
        step("1. Asset Inventory / Vulnerability Scanner — Confirm applicability", ["Confirm whether any asset in your environment runs the affected product/version.", "Identify affected hosts, owners, and network exposure (internet-facing vs. internal)."], ["No affected assets found → no known internal exposure based on available telemetry.", "Affected assets found → prioritize per exploitation state and patch."]),
        step("2. SIEM / EDR — Check for exploitation attempts", ["Search for known exploitation indicators or anomalous activity against the affected product around the disclosure/exploitation timeframe."]),
      ],
      scopeExposure: ["Number of affected assets", "Internet-facing vs. internal exposure", "Patch/remediation status", "Any signs of attempted exploitation"],
      decisionMatrix: [
        { finding: "No affected assets", priority: "Monitor" },
        { finding: "Affected assets present, not internet-facing", priority: "Investigate / Patch on schedule" },
        { finding: "Affected assets present, internet-facing", priority: "High" },
        { finding: "Affected assets + confirmed/likely exploitation activity", priority: "Critical / Incident Response" },
      ],
    };
  }

  if (type === "name" || type === "ransomwareGroup") {
    return {
      purpose,
      platformLimitation,
      steps: [
        step("1. SIEM / EDR / Proxy / DNS — Check the specific IOCs", ["Search your SIEM/EDR/proxy/DNS logs for any of the specific hashes/domains/IPs surfaced in Continue Investigation above -- this platform cannot tell you whether they've been observed in your environment.", "Prioritize any IOC already flagged malicious over merely-contextual infrastructure."]),
      ],
      scopeExposure: STANDARD_SCOPE_EXPOSURE,
      decisionMatrix: STANDARD_DECISION_MATRIX,
    };
  }

  return null;
}

/**
 * Deterministic, never-AI-authored environmental validation PLAN -- merges
 * the type-scoped workflow above (Improvement 1) with telemetry coverage
 * (Improvement 2) and the synthesized Analyst Verdict (Improvement 3), all
 * derived from real, already-computed data (the shared verdict this search
 * already resolved, and the same firstSeen/lastSeen/canonicalRecord this
 * page's own Overview and Source Citations sections already show) -- never
 * a second, independently-invented judgment. Kept separate from the
 * role-based `actions` above (external-intelligence pivots) so the frontend
 * can render "what this platform can pivot to" and "what you must check in
 * your own tools" as two explicit, non-conflatable sections.
 */
function environmentalValidationPlan(type, indicator, moduleData, verdict, firstSeen, lastSeen, canonicalRecord) {
  const typeSpecific = typeSpecificValidation(type, indicator, moduleData);
  if (!typeSpecific) return null;
  return {
    ...typeSpecific,
    telemetryCoverage: telemetryCoverageFor(type),
    observationWindow: buildObservationWindow(firstSeen, lastSeen, canonicalRecord),
    analystVerdict: deriveAnalystVerdict(type, verdict),
  };
}

// --- Task 2: Conflicting Intelligence guidance -- the specific SOC-analyst
// reasoning chain for the reported "VirusTotal = malicious, MISP = benign,
// therefore = monitor" flattening bug. verdictEngine.js already correctly
// detects this exact pattern (evidence.js#detectConflict: a `negative`
// polarity item from one source alongside a direct/corroborating malicious
// item from another) and routes it to state = "Conflicting Intelligence",
// which already caps confidence at "Low" (verdictEngine.js#deriveConfidenceLevel)
// -- so the underlying math was never actually averaging toward a false
// "clean" reading. What was missing is the SOC-facing NARRATIVE: a single
// generic "add to watchlist" line collapsed a real disagreement between
// sources into an unremarkable action, instead of walking the analyst
// through Threat Intelligence -> Conflicting Signals -> Environmental
// Evidence -> Analyst Decision the way a real SOC analyst reasons about it.
// Every field below is built from verdict.evidence.items, the same real,
// already-computed evidence every other section on this page reads --
// never a second, independently-invented reading of the same data.
// ---------------------------------------------------------------------

function evidenceBearingForConflict(evidence) {
  return (evidence?.items ?? []).filter((i) => i.category !== "contextual" && i.category !== "conflicting");
}

const CONFLICT_ANALYST_DECISION = [
  { finding: "No internal sightings", priority: "Monitor" },
  { finding: "Single access with no suspicious follow-on activity", priority: "Investigate / Monitor" },
  { finding: "Repeated access or multiple users/hosts", priority: "High Priority Investigation" },
  { finding: "Download or execution observed", priority: "High / Incident Response" },
  { finding: "C2, credential theft, persistence, or lateral movement", priority: "Critical / Incident Response" },
];

/**
 * Only ever populated when verdict.state === "Conflicting Intelligence" --
 * scoped to BLOCKABLE_TYPES (ip/domain/url/hash), the entity types with a
 * real external reputation source that can actually disagree with another.
 */
// `negative`-category evidence spans several distinct source shapes -- a MISP
// Warning Lists match (a genuine reference/allowlist dataset) reads very
// differently from VirusTotal/GreyNoise/Hybrid Analysis/urlscan.io actively
// scanning the indicator and reporting no malicious finding. Framing every
// negative source with "appears in a reference dataset" language is only
// accurate for MISP; the others need their own wording so the SOC analyst
// isn't told a scanning engine's clean verdict is a "dataset match".
function negativeSignalFraming(source, typeLabel) {
  const framers = {
    "MISP Warning Lists": `${source} match indicates this ${typeLabel} appears in a known-benign, commonly-used reference dataset`,
    VirusTotal: `${source} independently scanned this ${typeLabel} and reported no malicious or suspicious detections`,
    GreyNoise: `${source} classified this ${typeLabel} as a known-benign business service (RIOT)`,
    "Hybrid Analysis": `${source} sandboxed this ${typeLabel} and reported no threat`,
    "urlscan.io": `${source} reports a prior public scan found no malicious indicators`,
  };
  return framers[source] ?? `${source} reports a conflicting clean/benign signal`;
}

function conflictingIntelligenceGuidance(type, indicator, verdict) {
  if (verdict.state !== "Conflicting Intelligence") return null;

  const typeLabel = TYPE_LABEL[type] ?? "indicator";
  const bearing = evidenceBearingForConflict(verdict.evidence);
  const maliciousItems = bearing.filter((i) => (i.category === "direct" || i.category === "corroborating") && (i.polarity === "malicious" || i.polarity === "suspicious"));
  const negativeItems = bearing.filter((i) => i.category === "negative");
  const strongestMalicious = maliciousItems.reduce((max, i) => (i.weight > (max?.weight ?? -1) ? i : max), null);

  const threatIntelligenceSummary = strongestMalicious
    ? `${strongestMalicious.source} reports ${strongestMalicious.claim}, indicating a meaningful malicious reputation signal.`
    : "A malicious/suspicious reputation signal exists from at least one source.";

  const conflictingSignalNote =
    negativeItems.length > 0
      ? negativeItems.map((n) => `${n.source} reports ${n.claim}. This should be treated as context, not evidence that this specific ${typeLabel}'s activity is benign.`).join(" ")
      : (verdict.evidence?.conflictDescription ?? "A conflicting clean/benign signal exists from another source.");

  const reasoningChain = [
    { stage: "Threat Intelligence", summary: threatIntelligenceSummary },
    { stage: "Conflicting Signals", summary: verdict.evidence?.conflictDescription ?? conflictingSignalNote },
    {
      stage: "Environmental Evidence",
      summary: "This platform has no internal telemetry integration -- whether your environment actually interacted with this indicator can only be established in your own tools (see Recommended SOC Actions below).",
    },
    { stage: "Analyst Decision", summary: "Investigate before deciding to block or dismiss -- reputation alone should not drive the final call in either direction." },
  ];

  const sources = TELEMETRY_SOURCES[type] ?? [];
  const sourceList = sources.length > 0 ? sources.join(", ") : "your internal telemetry";
  const recommendedActions = [
    `Search the ${typeLabel} across ${sourceList} for the last 30 days.`,
    "Identify affected users and hosts, including first seen, last seen, access frequency, and originating process where available.",
    `Determine how the ${typeLabel} was accessed -- phishing email, browser navigation, redirect, advertisement, application activity, or another source.`,
    "Check for follow-on activity, including downloads, process execution, credential-related activity, or connections to additional suspicious domains/IPs.",
    "If no internal activity is observed: retain the indicator in monitoring/watchlist status and continue monitoring for new sightings or reputation changes.",
    "If suspicious activity or multiple affected hosts are identified: escalate for endpoint investigation and consider blocking across appropriate security controls.",
    "If execution, credential theft, persistence, or C2 activity is confirmed: escalate as a security incident and begin containment.",
  ];

  const keyIntelligenceNote =
    negativeItems.length > 0
      ? `${Array.from(new Set(negativeItems.map((n) => negativeSignalFraming(n.source, typeLabel)))).join("; ")}. This should be treated as context, not a benign verdict. The malicious reputation signal and actual environmental behavior should drive the final SOC decision -- not an automatic average toward "monitor."`
      : `A conflicting signal exists from another source. It should be treated as context, not a benign verdict.`;

  return { assessment: "Suspicious — Requires Investigation", threatIntelligenceSummary, conflictingSignalNote, reasoningChain, recommendedActions, analystDecision: CONFLICT_ANALYST_DECISION, keyIntelligenceNote };
}

// Deterministic "What To Investigate Next" for a CVE search -- the direct
// fix for the reported "Pivot to other high-severity CVEs to identify
// potential patterns or correlations" filler: that line was free-form
// AI narrative (server/investigation/correlationSummary.js's `nextSteps`)
// reasoning over a graph with no real actor/malware/campaign edges, so the
// model fell back to a logically-related-but-unfounded generic pivot.
// Every step below is gated behind a real, specific finding for THIS CVE --
// exploitation state (always present, since every CVE has one), a real
// vendor/product, a real graph edge, a real detection rule count -- and is
// simply omitted (not replaced with a guess) when that finding doesn't
// exist. This is the intelligence-graph decision table:
//   known exploitation / CISA KEV -> investigate exploitation immediately
//   exploit PoC available         -> assess exploitability, hunt for it
//   threat actor associated       -> hunt for that actor's TTPs/IOCs
//   malware associated            -> hunt for that malware + infrastructure
//   campaign associated           -> investigate that campaign's IOCs
//   affected product identified   -> search asset inventory
//   related IOCs identified       -> search for those indicators
//   detection rules available     -> validate detection coverage
//   no exploitation evidence      -> monitor intelligence, prioritize by exposure
// No other row exists -- there is deliberately no "pivot to similar CVEs"
// or "review other high-severity findings" step, since neither is grounded
// in anything specific to this CVE.
function cveInvestigationSteps(indicator, cveExploitationState, moduleData, graph) {
  const state = cveExploitationState?.state ?? null;
  const cve = moduleData?.cve ?? null;
  const edges = graph?.edges ?? [];
  const actorNames = edges.filter((e) => e.targetType === "actor").map((e) => e.targetLabel);
  const malwareNames = edges.filter((e) => e.targetType === "malware").map((e) => e.targetLabel);
  const campaignNames = edges.filter((e) => e.targetType === "campaign").map((e) => e.targetLabel);
  const iocEdges = edges.filter((e) => e.targetType === "ip" || e.targetType === "domain");
  const detectionRules = graph?.node?.metadata?.detectionRules ?? [];
  const exploitationEscalated = state === "confirmed_actively_exploited" || state === "exploitation_reported_unconfirmed";

  const steps = [];

  if (state === "confirmed_actively_exploited") {
    steps.push({
      title: "Investigate Known Exploitation",
      detail: `Check whether "${indicator}" has confirmed exploitation in the wild, including CISA KEV, vendor advisories, Exploit-DB, PoC repositories, and recent threat-intelligence reporting. ${cveExploitationState.reasoning} Exploitation is confirmed -- prioritize an environment-wide exposure assessment immediately.`,
      priority: "Immediate",
    });
  } else if (state === "exploitation_reported_unconfirmed") {
    steps.push({
      title: "Investigate Reported Exploitation",
      detail: `${cveExploitationState.reasoning} Treat this as unconfirmed until CISA KEV or a vendor advisory corroborates it, but validate promptly given the reporting.`,
      priority: "High",
    });
  } else if (state === "public_exploit_available" || state === "poc_only") {
    steps.push({
      title: "Assess Exploitability and Hunt for Exploitation",
      detail: `${cveExploitationState.reasoning} Assess whether the affected product/version is exposed in your environment, and hunt for exploitation indicators associated with "${indicator}" -- unusual process activity, crashes, or outbound connections consistent with this vulnerability class.`,
      priority: "High",
    });
  } else if (state === "predicted_high_risk_epss") {
    steps.push({
      title: "Monitor Elevated Predicted Risk",
      detail: `${cveExploitationState.reasoning} No exploitation has been observed. Prioritize based on exposure and revisit if EPSS or CISA KEV status changes.`,
      priority: "Normal",
    });
  } else {
    steps.push({
      title: "Monitor Intelligence -- No Exploitation Evidence",
      detail: `${cveExploitationState?.reasoning ?? "No exploitation signal found."} Monitor threat intelligence for changes and prioritize remediation based on exposure (affected product/version, asset criticality, internet exposure) rather than urgency.`,
      priority: "Low",
    });
  }

  if (cve?.vendor && cve.vendor !== "Unknown" && cve?.product && cve.product !== "Unknown") {
    steps.push({
      title: "Identify Affected Assets",
      detail: `Determine which products and versions are affected by "${indicator}" (${cve.vendor} ${cve.product}) and search your asset/vulnerability-management inventory for those versions. Prioritize internet-facing and business-critical assets.`,
      priority: exploitationEscalated ? "High" : "Normal",
    });
  }

  if (state && state !== "no_known_exploitation") {
    steps.push({
      title: "Hunt for Exploitation Activity",
      detail: `Search SIEM, EDR, and network telemetry for exploitation indicators associated with "${indicator}", including published IOCs, exploit paths, suspicious process activity, outbound connections, and post-exploitation activity. This platform has no internal telemetry integration -- this step must be performed in your own tools.`,
      priority: state === "confirmed_actively_exploited" ? "Immediate" : "High",
    });
  }

  if (actorNames.length > 0) {
    steps.push({
      title: "Investigate Related Threat Activity -- Threat Actor(s)",
      detail: `"${indicator}" is associated with ${actorNames.join(", ")}. Investigate this actor's known infrastructure and IOCs for activity within your environment (see the Relationships graph and Entity dossier).`,
      priority: "High",
    });
  }
  if (malwareNames.length > 0) {
    steps.push({
      title: "Investigate Related Threat Activity -- Malware",
      detail: `"${indicator}" is associated with ${malwareNames.join(", ")}. Hunt for this malware and its related infrastructure/IOCs within your environment.`,
      priority: "High",
    });
  }
  if (campaignNames.length > 0) {
    steps.push({
      title: "Investigate Related Threat Activity -- Campaign",
      detail: `"${indicator}" is associated with ${campaignNames.join(", ")}. Investigate the associated infrastructure and IOCs for activity within your environment.`,
      priority: "Normal",
    });
  }

  if (iocEdges.length > 0) {
    steps.push({
      title: "Investigate Related Indicators",
      detail: `${iocEdges.length} indicator(s) associated with "${indicator}" through a shared malware family have been identified (see the Relationships graph). Search for these indicators within your own telemetry.`,
      priority: "Normal",
    });
  }

  if (detectionRules.length > 0) {
    steps.push({
      title: "Validate Detection Coverage",
      detail: `${detectionRules.length} public detection rule(s) exist for techniques/entities associated with "${indicator}" (see Detection & Hunting). Validate that these rules are deployed and tuned in your environment.`,
      priority: "Normal",
    });
  }

  return steps;
}

// Deterministic "What To Investigate Next" derived from a COMPLETED sandbox
// report -- the direct fix for the reported "Investigate the sandbox
// results" / "Investigate related IOCs" filler. Every step below cites a
// SPECIFIC observed process, connection, dropped file, or technique from
// THIS report; there is no generic catch-all step, and nothing fires at all
// unless the underlying field actually has data (the same "don't invent
// pivots" discipline as cveInvestigationSteps above). Each step answers the
// platform's required 6 questions in its 5 fields: what was observed (
// `observation`), why it matters (`whyItMatters`), what/where to search (
// `investigation`), what would increase severity (`escalationCondition`),
// what to do next (`action`).
function processLabel(p) {
  return p.commandLine ? `${p.name ?? "a process"} ("${p.commandLine.length > 120 ? `${p.commandLine.slice(0, 120)}...` : p.commandLine}")` : (p.name ?? "an unnamed process");
}

function sandboxInvestigationSteps(indicator, sandboxRecord) {
  // "completed" (freshly submitted) and "existing_available" (a pre-existing
  // report found via a check-only lookup, e.g. a hash overview hit) both
  // carry a real report -- see the identical note in evidence.js#sandboxEvidence.
  if ((sandboxRecord?.status !== "completed" && sandboxRecord?.status !== "existing_available") || !sandboxRecord.report) return null;
  const r = sandboxRecord.report;
  const steps = [];
  const highSeverity = r.verdict === "malicious";

  if (r.processes.length > 0 && r.networkConnections.length > 0) {
    const proc = processLabel(r.processes[0]);
    const ips = r.networkConnections.slice(0, 5).map((c) => (c.port ? `${c.ip}:${c.port}` : c.ip));
    steps.push({
      observation: `Sandbox execution of "${indicator}" observed ${proc} establishing ${r.networkConnections.length} outbound network connection(s), including ${ips.join(", ")}.`,
      whyItMatters: "Process execution followed by an outbound connection is a concrete behavioral chain -- not a reputation score -- and is the strongest evidence this sample actually does something on a host, not just that some engine flagged it.",
      investigation: `Search EDR/SIEM for ${r.processes[0]?.name ?? "this process"} execution and network connections to ${ips[0]}${ips.length > 1 ? ` and the other ${ips.length - 1} address(es) above` : ""} across the last 30 days.`,
      escalationCondition: "If the same process/connection pattern appears on any host in your environment, or if additional process execution, file creation, or repeated outbound communication follows, escalate for endpoint investigation.",
      action: "Isolate the endpoint if matching execution or communication is confirmed on any host; otherwise continue monitoring for the same indicators.",
      priority: highSeverity ? "Immediate" : "High",
    });
  } else if (r.processes.length > 0) {
    const proc = processLabel(r.processes[0]);
    steps.push({
      observation: `Sandbox execution of "${indicator}" observed ${proc} run${r.processes.length > 1 ? `, along with ${r.processes.length - 1} other process(es)` : ""}, with no outbound network activity captured in this report.`,
      whyItMatters: "Process execution without observed network activity can still indicate local reconnaissance, staging, or a sample that phones home outside the sandbox's analysis window -- absence of network activity here is not evidence of safety.",
      investigation: `Search EDR for ${r.processes[0]?.name ?? "this process"} execution and its full process tree (parent/child processes, command-line arguments).`,
      escalationCondition: "If this process is observed executing on any host, or spawns additional child processes, escalate for endpoint investigation.",
      action: "Isolate the endpoint if matching execution is confirmed and behavior is consistent with malicious activity.",
      priority: highSeverity ? "High" : "Normal",
    });
  } else if (r.networkConnections.length > 0) {
    const ips = r.networkConnections.slice(0, 5).map((c) => (c.port ? `${c.ip}:${c.port}` : c.ip));
    steps.push({
      observation: `Sandbox analysis of "${indicator}" observed ${r.networkConnections.length} outbound network connection(s) with no distinct process named in this report: ${ips.join(", ")}.`,
      whyItMatters: "Outbound network activity during sandboxed execution is real observed behavior, independent of any reputation score, and is the kind of evidence that transfers directly to what to search in your own telemetry.",
      investigation: `Search network/proxy/DNS telemetry for connections to ${ips.join(", ")} during the last 30 days, and identify any internal host that reached them.`,
      escalationCondition: "If any internal host shows a connection to these addresses, especially repeated or beaconing-pattern traffic, escalate for endpoint investigation.",
      action: "Block the observed addresses at the perimeter if confirmed malicious, and investigate any internal host found communicating with them.",
      priority: highSeverity ? "High" : "Normal",
    });
  }

  if (r.dnsQueries.length > 0) {
    const domains = r.dnsQueries.slice(0, 5).map((d) => d.domain);
    steps.push({
      observation: `Sandbox analysis of "${indicator}" observed ${r.dnsQueries.length} DNS quer${r.dnsQueries.length === 1 ? "y" : "ies"}: ${domains.join(", ")}.`,
      whyItMatters: "A DNS lookup during sandboxed execution shows what infrastructure the sample actually tries to reach, which is a more specific and actionable indicator than a bare reputation score.",
      investigation: `Search DNS/proxy logs for lookups of ${domains.join(", ")} and determine whether any internal host resolved them.`,
      escalationCondition: "If any internal host resolved these domains, especially outside expected business use, escalate for endpoint investigation.",
      action: "Add the observed domains to DNS/proxy blocklists if confirmed malicious, and investigate any host found resolving them.",
      priority: "Normal",
    });
  }

  if (r.filesDropped.length > 0) {
    const named = r.filesDropped.slice(0, 5).map((f) => f.name ?? f.sha256 ?? "an unnamed file");
    const hashList = r.filesDropped.map((f) => f.sha256).filter(Boolean);
    steps.push({
      observation: `Sandbox execution of "${indicator}" dropped ${r.filesDropped.length} file(s): ${named.join(", ")}.`,
      whyItMatters: "A dropped file is a concrete, hunt-able artifact -- unlike a reputation score, a file hash can be searched directly across endpoint telemetry for exact matches.",
      investigation: `Search EDR for file-creation events matching ${named.join(", ")}${hashList.length > 0 ? `, or the hash(es) ${hashList.slice(0, 3).join(", ")}` : ""} across your environment.`,
      escalationCondition: "If any of these files are found created on a host, escalate for endpoint investigation and consider submitting the file's own hash for a separate sandbox check.",
      action: "Quarantine the endpoint if a matching dropped file is confirmed present and execution is corroborated.",
      priority: highSeverity ? "High" : "Normal",
    });
  }

  if (r.persistenceIndicators.length > 0) {
    steps.push({
      observation: `Sandbox analysis of "${indicator}" observed persistence-related behavior: ${r.persistenceIndicators.slice(0, 3).join("; ")}.`,
      whyItMatters: "A persistence mechanism means the sample is designed to survive a reboot -- this is a materially more serious finding than execution alone and changes the priority of any confirmed sighting.",
      investigation: "Search EDR/registry telemetry for the specific persistence mechanism observed (registry run key, scheduled task, or service) on any host that may have executed this sample.",
      escalationCondition: "If a matching persistence mechanism is found on any host, treat it as confirmed compromise, not a suspected one.",
      action: "Escalate as a security incident and begin containment if persistence is confirmed on any host.",
      priority: "Immediate",
    });
  }

  if (r.mitreAttackTechniques.length > 0) {
    const ids = r.mitreAttackTechniques.map((m) => m.id).filter(Boolean);
    steps.push({
      observation: `Sandbox analysis of "${indicator}" mapped to ${ids.length} MITRE ATT&CK technique(s): ${ids.join(", ")}.`,
      whyItMatters: "These techniques are the sample's actual observed behavior classified against a standard framework, not a generic malware label -- they tell you exactly what detection coverage to check.",
      investigation: `Validate whether detection rules exist and are deployed for ${ids.join(", ")} (see Detection & Hunting).`,
      escalationCondition: "If any of these techniques are also observed in your own EDR/SIEM telemetry independent of this sandbox run, escalate for investigation.",
      action: "Deploy or tune detection coverage for any of these techniques that isn't already covered.",
      priority: "Normal",
    });
  }

  if (r.relatedSamples.length > 0) {
    steps.push({
      observation: `Sandbox analysis identified ${r.relatedSamples.length} related sample(s) for "${indicator}".`,
      whyItMatters: "Related samples from the same sandbox analysis are the platform's strongest same-family pivot -- likely the same campaign or toolset, not a speculative pattern match.",
      investigation: `Review the related sample(s) (${r.relatedSamples.slice(0, 3).join(", ")}) for shared infrastructure or behavior with "${indicator}".`,
      escalationCondition: "If a related sample is also confirmed present in your environment, treat both as part of the same incident.",
      action: "Search for the related sample hash(es) directly if any are already known to be relevant to your environment.",
      priority: "Normal",
    });
  }

  // Nothing behavioral fired above -- report this honestly rather than
  // silently producing zero steps and letting the analyst assume "nothing
  // to add" means "confirmed safe" (the literal "clean sandbox result
  // should not automatically make an IOC benign" requirement).
  if (steps.length === 0) {
    steps.push(
      r.incomplete
        ? {
            observation: `Sandbox analysis of "${indicator}" completed but returned no distinguishing behavioral detail (no process, network, DNS, or dropped-file activity in this report).`,
            whyItMatters: "An incomplete or thin report is not the same as a confirmed-clean result -- this platform cannot tell whether that's because the sample genuinely did nothing, or because the sandbox environment didn't trigger its behavior.",
            investigation: `Treat "${indicator}" as inconclusive from sandbox evidence alone -- rely on the other intelligence sources on this page (reputation, MISP, environmental telemetry) for this decision.`,
            escalationCondition: "If any other source independently reports malicious activity, do not let this inconclusive sandbox result offset that signal.",
            action: "No sandbox-driven action -- continue relying on the platform's other evidence for this indicator.",
            priority: "Low",
          }
        : {
            observation: `Sandbox analysis of "${indicator}" completed with a ${r.verdict} verdict and no notable process, network, DNS, or dropped-file activity observed.`,
            whyItMatters: "A clean sandbox run is one input, not a standalone benign verdict -- a sample can behave differently outside this specific sandbox environment, and this platform's other evidence should still be weighed.",
            investigation: `Continue relying on this platform's other evidence sources for "${indicator}" -- do not treat this sandbox result alone as clearing it.`,
            escalationCondition: "If another source (reputation, MISP, environmental telemetry) reports malicious/suspicious activity, that signal should not be discounted because of this clean sandbox result.",
            action: "No sandbox-driven action beyond normal monitoring.",
            priority: "Low",
          },
    );
  }

  return steps;
}

/**
 * @param {{ type: string, indicator: string, verdict: import("../../src/types/threat-intel.js").VerdictResult, moduleData?: Record<string, unknown>, cveExploitationState?: import("../../src/types/threat-intel.js").CveExploitationAssessment | null, graph?: import("../../src/types/threat-intel.js").GraphNodeResult | null, crossRef?: Record<string, unknown> | null, firstSeen?: string | null, lastSeen?: string | null, sandboxRecord?: import("../../src/types/threat-intel.js").SandboxRecord | null }} args
 * @returns {import("../../src/types/threat-intel.js").ActionabilityGuidance}
 */
export function buildActionabilityGuidance({ type, indicator, verdict, moduleData, cveExploitationState = null, graph = null, crossRef = null, firstSeen = null, lastSeen = null, sandboxRecord = null }) {
  let result;
  if (type === "cve") result = cveActions(indicator, verdict, moduleData, cveExploitationState);
  else if (type === "ip" || type === "domain" || type === "url") result = iocActions(type, indicator, verdict, moduleData);
  else if (type === "sha256" || type === "sha1" || type === "md5") result = hashActions(indicator, verdict, moduleData, graph);
  else if (type === "name") result = nameActions(indicator, verdict, moduleData);
  else if (type === "ransomwareGroup") result = ransomwareGroupActions(indicator, verdict, moduleData);
  else if (type === "email" || type === "fileName" || type === "processName" || type === "registryKey" || type === "userAgent") result = artifactActions(type, indicator, verdict, moduleData);
  else result = genericActions(type, indicator, verdict);

  const huntingQueries = graph?.node?.metadata?.huntingQueries ?? [];
  const canonicalRecord = crossRef?.canonicalRecord ?? null;
  return {
    entityType: type,
    actions: result.actions,
    huntingQueries,
    notApplicable: result.notApplicable,
    environmentalValidation: environmentalValidationPlan(type, indicator, moduleData, verdict, firstSeen, lastSeen, canonicalRecord),
    conflictingIntelligence: BLOCKABLE_TYPES.has(type) ? conflictingIntelligenceGuidance(type, indicator, verdict) : null,
    cveInvestigationSteps: type === "cve" ? cveInvestigationSteps(indicator, cveExploitationState, moduleData, graph) : null,
    sandboxInvestigationSteps: sandboxInvestigationSteps(indicator, sandboxRecord),
  };
}
