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
    actions.push(action(`Hunt for prior connections to "${indicator}" across the last 90 days${recencyNote}.`, "This platform's own evidence indicates active malicious use -- retroactive hunting finds any already-occurred exposure.", "threatHunter", verdict.recommendedPriority));
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
        `Search EDR telemetry for "${indicator}" across the last 90 days -- identify every endpoint where the file was written or executed, the parent process, the user/account involved, and any outbound network connections made after execution.`,
        "Confirmed/likely-malicious file -- retroactive hunting finds any already-occurred execution and its blast radius, not just presence.",
        "socAnalyst",
        verdict.recommendedPriority,
      ),
    );
    actions.push(
      action(
        `Quarantine any endpoint where execution of "${indicator}" is confirmed, per policy.`,
        "Isolation should follow CONFIRMED execution, not mere presence of the file on disk.",
        "socAnalyst",
        verdict.recommendedPriority,
      ),
    );
    actions.push(
      action(
        `Retro-hunt for "${indicator}"${malwareFamily ? ` and other samples/filenames associated with the "${malwareFamily}" family` : ""} across all endpoints and historical telemetry, and check for lateral spread or persistence mechanisms if any host is confirmed.`,
        "Confirmed/likely-malicious file -- retroactive hunting finds any already-occurred exposure beyond the single host where it was first seen.",
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
  } else if (verdict.blockRecommendation === "Monitor — Do Not Block") {
    actions.push(action(`Add hash "${indicator}" to a monitoring watchlist rather than an outright block. ${verdict.blockRecommendationReasoning}`, verdict.reasoning, "socAnalyst", "Normal"));
    actions.push(action(`Search EDR telemetry for "${indicator}" to determine whether it has been observed in your environment before deciding whether to escalate.`, verdict.reasoning, "threatHunter", "Normal"));
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

/**
 * @param {{ type: string, indicator: string, verdict: import("../../src/types/threat-intel.js").VerdictResult, moduleData?: Record<string, unknown>, cveExploitationState?: import("../../src/types/threat-intel.js").CveExploitationAssessment | null, graph?: import("../../src/types/threat-intel.js").GraphNodeResult | null }} args
 * @returns {import("../../src/types/threat-intel.js").ActionabilityGuidance}
 */
export function buildActionabilityGuidance({ type, indicator, verdict, moduleData, cveExploitationState = null, graph = null }) {
  let result;
  if (type === "cve") result = cveActions(indicator, verdict, moduleData, cveExploitationState);
  else if (type === "ip" || type === "domain" || type === "url") result = iocActions(type, indicator, verdict, moduleData);
  else if (type === "sha256" || type === "sha1" || type === "md5") result = hashActions(indicator, verdict, moduleData, graph);
  else if (type === "name") result = nameActions(indicator, verdict, moduleData);
  else if (type === "ransomwareGroup") result = ransomwareGroupActions(indicator, verdict, moduleData);
  else if (type === "email" || type === "fileName" || type === "processName" || type === "registryKey" || type === "userAgent") result = artifactActions(type, indicator, verdict, moduleData);
  else result = genericActions(type, indicator, verdict);

  const huntingQueries = graph?.node?.metadata?.huntingQueries ?? [];
  return { entityType: type, actions: result.actions, huntingQueries, notApplicable: result.notApplicable };
}
