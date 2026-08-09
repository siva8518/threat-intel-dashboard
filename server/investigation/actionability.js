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
// this platform's own job. `environmentalValidationChecklist()` below is
// the deterministic, always-conditional counterpart: what the analyst must
// check in their own tools, kept structurally separate from `actions` so
// the frontend never conflates "what this platform found" with "what you
// still need to check."
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

// Deterministic, never-AI-authored checklist of what the analyst must check
// in their OWN internal tools -- this platform has no EDR/SIEM/firewall/DNS/
// proxy/email-security/network-telemetry integration anywhere (same fact
// shouldICare.js's ENVIRONMENTAL_RELEVANCE_UNKNOWN is built from), so it can
// never claim to have already performed any of these searches itself. Kept
// separate from the role-based `actions` above (which mix external-
// intelligence pivots with internal-tool recommendations) so the frontend
// can render "what this platform can pivot to" and "what you must check in
// your own tools" as two explicit, non-conflatable sections.
function environmentalValidationChecklist(type, indicator) {
  const quoted = `"${indicator}"`;
  if (type === "sha256" || type === "sha1" || type === "md5") {
    return [`Search the exact hash ${quoted} in your EDR/endpoint telemetry.`, "Check sandbox history for this hash if it was previously submitted internally.", "Review email security/gateway logs in case this file arrived as an attachment."];
  }
  if (type === "ip") {
    return [`Search ${quoted} in your firewall/proxy logs (both inbound and outbound).`, `Search ${quoted} in your SIEM/network telemetry.`, `Check DNS logs for any resolution activity involving ${quoted}.`];
  }
  if (type === "domain" || type === "url") {
    return [`Search ${quoted} in your DNS/proxy logs.`, `Search your email security logs for ${quoted} in phishing or spam attempts.`, `Search your SIEM for any outbound connection to ${quoted}.`];
  }
  if (type === "email") {
    return [`Search your email security/gateway logs for messages involving ${quoted}.`, "Check whether any user account has interacted with this sender/address."];
  }
  if (type === "fileName" || type === "processName") {
    return [`Search your EDR/endpoint telemetry for ${quoted}.`, "Check whether this matches any known-legitimate software in your environment before treating a match as suspicious."];
  }
  if (type === "registryKey") {
    return [`Search your EDR/endpoint telemetry for this registry key on any host.`];
  }
  if (type === "userAgent") {
    return [`Search your web/proxy logs for requests using this user agent string.`];
  }
  if (type === "cve") {
    return ["Confirm whether any asset in your environment actually runs the affected product/version (this platform has no asset-inventory integration)."];
  }
  if (type === "name" || type === "ransomwareGroup") {
    return ["Search your SIEM/EDR for any of the specific IOCs (hashes/domains/IPs) surfaced in Continue Investigation above -- this platform cannot tell you whether they've been observed in your environment."];
  }
  return [];
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
  return { entityType: type, actions: result.actions, huntingQueries, notApplicable: result.notApplicable, environmentalValidationChecklist: environmentalValidationChecklist(type, indicator) };
}
