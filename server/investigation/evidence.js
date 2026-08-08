// Evidence Reconciliation stage -- Stage 1 of the shared platform-wide
// intelligence assessment pipeline (Source Evidence -> Evidence
// Reconciliation -> Correlation -> Contextual Assessment -> Confidence ->
// Severity/Priority -> AI Analysis -> Actionable Guidance, see
// server/investigation/verdictEngine.js for the stages after this one).
//
// Replaces the old per-source `verdict: "malicious"|"suspicious"|"clean"|
// "unknown"` strings each of ~11 connectors computed independently using its
// own arbitrary threshold before those strings were fed into
// verdict.js#computeIocVerdict's vote-counter. This file is the ONE place
// that classifies raw per-source fields into evidence -- every rule below
// reads the connector's raw numeric/boolean fields directly, never that
// connector's own pre-computed `verdict` string, so a threshold only ever
// needs to change in one place.
//
// Evidence categories (see EvidenceCategory in src/types/threat-intel.ts):
// direct/corroborating/attribution carry real weight toward a verdict;
// indirect/contextual never do alone (ASN/hosting-provider ownership,
// certificate transparency, and registration data are ALWAYS contextual --
// this is a structural guardrail, not a per-provider judgment call, so a
// shared-hosting IP on Cloudflare/AWS/Azure/GCP/Akamai/Fastly/DigitalOcean/
// Oracle Cloud can never accumulate malicious-polarity evidence from ASN
// data alone, regardless of which holder string comes back); negative is an
// explicit clean/benign signal; conflicting is a synthetic item this module
// adds itself when two sources disagree, never silently averaged away.

function item({ category, source, claim, polarity, weight, rawField = null, firstSeen = null, lastSeen = null }) {
  return { category, source, claim, polarity, weight, rawField, firstSeen, lastSeen };
}

// --- Per-source classification rules -- keyed by the exact `source` string
// each connector already returns (server/connectors/*.js, server/lookups/*.js). ---

function abuseipdbRule(r) {
  const score = r.abuseConfidenceScore ?? 0;
  const reports = r.totalReports ?? 0;
  if (score >= 75 && reports >= 3) {
    return [item({ category: "direct", source: "AbuseIPDB", claim: `${score}% abuse confidence across ${reports} report(s)`, polarity: "malicious", weight: 0.85, rawField: "abuseConfidenceScore", lastSeen: r.lastSeen })];
  }
  if (score >= 20) {
    return [item({ category: "corroborating", source: "AbuseIPDB", claim: `${score}% abuse confidence across ${reports} report(s)`, polarity: "suspicious", weight: 0.5, rawField: "abuseConfidenceScore", lastSeen: r.lastSeen })];
  }
  if (reports > 0) {
    return [item({ category: "negative", source: "AbuseIPDB", claim: `${reports} report(s) on file but low abuse confidence (${score}%)`, polarity: "neutral", weight: 0.2, rawField: "abuseConfidenceScore", lastSeen: r.lastSeen })];
  }
  return [];
}

function virustotalRule(r) {
  const malicious = r.malicious ?? 0;
  const suspicious = r.suspicious ?? 0;
  const harmless = r.harmless ?? 0;
  if (malicious >= 5) {
    return [item({ category: "direct", source: "VirusTotal", claim: `${malicious} engine(s) flagged malicious${r.threatLabel ? ` (${r.threatLabel})` : ""}`, polarity: "malicious", weight: 0.9, rawField: "malicious", lastSeen: r.lastSeen })];
  }
  if (malicious >= 1) {
    return [item({ category: "corroborating", source: "VirusTotal", claim: `${malicious} engine(s) flagged malicious${r.threatLabel ? ` (${r.threatLabel})` : ""}`, polarity: "malicious", weight: 0.5, rawField: "malicious", lastSeen: r.lastSeen })];
  }
  if (suspicious > 0) {
    return [item({ category: "corroborating", source: "VirusTotal", claim: `${suspicious} engine(s) flagged suspicious`, polarity: "suspicious", weight: 0.35, rawField: "suspicious", lastSeen: r.lastSeen })];
  }
  if (harmless > 0) {
    return [item({ category: "negative", source: "VirusTotal", claim: `${harmless} engine(s) reported harmless, none flagged malicious/suspicious`, polarity: "benign", weight: 0.4, rawField: "harmless", lastSeen: r.lastSeen })];
  }
  return [];
}

function greynoiseRule(r) {
  if (r.classification === "malicious") {
    return [item({ category: "direct", source: "GreyNoise", claim: `Classified malicious${r.name ? ` (${r.name})` : ""}`, polarity: "malicious", weight: 0.8, rawField: "classification" })];
  }
  if (r.riot === true) {
    return [item({ category: "negative", source: "GreyNoise", claim: `Known-benign business service (RIOT)${r.name ? ` -- ${r.name}` : ""}`, polarity: "benign", weight: 0.7, rawField: "riot" })];
  }
  return [];
}

// An exposed vulnerable service is context about attack surface, not
// evidence the IP itself is being used maliciously -- fixes today's
// `verdict: vulnCount > 0 ? "suspicious" : "unknown"` misclassification.
function shodanRule(r) {
  const vulnCount = r.vulnCount ?? 0;
  if (vulnCount > 0) {
    return [item({ category: "contextual", source: "Shodan", claim: `${vulnCount} known vulnerabilit${vulnCount === 1 ? "y" : "ies"} on exposed service(s) -- attack-surface context, not evidence of malicious use`, polarity: "neutral", weight: 0.1, rawField: "vulnCount" })];
  }
  return [];
}

function leakixRule(r) {
  const leakCount = r.leakCount ?? 0;
  const serviceCount = r.serviceCount ?? 0;
  if (leakCount > 0) {
    return [item({ category: "direct", source: "LeakIX", claim: `${leakCount} leak(s) associated with this indicator`, polarity: "suspicious", weight: 0.55, rawField: "leakCount" })];
  }
  if (serviceCount > 0) {
    return [item({ category: "contextual", source: "LeakIX", claim: `${serviceCount} exposed service(s) observed, no leaks`, polarity: "neutral", weight: 0.1, rawField: "serviceCount" })];
  }
  return [];
}

// Any community pulse mention, unweighted, used to be treated as
// "malicious" -- an OTX pulse is a researcher's tagging, useful as
// corroboration, never sufficient alone.
function otxRule(r) {
  const pulseCount = r.pulseCount ?? 0;
  if (pulseCount > 0) {
    return [item({ category: "corroborating", source: "OTX", claim: `Mentioned in ${pulseCount} community threat pulse(s)`, polarity: "suspicious", weight: 0.35, rawField: "pulseCount", lastSeen: r.lastSeen })];
  }
  return [];
}

function pulsediveRule(r) {
  if (r.risk === "critical" || r.risk === "high") {
    return [item({ category: "direct", source: "Pulsedive", claim: `Risk rated "${r.risk}"${r.threats?.length ? ` (${r.threats.join(", ")})` : ""}`, polarity: "malicious", weight: 0.6, rawField: "risk" })];
  }
  if (r.risk === "medium" || r.risk === "low") {
    return [item({ category: "corroborating", source: "Pulsedive", claim: `Risk rated "${r.risk}"`, polarity: "suspicious", weight: 0.3, rawField: "risk" })];
  }
  return [];
}

function hybridAnalysisRule(r) {
  const items = [];
  const score = r.threatScore ?? 0;
  if (score >= 70 || r.verdictLabel === "malicious") {
    items.push(item({ category: "direct", source: "Hybrid Analysis", claim: `Sandbox threat score ${score}/100${r.verdictLabel ? ` (${r.verdictLabel})` : ""}`, polarity: "malicious", weight: 0.85, rawField: "threatScore" }));
  } else if (score >= 30 || r.verdictLabel === "suspicious") {
    items.push(item({ category: "corroborating", source: "Hybrid Analysis", claim: `Sandbox threat score ${score}/100${r.verdictLabel ? ` (${r.verdictLabel})` : ""}`, polarity: "suspicious", weight: 0.45, rawField: "threatScore" }));
  } else if (r.verdictLabel === "whitelisted" || score === 0) {
    items.push(item({ category: "negative", source: "Hybrid Analysis", claim: `Sandbox reported ${r.verdictLabel ?? "no threat"} (score ${score}/100)`, polarity: "benign", weight: 0.4, rawField: "threatScore" }));
  }
  if (r.malwareFamily) {
    items.push(item({ category: "attribution", source: "Hybrid Analysis", claim: `Sandbox matched malware family "${r.malwareFamily}"`, polarity: "malicious", weight: 0.5, rawField: "malwareFamily" }));
  }
  return items;
}

// Team Cymru's Malware Hash Registry (hash lookups only) -- distinct from
// its IP-to-ASN service below, which is always contextual.
function teamCymruMhrRule(r) {
  const pct = r.detectionPercent;
  if (pct == null) return [];
  if (pct >= 50) return [item({ category: "direct", source: "Team Cymru MHR", claim: `${pct}% detection in Malware Hash Registry`, polarity: "malicious", weight: 0.75, rawField: "detectionPercent", lastSeen: r.lastSeen })];
  if (pct > 0) return [item({ category: "corroborating", source: "Team Cymru MHR", claim: `${pct}% detection in Malware Hash Registry`, polarity: "suspicious", weight: 0.4, rawField: "detectionPercent", lastSeen: r.lastSeen })];
  return [];
}

// Structural guardrail: ASN/holder ownership NEVER produces malicious- or
// suspicious-polarity evidence, for any holder string -- including
// Cloudflare, AWS, Azure, GCP, Akamai, Fastly, DigitalOcean, Oracle Cloud.
function teamCymruAsnRule(r) {
  if (!r.asn) return [];
  return [item({ category: "contextual", source: "Team Cymru", claim: `ASN ${r.asn} (${r.registry ?? "unknown registry"}, ${r.country ?? "unknown country"}) -- ownership context only, never treated as malicious evidence`, polarity: "neutral", weight: 0.05, rawField: "asn" })];
}

function ripestatRule(r) {
  if (!r.asn && !r.holder) return [];
  return [item({ category: "contextual", source: "RIPEstat", claim: `ASN ${r.asn ?? "unknown"}, holder "${r.holder ?? "unknown"}" -- ownership context only, never treated as malicious evidence regardless of which provider holds it`, polarity: "neutral", weight: 0.05, rawField: "asn" })];
}

function iscRule(r) {
  const feeds = r.threatFeeds ?? [];
  const hasRecentActivity = r.reportCount != null || r.attackTargets != null;
  if (feeds.length > 0 && hasRecentActivity) {
    return [item({ category: "direct", source: "SANS ISC", claim: `Listed on ${feeds.length} threat feed(s) with recent scanning/attack activity`, polarity: "malicious", weight: 0.6, rawField: "threatFeeds", lastSeen: r.lastSeen })];
  }
  if (feeds.length > 0) {
    return [item({ category: "corroborating", source: "SANS ISC", claim: `Listed on ${feeds.length} threat feed(s)`, polarity: "suspicious", weight: 0.35, rawField: "threatFeeds" })];
  }
  if (hasRecentActivity) {
    return [item({ category: "corroborating", source: "SANS ISC", claim: "Recent scanning/attack activity reported, not yet on a third-party threat feed", polarity: "suspicious", weight: 0.3, rawField: "reportCount" })];
  }
  return [];
}

function urlscanRule(r) {
  if (r.malicious === true) {
    return [item({ category: "direct", source: "urlscan.io", claim: `Flagged malicious (score ${r.score ?? "n/a"})${r.categories?.length ? `, categories: ${r.categories.join(", ")}` : ""}`, polarity: "malicious", weight: 0.85, rawField: "malicious" })];
  }
  if (r.malicious === false && r.scanId) {
    return [item({ category: "negative", source: "urlscan.io", claim: "Prior public scan found no malicious indicators", polarity: "benign", weight: 0.4, rawField: "malicious" })];
  }
  return [];
}

function crtshRule(r) {
  if (!r.certificateCount) return [];
  return [item({ category: "contextual", source: "crt.sh", claim: `${r.certificateCount} certificate(s), ${r.subdomainCount ?? 0} subdomain(s) observed -- certificate transparency alone does not imply malicious or clean`, polarity: "neutral", weight: 0.05, rawField: "certificateCount" })];
}

function rdapRule(r) {
  if (!r.registered) return [];
  return [item({ category: "contextual", source: "RDAP", claim: `Registered${r.registrar ? ` via ${r.registrar}` : ""}${r.createdDate ? `, created ${r.createdDate}` : ""} -- registration data alone does not imply malicious or clean`, polarity: "neutral", weight: 0.05, rawField: "registrar" })];
}

function hudsonRockRule(r) {
  const infections = r.infostealerInfections ?? 0;
  if (infections > 0) {
    return [item({ category: "indirect", source: "Hudson Rock", claim: `${infections} infostealer-exposed credential(s) tied to this domain (${r.employeesExposed ?? 0} employees, ${r.usersExposed ?? 0} users) -- a real risk signal, not proof this domain is itself malicious infrastructure`, polarity: "suspicious", weight: 0.25, rawField: "infostealerInfections" })];
  }
  return [];
}

// Fixes an actual bug in the old vote-counter: a MISP known-benign match
// (`verdict: "clean"`) was silently ignored by computeIocVerdict's vote
// counting, which only ever looked for `verdict === "malicious"` or
// `"suspicious"`. Here it's an explicit negative item.
function mispRule(r) {
  const matches = r.matchedLists ?? [];
  if (matches.length > 0) {
    return [item({ category: "negative", source: "MISP Warning Lists", claim: `Matched known-benign warning list(s): ${matches.join(", ")}`, polarity: "benign", weight: 0.5, rawField: "matchedLists" })];
  }
  return [];
}

const SOURCE_RULES = {
  AbuseIPDB: abuseipdbRule,
  VirusTotal: virustotalRule,
  GreyNoise: greynoiseRule,
  Shodan: shodanRule,
  LeakIX: leakixRule,
  OTX: otxRule,
  Pulsedive: pulsediveRule,
  "Hybrid Analysis": hybridAnalysisRule,
  "Team Cymru MHR": teamCymruMhrRule,
  "Team Cymru": teamCymruAsnRule,
  RIPEstat: ripestatRule,
  "SANS ISC": iscRule,
  "urlscan.io": urlscanRule,
  "crt.sh": crtshRule,
  RDAP: rdapRule,
  "Hudson Rock": hudsonRockRule,
  "MISP Warning Lists": mispRule,
};

// --- Correlation stage inputs -- this platform's own previously-ingested
// intelligence (see crossReference.js), and entity-type-specific evidence
// for the non-lookup-based entity types (CVE/name/ransomwareGroup). ---

// Every hit here shares ONE source string ("This platform's own tracked
// intelligence") deliberately -- crossReferenceIndicator() cross-references
// a single internal correlation pass, not several independent reputation
// feeds, so it must always count as exactly one independent source family
// no matter how many malware/actor/campaign names it matched (see
// independentSourceCount below).
// Confirmed live: this platform's own cross-reference is a same-indicator
// match against news-article-derived IOC extraction (server/malwareExtraction.js
// et al.), not a first-party vetted detection -- that pipeline is real but
// meaningfully noisier than a structured feed (this session already found
// junk entity records like a malware family literally named "malware" and
// an actor literally named "CISA"; live-tested here, the extremely common
// placeholder/example address 1.1.1.1 matched "BRICKSTORM"/"BeaverTail" via
// this exact path, driving severity straight to CRITICAL off a single noisy
// internal correlation with no external confirmation at all). Categorized
// "corroborating", not "direct" -- it can support and add weight to a real
// external detection, but must never alone carry the same evidentiary
// weight as a first-party feed with its own detection methodology.
function crossReferenceEvidence(crossRef) {
  if (!crossRef) return [];
  const items = [];
  const SOURCE = "This platform's own tracked intelligence";
  if (crossRef.matchedMalwareFamilies?.length > 0) {
    items.push(item({ category: "corroborating", source: SOURCE, claim: `Matched known malware famil${crossRef.matchedMalwareFamilies.length === 1 ? "y" : "ies"}: ${crossRef.matchedMalwareFamilies.join(", ")}`, polarity: "malicious", weight: 0.45, rawField: "matchedMalwareFamilies" }));
  }
  if (crossRef.associatedThreatActors?.length > 0) {
    items.push(item({ category: "attribution", source: SOURCE, claim: `Associated with tracked threat actor(s): ${crossRef.associatedThreatActors.join(", ")}`, polarity: "malicious", weight: 0.4, rawField: "associatedThreatActors" }));
  }
  if (crossRef.activeCampaigns?.length > 0) {
    items.push(item({ category: "corroborating", source: SOURCE, claim: `Linked to active campaign(s): ${crossRef.activeCampaigns.join(", ")}`, polarity: "malicious", weight: 0.35, rawField: "activeCampaigns" }));
  }
  return items;
}

// CVE evidence -- deliberately keeps KEV (an observed fact), news-reported
// exploitation language (unconfirmed), exploit-code availability (a
// capability signal, not confirmed use), and EPSS/CVSS (predictions/
// technical-severity, never evidence of exploitation) as separate items.
// See server/investigation/cveExploitState.js for the state this reads.
function cveEvidence(moduleData, cveExploitationState) {
  const cve = moduleData?.cve;
  if (!cve) return [];
  const items = [];
  if (cve.knownExploited) {
    items.push(item({ category: "direct", source: "CISA KEV", claim: "Listed in CISA's Known Exploited Vulnerabilities catalog", polarity: "malicious", weight: 0.9, rawField: "knownExploited" }));
  }
  if (cveExploitationState?.state === "exploitation_reported_unconfirmed") {
    items.push(item({ category: "corroborating", source: "Security News Coverage", claim: "News reporting describes exploitation language, not yet corroborated against an authoritative catalog", polarity: "suspicious", weight: 0.4, rawField: "relatedNews" }));
  }
  if ((cveExploitationState?.verifiedExploitsAvailable ?? 0) > 0) {
    items.push(item({ category: "corroborating", source: "Exploit-DB", claim: `${cveExploitationState.verifiedExploitsAvailable} verified public exploit(s) available`, polarity: "suspicious", weight: 0.35, rawField: "exploits" }));
  } else if ((cveExploitationState?.exploitsAvailable ?? 0) > 0 || (cveExploitationState?.githubPocsAvailable ?? 0) > 0) {
    items.push(item({ category: "indirect", source: "Exploit-DB / GitHub", claim: "Unverified exploit code or proof-of-concept repository found", polarity: "neutral", weight: 0.15, rawField: "exploits" }));
  }
  if ((cve.epssScore ?? 0) > 0) {
    items.push(item({ category: "contextual", source: "EPSS", claim: `EPSS predicted exploitation probability ${(cve.epssScore * 100).toFixed(1)}% -- a prediction, never evidence of actual exploitation`, polarity: "neutral", weight: 0.05, rawField: "epssScore" }));
  }
  items.push(item({ category: "contextual", source: "NVD/CVSS", claim: `CVSS severity ${cve.severity}${cve.cvssScore ? ` (${cve.cvssScore})` : ""} -- technical severity, never evidence of exploitation`, polarity: "neutral", weight: 0.05, rawField: "cvssScore" }));
  return items;
}

// Malware/Threat Actor/Campaign name search -- `verified` (confirmed
// against MITRE ATT&CK/a live indicator feed/a ransomware tracker, vs.
// reported by news coverage alone) is the real evidence-strength signal
// here, not a generic "found a record" hit. Reads EVERY matched entity
// (capped, to keep the evidence-card list scannable), not just the first --
// entityModule.js/entityCorrelation.js's own `[0]` was only ever a *display*
// precedence for "which entity is the headline," never meant to say every
// other real match should be silently dropped from the evidence itself.
const CAP_ENTITY_EVIDENCE = 5;
function nameEntityEvidence(moduleData) {
  const items = [];
  const SOURCE = "This platform's own tracked intelligence";

  for (const m of (moduleData?.malware ?? []).slice(0, CAP_ENTITY_EVIDENCE)) {
    const malware = m.entity ?? m;
    const sightings = malware.iocSightings ?? 0;
    items.push(
      item({
        category: malware.verified ? "direct" : "indirect",
        source: SOURCE,
        claim: `Malware family "${malware.name}"${malware.verified ? " (verified against MITRE ATT&CK / a live indicator feed)" : " (reported by news coverage only, not yet corroborated)"}, ${sightings} live indicator sighting(s)`,
        polarity: sightings > 0 ? "malicious" : "neutral",
        weight: malware.verified ? 0.7 : 0.3,
        rawField: "verified",
      }),
    );
  }
  for (const actor of (moduleData?.actors ?? []).slice(0, CAP_ENTITY_EVIDENCE)) {
    items.push(
      item({
        category: actor.verified ? "direct" : "indirect",
        source: SOURCE,
        claim: `Threat actor "${actor.name}" (${actor.type})${actor.verified ? " (verified against MITRE ATT&CK / a ransomware tracker)" : " (reported by news coverage only)"}`,
        polarity: "malicious",
        weight: actor.verified ? 0.7 : 0.3,
        rawField: "verified",
      }),
    );
  }
  for (const campaign of (moduleData?.campaigns ?? []).slice(0, CAP_ENTITY_EVIDENCE)) {
    items.push(
      item({
        category: campaign.verified ? "corroborating" : "indirect",
        source: SOURCE,
        claim: `Campaign "${campaign.name}"${campaign.verified ? " (corroborated by 2+ independent sources)" : " (single-source report)"}`,
        polarity: "malicious",
        weight: campaign.verified ? 0.5 : 0.25,
        rawField: "verified",
      }),
    );
  }
  return items;
}

// Distinguishes "victim disclosures only" (a bare ransomware-tracker group
// name with no verified actor/malware/campaign profile in this platform's
// own entity stores) from "victim disclosures + a verified profile" -- the
// dossier's own sourceType (entityCorrelation.js) is itself evidence-
// strength signal, not just display metadata.
function ransomwareGroupEvidence(moduleData) {
  const count = moduleData?.victimCount ?? 0;
  const items = [];
  if (count > 0) {
    items.push(
      item({
        category: "direct",
        source: "Ransomware Victim Tracking (ransomware.live / RansomWatch / RansomLook)",
        claim: `${count} disclosed victim(s) attributed to this group`,
        polarity: "malicious",
        weight: 0.85,
        rawField: "victimCount",
      }),
    );
  }
  const dossier = moduleData?.dossier;
  if (dossier?.sourceType === "verified-profile") {
    items.push(
      item({
        category: "corroborating",
        source: "This platform's own tracked intelligence",
        claim: `Matched a verified malware/actor/campaign profile in this platform's own entity stores (${dossier.malwareFamilyCount} malware famil${dossier.malwareFamilyCount === 1 ? "y" : "ies"}, ${dossier.campaignCount} campaign(s), ${dossier.cveCount} CVE(s))`,
        polarity: "malicious",
        weight: 0.5,
        rawField: "sourceType",
      }),
    );
  }
  return items;
}

// --- Per-source Evidence Card roster -- Stage 1b. Distinct from the
// category-grouped `items` above: one card per QUERIED source, always,
// including an explicit "No finding" card for a source that returned a
// successful lookup but produced no classifiable item. This is what lets the
// UI show "here is what EVERY source found" instead of compressing multiple
// sources into one sentence -- a source with no signal must never be
// silently omitted (that reads as "clean") or silently merged into another
// source's finding (that reads as "confirms/conflicts"). ---

const EVIDENCE_TYPE_LABEL = {
  AbuseIPDB: "Reputation / Community Reporting",
  VirusTotal: "Reputation / Multi-Engine Detection",
  GreyNoise: "Reputation / Scanning Classification",
  Shodan: "Infrastructure Context",
  LeakIX: "Exposure / Leak Association",
  OTX: "Threat Intelligence / Community Reporting",
  Pulsedive: "Reputation / Risk Score",
  "Hybrid Analysis": "Behavioral / Sandbox Analysis",
  "Team Cymru MHR": "Malware Association",
  "Team Cymru": "Infrastructure Context",
  RIPEstat: "Infrastructure Context",
  "SANS ISC": "Reputation / Attack Telemetry",
  "urlscan.io": "Behavioral / Scan Analysis",
  "crt.sh": "Infrastructure Context",
  RDAP: "Infrastructure Context",
  "Hudson Rock": "Exposure / Credential Association",
  "MISP Warning Lists": "Community Reporting / Known-Benign List",
  "This platform's own tracked intelligence": "Internal Correlation",
  "CISA KEV": "Exploitation / Confirmed Observed Exploitation",
  "Security News Coverage": "Exploitation / Unconfirmed Reporting",
  "Exploit-DB": "Exploitation / Public Exploit Availability",
  "Exploit-DB / GitHub": "Exploitation / Proof-of-Concept Availability",
  EPSS: "Exploitation Prediction (not evidence of exploitation)",
  "NVD/CVSS": "Technical Severity (not evidence of exploitation)",
  "Ransomware Victim Tracking (ransomware.live / RansomWatch / RansomLook)": "Victim / Impact Tracking",
};

function evidenceTypeFor(source) {
  return EVIDENCE_TYPE_LABEL[source] ?? "Reputation";
}

// `level` is a strength-of-signal scale, deliberately separate from
// `polarity` (malicious/suspicious/benign/neutral, already on every item) --
// the UI derives its RED/AMBER/GREEN/BLUE/GRAY color from the two together
// (e.g. malicious+HIGH -> RED, benign -> GREEN regardless of level,
// contextual -> BLUE, "no finding" -> GRAY) rather than from level alone.
function levelFor(i) {
  if (i.category === "contextual") return "CONTEXT";
  if (i.category === "negative") return "LOW";
  if (i.category === "conflicting") return "MEDIUM";
  if (i.weight >= 0.7) return "HIGH";
  if (i.weight >= 0.35) return "MEDIUM";
  return "LOW";
}

function reasonFor(i) {
  switch (i.category) {
    case "direct":
      return "Direct first-party detection from this source.";
    case "corroborating":
      return "Supports other evidence but is not independently conclusive on its own.";
    case "indirect":
      return "A weaker or unverified signal -- context, not confirmation.";
    case "attribution":
      return "Attribution claim -- links this indicator to a named actor, campaign, or malware family.";
    case "contextual":
      return "Ownership/infrastructure context only -- never treated as malicious or clean evidence.";
    case "negative":
      return "An explicit clean/benign signal from this source.";
    default:
      return "";
  }
}

function cardFromItem(i) {
  return {
    source: i.source,
    evidenceType: evidenceTypeFor(i.source),
    level: levelFor(i),
    polarity: i.polarity,
    finding: i.claim,
    reason: reasonFor(i),
    lastSeen: i.lastSeen ?? null,
  };
}

function noFindingCard(source, lastSeen = null) {
  return {
    source,
    evidenceType: evidenceTypeFor(source),
    level: "UNKNOWN",
    polarity: "neutral",
    finding: "No finding",
    reason: "This source was queried and returned a result, but reported no notable signal for this indicator.",
    lastSeen,
  };
}

// One card per queried source. `items` already carries every classified
// finding (lookup-rule-based, cross-reference, and entity-specific); any
// lookupResult source that produced zero items still gets a card so the UI
// never has to infer "silent = clean" or "silent = not queried".
function buildEvidenceCards(items, lookupResults) {
  const cards = [];
  const sourcesWithItems = new Set();
  for (const i of items) {
    if (i.category === "conflicting") continue; // a synthetic reconciliation note, not a per-source finding
    cards.push(cardFromItem(i));
    sourcesWithItems.add(i.source);
  }
  for (const r of lookupResults ?? []) {
    if (!r?.source || sourcesWithItems.has(r.source) || !SOURCE_RULES[r.source]) continue;
    cards.push(noFindingCard(r.source, r.lastSeen ?? null));
    sourcesWithItems.add(r.source);
  }
  return cards;
}

// Conflict detection -- true only when a negative (explicit clean/benign)
// item and a direct/corroborating malicious/suspicious item exist from
// DIFFERENT sources. Absence of data from one source is never itself a
// conflict. Rather than silently averaging or picking a side, this appends
// one synthetic "conflicting" item describing the disagreement -- the
// original items keep their own category/polarity so each source's actual
// claim stays intact and inspectable.
function detectConflict(items) {
  const negatives = items.filter((i) => i.category === "negative");
  const positives = items.filter((i) => (i.category === "direct" || i.category === "corroborating") && (i.polarity === "malicious" || i.polarity === "suspicious"));
  for (const negative of negatives) {
    const conflicting = positives.find((p) => p.source !== negative.source);
    if (conflicting) {
      const description = `${conflicting.source} reports ${conflicting.polarity} (${conflicting.claim}) while ${negative.source} reports a clean/benign signal (${negative.claim}).`;
      return {
        hasConflict: true,
        conflictDescription: description,
        conflictItem: item({ category: "conflicting", source: "Evidence Reconciliation", claim: description, polarity: "neutral", weight: 0 }),
      };
    }
  }
  return { hasConflict: false, conflictDescription: null, conflictItem: null };
}

/**
 * Evidence Reconciliation -- Stage 1 of the shared pipeline. Classifies raw
 * per-source fields into evidence items, cross-references this platform's
 * own tracked intelligence, adds entity-type-specific evidence for CVE/
 * name/ransomwareGroup searches, and detects conflicting evidence.
 *
 * @param {{ type: string, lookupResults?: Array<Record<string, unknown>>, crossRef?: ReturnType<import("./crossReference.js").crossReferenceIndicator> | null, moduleData?: Record<string, unknown>, cveExploitationState?: import("../../src/types/threat-intel.js").CveExploitationAssessment | null }} args
 * @returns {import("../../src/types/threat-intel.js").EvidenceReconciliation}
 */
export function buildEvidence({ type, lookupResults, crossRef, moduleData, cveExploitationState }) {
  const items = [];

  for (const r of lookupResults ?? []) {
    const rule = r?.source ? SOURCE_RULES[r.source] : null;
    if (rule) items.push(...rule(r));
  }

  items.push(...crossReferenceEvidence(crossRef));

  if (type === "cve") items.push(...cveEvidence(moduleData, cveExploitationState));
  if (type === "name") items.push(...nameEntityEvidence(moduleData));
  if (type === "ransomwareGroup") items.push(...ransomwareGroupEvidence(moduleData));

  const cards = buildEvidenceCards(items, lookupResults);

  const { hasConflict, conflictDescription, conflictItem } = detectConflict(items);
  if (conflictItem) items.push(conflictItem);

  // contextual/conflicting items never count toward source/independence
  // tallies -- they carry no verdict weight by design.
  const evidenceBearing = items.filter((i) => i.category !== "contextual" && i.category !== "conflicting");
  const sourceCount = evidenceBearing.length;
  const independentSourceCount = new Set(evidenceBearing.map((i) => i.source)).size;

  return { items, cards, hasConflict, conflictDescription, sourceCount, independentSourceCount };
}
