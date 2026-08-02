// Shared verdict computation -- every module's Universal Overview reads
// severity/riskLevel/priority from this ONE function instead of each module
// (or the frontend) independently inventing its own number. This is a
// direct lesson from this app's own AI Summarization work: letting a report's
// own "vendor severity" field and its badge disagree confused readers until
// they were explicitly reconciled -- this file exists so that never happens
// here in the first place.
const LEVEL_TO_FIELDS = {
  critical: { severity: "CRITICAL", riskLevel: "Critical", priority: "Immediate" },
  high: { severity: "HIGH", riskLevel: "High", priority: "High" },
  medium: { severity: "MEDIUM", riskLevel: "Medium", priority: "Normal" },
  low: { severity: "LOW", riskLevel: "Low", priority: "Low" },
  unknown: { severity: "UNKNOWN", riskLevel: "Low", priority: "Low" },
};

function fromLevel(level, label, confidence = "Medium") {
  return { verdict: level, label, confidence, ...LEVEL_TO_FIELDS[level] };
}

/** Same vote-counting + high-confidence special cases as the legacy /ioc-search route -- kept identical so verdicts don't shift under existing IP/domain/URL/hash indicators. */
export function computeIocVerdict(lookupResults) {
  const maliciousVotes = lookupResults.filter((r) => r.verdict === "malicious").length;
  const suspiciousVotes = lookupResults.filter((r) => r.verdict === "suspicious").length;
  const highConfidenceHit = lookupResults.some((r) => {
    if (r.source === "VirusTotal") return (r.malicious ?? 0) >= 5;
    if (r.source === "Hybrid Analysis") return (r.threatScore ?? 0) >= 70;
    if (r.source === "Team Cymru MHR") return (r.detectionPercent ?? 0) >= 50;
    if (r.source === "urlscan.io") return r.malicious === true;
    return false;
  });

  if (highConfidenceHit || maliciousVotes >= 2) return fromLevel("critical", "Malicious", "High");
  if (maliciousVotes >= 1 || suspiciousVotes >= 1) return fromLevel("high", "Suspicious", "Medium");
  if (lookupResults.length > 0) return fromLevel("low", "Clean", "Medium");
  return fromLevel("unknown", "No Data", "Low");
}

/** Same KEV > EPSS > CVSS priority order TriageConsole.tsx already used for CVEs. */
export function computeCveVerdict(cve) {
  if (cve.knownExploited) return fromLevel("critical", "Actively Exploited (KEV)", "High");
  if ((cve.epssScore ?? 0) >= 0.5) return fromLevel("critical", "High Exploitation Probability", "High");
  if (cve.severity === "CRITICAL") return fromLevel("high", "Critical Severity", "Medium");
  if (cve.severity === "HIGH") return fromLevel("medium", "High Severity", "Medium");
  if (cve.severity === "MEDIUM") return fromLevel("low", "Medium Severity", "Medium");
  return fromLevel("low", "Low Severity", "Medium");
}

/** Entity (malware/actor/campaign) verdict -- elevated for ransomware/APT actors and verified, actively-sighted malware; otherwise informational. */
export function computeEntityVerdict(kind, entity) {
  if (kind === "actor") {
    if (entity.type === "Ransomware" || entity.type === "APT") return fromLevel("high", `${entity.type} — Active Threat Actor`, entity.verified ? "High" : "Medium");
    return fromLevel("medium", `${entity.type} — Tracked Threat Actor`, entity.verified ? "High" : "Medium");
  }
  if (kind === "malware") {
    if ((entity.iocSightings ?? 0) > 0) return fromLevel("high", "Active Malware Family — Live Indicators Observed", entity.verified ? "High" : "Medium");
    return fromLevel("medium", "Tracked Malware Family", entity.verified ? "High" : "Medium");
  }
  // campaign
  return fromLevel("medium", "Tracked Campaign", entity.verified ? "High" : "Medium");
}

/** Cross-reference-only types (email/filename/processname/registrykey/useragent) -- verdict is purely "was this seen linked to known-malicious activity in this app's own data". */
export function computeCrossReferenceOnlyVerdict(crossRef) {
  if (crossRef.matchedMalwareFamilies.length > 0) return fromLevel("high", "Linked to Tracked Malware Activity", "Medium");
  return fromLevel("unknown", "No External Reputation Source — Not Found in This Platform's Own Data", "Low");
}
