// Repository classification: a weighted keyword/topic heuristic, not an ML
// classifier -- same "documented, tunable, not a black box" style as
// threatScoring.js. GitHub topics are the strongest signal (repo owners
// explicitly curate them); name/description are medium; README/file content
// matches are the weakest signal, since a false-positive keyword mention
// buried in prose shouldn't carry as much weight as a deliberate tag.
const TOPIC_WEIGHT = 3;
const NAME_OR_DESCRIPTION_WEIGHT = 2;
const CONTENT_WEIGHT = 1;
const NORMALIZING_CONSTANT = 6; // score needed to reach confidence 1.0 -- roughly "two strong signals"
const CONFIDENCE_THRESHOLD = 0.25; // below this, too weak to report as a category

const CATEGORY_SIGNALS = {
  "Exploit PoC": {
    topics: ["exploit", "poc", "cve", "vulnerability", "0day", "zero-day", "exploitation"],
    keywords: ["proof of concept", "exploit", "vulnerability", "poc for cve"],
  },
  Malware: {
    topics: ["malware", "malware-analysis", "malware-samples", "ransomware", "trojan", "rat", "botnet", "stealer", "loader"],
    keywords: ["malware analysis", "malware sample", "malicious", "ransomware", "botnet", "stealer", "loader"],
  },
  "IOC Feed": {
    topics: ["ioc", "iocs", "indicators", "indicators-of-compromise", "threat-feed"],
    keywords: ["indicators of compromise", "ioc feed", "ioc list", "c2 list", "c2 feed"],
  },
  "Threat Hunting": {
    topics: ["threat-hunting", "threathunting", "hunting"],
    keywords: ["threat hunting", "hunt queries", "hunting queries"],
  },
  "Detection Engineering": {
    topics: ["detection", "detection-engineering", "detection-rules", "detection-content"],
    keywords: ["detection engineering", "detection rule", "detection content"],
  },
  "Sigma Rules": {
    topics: ["sigma", "sigma-rules"],
    keywords: ["sigma rule", "sigmahq"],
  },
  "YARA Rules": {
    topics: ["yara", "yara-rules", "yara-signatures"],
    keywords: ["yara rule", "yara signature"],
  },
  "Suricata Rules": {
    topics: ["suricata", "suricata-rules", "snort", "ids-signatures"],
    keywords: ["suricata rule", "snort rule", "ids signature"],
  },
  "DFIR Tool": {
    topics: ["dfir", "forensics", "incident-response", "memory-forensics", "digital-forensics"],
    keywords: ["digital forensics", "incident response", "dfir"],
  },
  "Threat Intelligence": {
    topics: ["threat-intelligence", "cti", "osint", "threat-intel"],
    keywords: ["threat intelligence", "cyber threat intelligence"],
  },
  "Security Tool": {
    topics: ["security-tools", "pentest", "security", "red-team", "blue-team"],
    keywords: ["security tool", "penetration testing", "red team", "blue team"],
  },
  Research: {
    topics: ["research", "security-research", "writeup"],
    keywords: ["research paper", "whitepaper", "write-up", "writeup"],
  },
};

/**
 * @param {{ name: string, description: string|null, topics: string[] }} repoMeta
 * @param {string} [contentText] - README + targeted file text, if already fetched (see contentFetcher.js). Optional: classification without it just relies on metadata/topics, which are often enough on their own.
 * @returns {Array<{ category: string, confidence: number }>} sorted descending by confidence
 */
export function classifyRepository(repoMeta, contentText = "") {
  const lowerName = (repoMeta.name ?? "").toLowerCase();
  const lowerDescription = (repoMeta.description ?? "").toLowerCase();
  const lowerTopics = (repoMeta.topics ?? []).map((t) => t.toLowerCase());
  const lowerContent = contentText.toLowerCase();

  const results = [];
  for (const [category, signals] of Object.entries(CATEGORY_SIGNALS)) {
    let score = 0;
    for (const topic of signals.topics) {
      if (lowerTopics.includes(topic)) score += TOPIC_WEIGHT;
    }
    for (const keyword of signals.keywords) {
      if (lowerName.includes(keyword)) score += NAME_OR_DESCRIPTION_WEIGHT;
      if (lowerDescription.includes(keyword)) score += NAME_OR_DESCRIPTION_WEIGHT;
      if (lowerContent.includes(keyword)) score += CONTENT_WEIGHT;
    }

    const confidence = Math.min(score / NORMALIZING_CONSTANT, 1);
    if (confidence >= CONFIDENCE_THRESHOLD) results.push({ category, confidence });
  }

  return results.sort((a, b) => b.confidence - a.confidence);
}
