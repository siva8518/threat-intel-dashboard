// Regex-based entity extraction from repo text (README + targeted rule/IOC
// files -- see contentFetcher.js). This is explicitly best-effort, not NLP/ML:
// same "documented heuristic, not a black box" philosophy as the rest of this
// app. Two extraction passes are cross-checked against data this app already
// has cached (real ATT&CK technique IDs, real ATT&CK group names) rather than
// trusting the raw regex match alone -- that's the single biggest lever for
// cutting false positives cheaply.

const CVE_PATTERN = /CVE-\d{4}-\d{4,7}/gi;
const SHA256_PATTERN = /\b[a-fA-F0-9]{64}\b/g;
const SHA1_PATTERN = /\b[a-fA-F0-9]{40}\b/g;
const MD5_PATTERN = /\b[a-fA-F0-9]{32}\b/g;
const IPV4_PATTERN = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
// Full (uncompressed) form only -- misses "::" shorthand. A known, documented
// limitation rather than shipping a multi-hundred-character "complete" IPv6
// regex that's still an approximation anyway.
const IPV6_PATTERN = /\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b/g;
const EMAIL_PATTERN = /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g;
const URL_PATTERN = /\bhttps?:\/\/[^\s"'<>()[\]]+/gi;
const YARA_RULE_NAME_PATTERN = /\brule\s+([A-Za-z_][A-Za-z0-9_]*)/g;
const SIGMA_RULE_ID_PATTERN = /^\s*id:\s*([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/gm;
const ATTACK_TECHNIQUE_ID_PATTERN = /\bT1\d{3}(?:\.\d{3})?\b/g;

// Registry keys have a distinctive, unambiguous syntax (HKLM\..., HKEY_LOCAL_MACHINE\...)
// -- high-confidence, low-false-positive extraction, same reliability class as
// the hash/IP/CVE patterns above.
const REGISTRY_KEY_PATTERN = /\bHK(?:EY_)?(?:LM|CU|CR|U|CC|LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)\\[^\s"'<>()[\]{}]+/gi;
// Windows drive-letter paths -- similarly unambiguous syntax.
const WINDOWS_FILE_PATH_PATTERN = /\b[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n\s]+\\)*[^\\/:*?"<>|\r\n\s]+/g;
// Bare filenames anchored on a closed, security-relevant extension list --
// deliberately not a generic "word.word" pattern (far too noisy against
// prose), so genuine false positives are rare even without a preceding path.
const FILE_NAME_PATTERN = /\b[\w][\w.-]{0,80}\.(?:exe|dll|ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|scr|com|jar|py|sh|msi|hta|lnk|docm|xlsm|pptm|zip|rar|7z|iso|img)\b/gi;
// "port 443" / "port: 8080" -- anchor-phrase required so a bare number in
// unrelated prose (a CVE score, a byte count) is never mistaken for a port.
const PORT_PATTERN = /\bport\s*[:#]?\s*(\d{1,5})\b/gi;
// "Event ID 4688" / "EID 4104" -- anchor-phrase required for the same reason.
const EVENT_ID_PATTERN = /\b(?:event\s*id|eid)\s*[:#]?\s*(\d{3,5})\b/gi;
// Named pipes have their own unambiguous Windows syntax.
const NAMED_PIPE_PATTERN = /\\\\\.\\pipe\\[^\s"'<>()[\]{}]+/g;
// Mutex/scheduled-task/service names are NOT reliably extractable from free
// prose in general (unlike the syntax-anchored patterns above, there's no
// unambiguous shape to a mutex or task name) -- these three deliberately
// only match when the source text quotes the name right after a clear
// anchor phrase (e.g. `mutex named "Global\\FooBar"`), trading recall for
// precision: missing an unquoted mention is far preferable to inventing or
// mismatching one, same "never guess" principle as the rest of this app.
const MUTEX_NAME_PATTERN = /\bmutex(?:es)?(?:\s+(?:named|called))?[^."'\n]{0,20}["“]([^"”]{2,80})["”]/gi;
const SCHEDULED_TASK_NAME_PATTERN = /\bscheduled\s+tasks?[^."'\n]{0,20}["“]([^"”]{2,80})["”]/gi;
const SERVICE_NAME_PATTERN = /\bservices?(?:\s+(?:named|called))?[^."'\n]{0,20}["“]([^"”]{2,80})["”]/gi;

// Common enough to keep the domain regex's false-positive rate manageable
// without requiring a full public-suffix-list dependency. Not exhaustive --
// documented limitation, matching this app's existing "best-effort" style
// (see server/connectors/attack.js's country/motivation keyword lists).
const COMMON_TLDS = [
  "com", "net", "org", "io", "co", "info", "biz", "xyz", "top", "club", "online", "site", "icu",
  "link", "click", "live", "life", "world", "app", "dev", "me", "cc", "pw", "tk", "ws", "name",
  "work", "download", "ru", "su", "cn", "de", "uk", "nl", "fr", "br", "in", "jp", "kr",
];
const DOMAIN_PATTERN = new RegExp(
  `\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:${COMMON_TLDS.join("|")})\\b`,
  "gi",
);

// The 14 Enterprise ATT&CK tactics (stable, official -- attack.mitre.org/tactics/enterprise).
const ATTACK_TACTICS = [
  "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
  "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
  "Collection", "Command and Control", "Exfiltration", "Impact",
];

/** Un-defangs common IOC-sharing conventions (hxxp://, [.], (dot), [at]) so indicators are directly usable, not just visually present. */
function refang(text) {
  return text
    .replace(/hxxps?:\/\//gi, (m) => m.toLowerCase().replace("hxxp", "http"))
    .replace(/\[\.\]|\(\.\)/g, ".")
    .replace(/\[:\]/g, ":")
    .replace(/\[at\]|\(at\)/gi, "@");
}

function uniqueMatches(text, pattern) {
  return Array.from(new Set(text.match(pattern) ?? []));
}

function uniqueCapturedGroups(text, pattern) {
  const results = new Set();
  let match;
  const re = new RegExp(pattern); // fresh instance -- global regexes carry lastIndex state across calls otherwise
  while ((match = re.exec(text)) !== null) {
    results.add(match[1]);
    if (match.index === re.lastIndex) re.lastIndex++; // guard against zero-width-match infinite loops
  }
  return Array.from(results);
}

/**
 * @param {string} rawText - combined README + targeted-file text for one repo
 * @param {object} knownData
 * @param {Array<{id: string}>} knownData.techniques - this app's already-cached ATT&CK technique list, used to filter out false-positive "T1234"-shaped matches that aren't real technique IDs
 * @param {Array<{name: string, aliases: string[]}>} knownData.groups - this app's already-cached ATT&CK groups, used to detect actor-name mentions
 * @param {string[]} knownData.malwareFamilies - curated family name seed list (server/data/malware-attack-map.json)
 */
export function extractEntities(rawText, { techniques = [], groups = [], malwareFamilies = [] } = {}) {
  const text = refang(rawText ?? "");
  const lower = text.toLowerCase();

  const knownTechniqueIds = new Set(techniques.map((t) => t.id));
  const attackTechniques = uniqueMatches(text, ATTACK_TECHNIQUE_ID_PATTERN).filter((id) => knownTechniqueIds.has(id));

  const attackTactics = ATTACK_TACTICS.filter((tactic) => lower.includes(tactic.toLowerCase()));

  const threatActorNames = groups
    .filter((g) => lower.includes(g.name.toLowerCase()) || g.aliases.some((a) => lower.includes(a.toLowerCase())))
    .map((g) => g.name);

  const malwareFamilyMatches = malwareFamilies.filter((family) => lower.includes(family.toLowerCase()));

  return {
    cveIds: uniqueMatches(text, CVE_PATTERN).map((id) => id.toUpperCase()),
    sha256: uniqueMatches(text, SHA256_PATTERN),
    sha1: uniqueMatches(text, SHA1_PATTERN),
    md5: uniqueMatches(text, MD5_PATTERN),
    ipv4: uniqueMatches(text, IPV4_PATTERN),
    ipv6: uniqueMatches(text, IPV6_PATTERN),
    domains: uniqueMatches(text, DOMAIN_PATTERN).map((d) => d.toLowerCase()),
    urls: uniqueMatches(text, URL_PATTERN),
    emails: uniqueMatches(text, EMAIL_PATTERN).map((e) => e.toLowerCase()),
    yaraRuleNames: uniqueCapturedGroups(text, YARA_RULE_NAME_PATTERN),
    sigmaRuleIds: uniqueCapturedGroups(text, SIGMA_RULE_ID_PATTERN),
    registryKeys: uniqueMatches(text, REGISTRY_KEY_PATTERN),
    filePaths: uniqueMatches(text, WINDOWS_FILE_PATH_PATTERN),
    fileNames: uniqueMatches(text, FILE_NAME_PATTERN),
    ports: uniqueCapturedGroups(text, PORT_PATTERN),
    eventIds: uniqueCapturedGroups(text, EVENT_ID_PATTERN),
    namedPipes: uniqueMatches(text, NAMED_PIPE_PATTERN),
    // Best-effort/low-recall by design -- see the pattern comments above.
    mutexes: uniqueCapturedGroups(text, MUTEX_NAME_PATTERN),
    scheduledTasks: uniqueCapturedGroups(text, SCHEDULED_TASK_NAME_PATTERN),
    services: uniqueCapturedGroups(text, SERVICE_NAME_PATTERN),
    attackTechniques,
    attackTactics,
    threatActorNames,
    malwareFamilies: malwareFamilyMatches,
  };
}
