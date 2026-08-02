// Ordered indicator-type detection for the Intelligence Investigation
// Console -- one shape/regex check per type, most specific first so e.g. a
// CVE ID never falls through and gets mis-read as a "file name". Patterns
// are the same ones already proven in TriageConsole.tsx's detectTriageType
// and server/githubIntel/extractor.js, not re-derived from scratch.
//
// Types with no reliable shape of their own (process name, malware family,
// threat actor, campaign name) all fall through to "name" -- the orchestrator
// resolves which of those four it actually is by checking this app's own
// entity stores (see server/investigation/entityModule.js), the same way
// TriageConsole.tsx's "name" bucket already worked.
const CVE_PATTERN = /^CVE-\d{4}-\d{4,7}$/i;
const IPV4_PATTERN = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_PATTERN = /^[0-9a-f]{0,4}(:[0-9a-f]{0,4}){2,7}$/i;
const SHA256_PATTERN = /^[a-f0-9]{64}$/i;
const SHA1_PATTERN = /^[a-f0-9]{40}$/i;
const MD5_PATTERN = /^[a-f0-9]{32}$/i;
const URL_PATTERN = /^https?:\/\//i;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const DOMAIN_PATTERN = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63})+$/i;
const REGISTRY_KEY_PATTERN = /^(HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\/i;
const USER_AGENT_PATTERN = /^(Mozilla\/|curl\/|python-requests\/|Go-http-client\/|Wget\/|okhttp\/)/i;
// Deliberately excludes the legacy MS-DOS ".com" executable extension --
// confirmed live that "google.com" (and any other .com domain) otherwise
// matches this before DOMAIN_PATTERN ever gets a chance, since ".com" as a
// file extension is effectively obsolete while ".com" as a TLD is the most
// common one in existence.
const FILE_NAME_PATTERN = /^[\w.\-]{1,255}\.(exe|dll|sys|bat|ps1|vbs|js|jar|scr|msi|bin|sh|py|zip|rar|7z|docm|xlsm|pdf|lnk)$/i;
const PROCESS_NAME_PATTERN = /^[\w.\-]{1,255}\.exe$/i;

/**
 * @param {string} raw
 * @returns {{ type: import("../../src/types/threat-intel.js").IndicatorType, normalized: string }}
 */
export function detectIndicatorType(raw) {
  const value = raw.trim();

  if (CVE_PATTERN.test(value)) return { type: "cve", normalized: value.toUpperCase() };
  if (IPV4_PATTERN.test(value)) return { type: "ipv4", normalized: value };
  if (IPV6_PATTERN.test(value)) return { type: "ipv6", normalized: value };
  if (SHA256_PATTERN.test(value)) return { type: "sha256", normalized: value.toLowerCase() };
  if (SHA1_PATTERN.test(value)) return { type: "sha1", normalized: value.toLowerCase() };
  if (MD5_PATTERN.test(value)) return { type: "md5", normalized: value.toLowerCase() };
  if (URL_PATTERN.test(value)) return { type: "url", normalized: value };
  if (EMAIL_PATTERN.test(value)) return { type: "email", normalized: value.toLowerCase() };
  if (REGISTRY_KEY_PATTERN.test(value)) return { type: "registryKey", normalized: value };
  if (USER_AGENT_PATTERN.test(value)) return { type: "userAgent", normalized: value };
  // Domain checked before file/process name -- a real registrable domain
  // (google.com, evil-actor.io) is a far more common SOC search than a bare
  // file/process name that happens to share the same "word.tld-looking"
  // shape, and DOMAIN_PATTERN already requires a real-looking label
  // structure that most file names don't accidentally satisfy.
  if (DOMAIN_PATTERN.test(value)) return { type: "domain", normalized: value.toLowerCase() };
  // Process names are a strict subset of file names (.exe only) -- checked
  // first so "svchost.exe" reads as a process, not a generic file.
  if (PROCESS_NAME_PATTERN.test(value)) return { type: "processName", normalized: value };
  if (FILE_NAME_PATTERN.test(value)) return { type: "fileName", normalized: value };
  return { type: "name", normalized: value };
}

/** Hash type ("sha256"/"sha1"/"md5") collapses to one module type -- see hashModule.js. */
export function isHashType(type) {
  return type === "sha256" || type === "sha1" || type === "md5";
}

/** IPv4/IPv6 collapse to one module type -- see ipModule.js. */
export function isIpType(type) {
  return type === "ipv4" || type === "ipv6";
}
