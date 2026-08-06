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
// TriageConsole.tsx's "name" bucket already worked. Organization/Victim get
// the same "name" fallback treatment for the same reason -- a free-text
// company name has no positively-identifiable shape of its own; index.js's
// resolveGraphTarget() tries the victim/dark-web stores as a last resort
// when nothing in the three entity stores matches.
import { ransomwareCampaigns as getRansomwareCampaigns } from "../ransomwareCampaigns.js";
import countryNamesData from "../data/country-names.json" with { type: "json" };

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
// Anchored-start check for common product-token UAs, or a looser fallback
// for a real browser/bot UA string quoted mid-sentence (e.g. copied from a
// log line with a leading timestamp) -- requires 2+ "/"-delimited product
// tokens alongside a known engine marker so a random string containing the
// word "Mozilla" doesn't false-positive.
const USER_AGENT_PATTERN = /^(Mozilla\/|curl\/|python-requests\/|Go-http-client\/|Wget\/|okhttp\/)/i;
const USER_AGENT_FALLBACK_PATTERN = /Mozilla\/[\d.]+.*(AppleWebKit|Gecko|Trident)\/[\d.]+/i;
// Deliberately excludes the legacy MS-DOS ".com" executable extension --
// confirmed live that "google.com" (and any other .com domain) otherwise
// matches this before DOMAIN_PATTERN ever gets a chance, since ".com" as a
// file extension is effectively obsolete while ".com" as a TLD is the most
// common one in existence. Extension list widened beyond the original
// executable/script/archive set to also cover common document/disk-image
// types real SOC alerts reference.
// ".one" deliberately excluded despite being a real Microsoft OneNote
// extension -- it's also a real, registered gTLD (e.g. "example.one"), the
// same class of collision the .com exclusion above already guards against.
const FILE_NAME_PATTERN =
  /^[\w.\-]{1,255}\.(exe|dll|sys|bat|ps1|psm1|vbs|js|jar|scr|msi|bin|sh|py|zip|rar|7z|docm|xlsm|pdf|lnk|doc|docx|xls|xlsx|ppt|pptx|iso|img|hta|wsf|cpl|dat)$/i;
const PROCESS_NAME_PATTERN = /^[\w.\-]{1,255}\.exe$/i;
// A bare filename/process name is sometimes pasted with its containing path
// (Windows or POSIX) -- strip a leading path before testing the shape
// patterns above, but keep `normalized` as the original full value so the
// analyst's exact paste is preserved for cross-reference matching.
const PATH_PREFIX_PATTERN = /^.*[\\/]/;
const ASN_PATTERN = /^AS\s?\d+$/i;

function normalizeCountry(v) {
  return v.trim().toLowerCase();
}

let countryNameSet = null;
function getCountryNames() {
  if (!countryNameSet) {
    countryNameSet = new Map();
    for (const [code, name] of Object.entries(countryNamesData)) {
      if (code.startsWith("_") || typeof name !== "string") continue;
      countryNameSet.set(normalizeCountry(name), name);
    }
  }
  return countryNameSet;
}

function getRansomwareGroupNames() {
  // Rebuilt on every call (not cached across the process lifetime) since
  // ransomware.live/RansomWatch/RansomLook sync on their own schedule and a
  // newly-seen group should be searchable without a server restart -- this
  // is a cheap Set build over an already-in-memory array, not a new fetch.
  const set = new Map();
  for (const c of getRansomwareCampaigns()) {
    if (c.group) set.set(c.group.trim().toLowerCase(), c.group);
  }
  return set;
}

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
  if (ASN_PATTERN.test(value)) return { type: "asn", normalized: value.replace(/^AS\s?/i, "") };
  if (USER_AGENT_PATTERN.test(value) || USER_AGENT_FALLBACK_PATTERN.test(value)) return { type: "userAgent", normalized: value };
  // File/process name checked before domain -- confirmed live that
  // DOMAIN_PATTERN's bare "label.label" shape requirement is NOT actually
  // TLD-aware (it has no real TLD list to check against), so it silently
  // matched "malware.exe"/"notes.docx" as a domain before either pattern
  // below ever got a chance, misclassifying what is probably the single
  // most common SOC search term there is. FILE_NAME_PATTERN/
  // PROCESS_NAME_PATTERN's curated extension allowlist makes this safe the
  // other direction too -- no real domain accidentally ends in ".exe" or
  // ".docx" the way "malware.exe" accidentally looks like a two-label
  // domain. Process names are a strict subset of file names (.exe only) --
  // checked first so "svchost.exe" reads as a process, not a generic file.
  // Both strip a leading path (if any) only for the shape test --
  // `normalized` keeps the analyst's original full paste.
  const basename = value.replace(PATH_PREFIX_PATTERN, "");
  if (PROCESS_NAME_PATTERN.test(basename)) return { type: "processName", normalized: value };
  if (FILE_NAME_PATTERN.test(basename)) return { type: "fileName", normalized: value };
  if (DOMAIN_PATTERN.test(value)) return { type: "domain", normalized: value.toLowerCase() };
  // Ransomware group / country checked against this app's own real, already-
  // synced data (not a fixed regex) -- placed after every shape-based check
  // above since neither can collide with a real IP/domain/hash/CVE shape,
  // and before the generic "name" fallback so these two get their own
  // richer graph node type instead of being folded into a bare actor/
  // campaign substring search.
  const ransomwareMatch = getRansomwareGroupNames().get(value.trim().toLowerCase());
  if (ransomwareMatch) return { type: "ransomwareGroup", normalized: ransomwareMatch };
  const countryMatch = getCountryNames().get(normalizeCountry(value));
  if (countryMatch) return { type: "country", normalized: countryMatch };
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
