// Shared malware-family-name cleanup utilities, originally built alongside
// the (now-removed) Correlation Engine tab's union-find clustering, but kept
// here since server/correlate.js, server/newsCorrelation.js, and
// server/combinedExtractionJob.js all still depend on them.

const GENERIC_LABELS = new Set([
  "32-bit",
  "64-bit",
  "elf",
  "mips",
  "arm",
  "arm5",
  "windows",
  "macos",
  "linux",
  "opendir",
  "exe",
  "dll",
  "sh",
  "apk",
  "ps1",
  "html",
  "config",
  "json",
  "unknown",
  "n/a",
  // Common dual-use offensive/red-team tools -- these are generic
  // payload/C2 framework names nearly every unrelated exploit or PoC repo
  // happens to mention, not a real malware family.
  "cobalt strike",
  "cobaltstrike",
  "mimikatz",
  "metasploit",
  "empire",
  "powershell empire",
  "meterpreter",
  "psexec",
  // URLHaus's `tags` field is freeform and community-submitted (server/
  // connectors/urlhaus.js joins it straight into `malwareFamily`) -- these
  // are honeypot/protocol/infrastructure labels confirmed live showing up
  // as fake "malware families" (a URLHaus submitter tagging a host as
  // "cowrie"/"telnet" describes how the sighting was captured, not what
  // malware it is) rather than an actual family name.
  "cowrie",
  "honeypot",
  "ssh",
  "telnet",
  "ftp",
  "rdp",
  "smb",
  "scanner",
  "bruteforce",
  "c2",
  "proxy",
  "botnet",
]);

// Same URLHaus freeform-tag problem, but for values that can't be caught by
// a fixed denylist -- a submitter tagging a host with its own hostname/IP-like
// identifier (e.g. "137-184-6-122") or a detection-signature id (e.g.
// "win-0x4679", confirmed live sitting in the same comma-joined tag list
// right next to a real family name like "ClearFake") rather than any real
// family name. A genuine malware family name is never purely digits and
// separators, and never a short word glued to a hex code by a dash.
const NUMERIC_LABEL_PATTERN = /^\d+([.-]\d+){2,}$/;
const SIGNATURE_ID_PATTERN = /^\w{1,6}-0x[0-9a-f]+$/i;

export function splitFamilies(malwareFamily) {
  if (!malwareFamily || malwareFamily === "Unknown" || malwareFamily === "N/A") return [];
  return malwareFamily
    .split(",")
    .map((f) => f.trim())
    .filter((f) => f && !GENERIC_LABELS.has(f.toLowerCase()) && !NUMERIC_LABEL_PATTERN.test(f) && !SIGNATURE_ID_PATTERN.test(f));
}

/**
 * Names of ATT&CK "software" entries used by more than `threshold` different
 * groups -- dual-use/living-off-the-land tools (Mimikatz, PsExec, Cobalt
 * Strike, and built-in admin binaries like ping/net/tasklist/certutil) that
 * are real attribution but too generic to anchor a correlation on. Reused by
 * server/newsCorrelation.js for the same reason: as plain English words/
 * common tool names, they light up in headlines that have nothing to do with
 * the actual malware family.
 */
export function getCommonAttackToolNames(attackData, threshold = 5) {
  const groupCountBySoftwareId = new Map();
  for (const g of attackData?.groups ?? []) {
    for (const sid of g.softwareIds ?? []) groupCountBySoftwareId.set(sid, (groupCountBySoftwareId.get(sid) ?? 0) + 1);
  }
  const softwareById = new Map((attackData?.software ?? []).map((s) => [s.id, s]));
  const names = new Set();
  for (const [id, count] of groupCountBySoftwareId.entries()) {
    if (count <= threshold) continue;
    const software = softwareById.get(id);
    if (!software) continue;
    for (const n of [software.name, ...(software.aliases ?? [])]) names.add(n.toLowerCase());
  }
  return names;
}
