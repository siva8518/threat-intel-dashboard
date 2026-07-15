// Discovery categories. Deliberately starting with a small, diverse subset
// (not the full ~18-category list from the original ask) to validate the
// whole discovery -> extraction -> correlation -> scoring pipeline end to
// end before fanning out query variety -- cheaper to catch a bug against
// ~30 repos than ~2,000. Add more categories/queries here once this set is
// confirmed working live.
//
// Each query is a single GitHub Search API `q=` string (qualifiers like
// `topic:`, `in:readme,description` are ANDed together automatically by
// GitHub's search syntax). Confirmed live against the real Search API.
export const CATEGORIES = [
  {
    id: "exploit-poc",
    label: "Exploit PoC",
    queries: ["topic:exploit topic:cve", '"proof of concept" CVE in:readme,description'],
  },
  {
    id: "sigma-rules",
    label: "Sigma Rules",
    queries: ["topic:sigma-rules", "topic:sigma"],
  },
  {
    id: "yara-rules",
    label: "YARA Rules",
    queries: ["topic:yara-rules", "topic:yara"],
  },
  {
    id: "malware",
    label: "Malware",
    queries: ["topic:malware", "topic:malware-analysis"],
  },
  {
    // Repos named directly after a CVE ID (e.g. "rapid7-CVE-2026-15409") --
    // confirmed live that "topic:exploit topic:cve" above missed these when
    // the repo owner tagged nothing at all and just named the repo after the
    // CVE, which is common for single-CVE vendor/researcher PoC drops.
    // `in:name` is a real GitHub Search qualifier (confirmed against the live
    // Search API), matched case-insensitively against the repo name only.
    id: "cve-poc",
    label: "CVE Proof of Concept",
    queries: ["CVE in:name", "topic:cve"],
  },
];
